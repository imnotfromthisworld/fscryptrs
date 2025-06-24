pub mod crypto;
mod types;

use std::io::SeekFrom;
use std::marker::PhantomData;
use std::rc::Rc;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::Metadata,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Seek, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use aead::{Aead, KeyInit};
use aes_siv::Aes256SivAead;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as b64};
use crypto::CryptoFile;
use fuser::{FileType, Filesystem};
use nix::sys::stat::Mode;
use thiserror::Error;
use tracing::{debug, error, info, instrument};

const TTL: Duration = Duration::from_secs(1); // 1 second

struct CryptoHandler<Cipher, Digest, Mode>
where
    Cipher: crypto::Cipher,
    Digest: crypto::Digest,
    Mode: crypto::Encoder,
{
    key: Rc<crypto_common::Key<Cipher>>,
    dir_cipher: Aes256SivAead,
    symlink_cipher: Cipher,
    digest_check: bool,
    phantom_cipher: PhantomData<Cipher>,
    phantom_digest: PhantomData<Digest>,
    phantom_mode: PhantomData<Mode>,
}

impl<C, D, E> CryptoHandler<C, D, E>
where
    C: crypto::Cipher,
    D: crypto::Digest,
    E: crypto::Encoder,
{
    fn new(key: [u8; 32], dir_key: [u8; 64], digest_check: bool) -> Self {
        Self {
            key: Rc::new(crypto_common::Key::<C>::from_slice(&key).clone()),
            dir_cipher: Aes256SivAead::new_from_slice(&dir_key)
                .expect("dir_key is a valid AesSiv key"),
            symlink_cipher: C::new_from_slice(&key).expect("symlink cipher key is of valid length"),
            digest_check,
            phantom_cipher: std::marker::PhantomData,
            phantom_digest: std::marker::PhantomData,
            phantom_mode: std::marker::PhantomData,
        }
    }

    /// Opens file and its digest file at `path` with specified `mode` and `flags`
    /// Returns error if the file does not exist
    fn open_file(&self, path: &str, mode: u32, flags: i32) -> Result<CryptoFile<C, D, E>, IoError> {
        let cr_fl = std::fs::OpenOptions::new()
            .read(test_rd(flags))
            .write(test_wr(flags))
            .mode(mode)
            .custom_flags(flags)
            .open(path)?;

        let dig_fl = if self.digest_check {
            Some(
                std::fs::OpenOptions::new()
                    .read(test_rd(flags))
                    .write(test_wr(flags))
                    .mode(mode)
                    .custom_flags(flags)
                    .open(path.to_owned() + ".dg")?,
            )
        } else {
            None
        };

        self.wrap_file(cr_fl, dig_fl, false)
    }

    /// Creates CryptoFile out of the underlying `file` and `digest file`
    fn wrap_file(
        &self,
        file: std::fs::File,
        digest_file: Option<std::fs::File>,
        init: bool,
    ) -> Result<CryptoFile<C, D, E>, IoError> {
        CryptoFile::<C, D, E>::open(file, digest_file, self.key.clone(), init).map_err(|e| {
            error!("failed to wrap file {}", e);
            IoError::other(e)
        })
    }

    /// Creates new file and its digest file at `path` with specified `mode` and `flags`
    /// Returns error if the file already exists
    #[instrument(skip(self, mode))]
    fn create_file(
        &self,
        mut path: OsString,
        mode: Option<u32>,
        flags: i32,
    ) -> Result<CryptoFile<C, D, E>, IoError> {
        let read = (flags & libc::O_ACCMODE == libc::O_RDONLY)
            || (flags & libc::O_ACCMODE == libc::O_RDWR)
            || (flags & libc::O_ACCMODE == libc::O_WRONLY);
        let write = read;
        let create = flags & libc::O_CREAT == libc::O_CREAT;
        let create_new = flags & libc::O_EXCL == libc::O_EXCL;

        debug!(
            "read {}, write {}, create {}, create_new {}",
            read, write, create, create_new
        );

        let file = std::fs::OpenOptions::new()
            .read(read)
            .write(write)
            .create(create)
            .create_new(create_new)
            .mode(mode.unwrap_or(0o644))
            .open(&path)?;

        let digest_file = if self.digest_check {
            path.push(".dg");
            Some(
                std::fs::OpenOptions::new()
                    .read(read)
                    .write(write)
                    .create(create)
                    .create_new(create_new)
                    .mode(mode.unwrap_or(0o644))
                    .open(path)?,
            )
        } else {
            None
        };

        self.wrap_file(file, digest_file, create)
    }

    /// Creates new crypto dir at `path` with random directory IV
    fn create_dir(&self, mut path: OsString, mode: u32) -> Result<Siv, IoError> {
        let mode = Mode::from_bits(mode).expect("should be a valid mode");

        nix::unistd::mkdir(path.as_os_str(), mode)?;

        path.push("/.dircfg");
        let mut dircfg = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;

        let iv = <Aes256SivAead as aead::AeadCore>::generate_nonce(aead::OsRng);

        dircfg.write_all(&iv)?;

        Ok(iv.into())
    }

    fn encrypt_filename(&self, name: &str, iv: &Siv) -> Result<String> {
        let ct = self
            .dir_cipher
            .encrypt(iv[..].into(), name.as_bytes())
            .with_context(|| "failed encrypting filename")?;

        let out = b64.encode(ct);
        Ok(out)
    }

    fn decrypt_filename(&self, name: &str, iv: &Siv) -> Result<String> {
        let Ok(ciphertext) = b64.decode(name) else {
            bail!("failed b64 decoding filename; {}", name)
        };

        let pt = self
            .dir_cipher
            .decrypt(iv[..].into(), &ciphertext[..])
            .with_context(|| "failed decrypting filename")?;

        let name = String::from_utf8(pt).context("failed converting byte array to string")?;

        Ok(name)
    }

    /// Decrypts the given symlink given in `target`
    fn encrypt_symlink(&mut self, target: &std::path::Path) -> Result<String> {
        let mut buf = target.to_string_lossy().as_bytes().to_vec();
        let iv = crate::crypto::generate_12b_iv();

        self.symlink_cipher
            .encrypt_in_place(iv[..].into(), &[], &mut buf)?;

        let mut out = vec![];
        out.extend(iv);
        out.extend(buf);

        Ok(b64.encode(out))
    }

    /// Decrypts the given symlink given in `data`
    fn decrypt_symlink(&self, data: std::path::PathBuf) -> Result<std::path::PathBuf> {
        let Some(data) = data.to_str() else {
            bail!("failed converting path to string");
        };

        let mut decoded = b64.decode(data)?;

        let (iv, data) = decoded.split_at_mut(12);

        let decrypted = self.symlink_cipher.decrypt(iv[..].into(), &data[..])?;

        Ok(std::path::PathBuf::from(String::from_utf8(decrypted)?))
    }
}

#[derive(Error, Debug)]
pub enum LookupError {
    #[error("nonexistent parent dir with inode `{0}`")]
    NoParentInode(Inode),
    #[error("directory `{parent}` does not contain file {child:?}")]
    NotFound { parent: String, child: OsString },
    #[error("inode `{0}` is not a directory")]
    ParentInodeNotDir(Inode),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("directory does not contain config file; {0}")]
    NoDirConfig(std::io::Error),
    #[error("failed encrypting filename; {0}")]
    EncryptionFailed(anyhow::Error),
    #[error("unsupported filetype")]
    UnsupportedFiletype,
}

type Inode = u64;
type Handle = u64;
type Siv = [u8; 16];

const BLOCK_SIZE: u64 = 4096;

#[derive(Debug)]
enum MyFileType {
    RegularFile,
    Directory(Siv),
    Symlink,
}

#[derive(Debug)]
struct InodeData {
    inode: Inode,
    lookup_count: std::sync::atomic::AtomicU64,
    path: String,
    filetype: MyFileType,
}

struct HandleData<Cipher, Digest, Mode>
where
    Cipher: crypto::Cipher,
    Digest: crypto::Digest,
    Mode: crypto::Encoder,
{
    file: CryptoFile<Cipher, Digest, Mode>,
}

struct DirHandleData {
    iter: std::iter::Peekable<nix::dir::OwningIter>,
}

pub struct Fs<Cipher, Digest, Mode>
where
    Cipher: crypto::Cipher,
    Digest: crypto::Digest,
    Mode: crypto::Encoder,
{
    inodes: HashMap<Inode, InodeData>,
    file_handles: HashMap<Handle, HandleData<Cipher, Digest, Mode>>,
    dir_handles: HashMap<Handle, DirHandleData>,
    /// counter for storing open file handles
    counter: AtomicU64,
    root_path: String,
    /// Handles the cryptography, such as opening `CryptoFile`'s, encrypting paths, etc.
    crypto: CryptoHandler<Cipher, Digest, Mode>,
}

impl<Cipher, Digest, E> Fs<Cipher, Digest, E>
where
    Cipher: crypto::Cipher,
    Digest: crypto::Digest,
    E: crypto::Encoder,
    CryptoFile<Cipher, Digest, E>: crypto::traits::DigestHandler<Digest>,
{
    pub fn new(
        encrypted_root: String,
        key: [u8; 32],
        dir_key: [u8; 64],
        digest_check: bool,
    ) -> Self {
        Self {
            inodes: HashMap::new(),
            file_handles: HashMap::new(),
            dir_handles: HashMap::new(),
            counter: 0.into(),
            root_path: encrypted_root,
            crypto: CryptoHandler::new(key, dir_key, digest_check),
        }
    }

    /// Get fuser::FileType out of file's metadata
    fn filetype(inode: &Metadata) -> FileType {
        let ft = inode.file_type();
        if ft.is_file() {
            FileType::RegularFile
        } else if ft.is_dir() {
            return FileType::Directory;
        } else if ft.is_symlink() {
            return FileType::Symlink;
        } else if ft.is_block_device() {
            return FileType::BlockDevice;
        } else if ft.is_char_device() {
            return FileType::CharDevice;
        } else if ft.is_socket() {
            return FileType::Socket;
        } else if ft.is_fifo() {
            return FileType::NamedPipe;
        } else {
            unreachable!("missing filetype")
        }
    }

    fn do_lookup(&mut self, parent_ino: Inode, name: &OsStr) -> Result<&InodeData, LookupError> {
        let Some(parent) = self.inodes.get(&parent_ino) else {
            return Err(LookupError::NoParentInode(parent_ino));
        };

        let iv = match parent.filetype {
            MyFileType::Directory(iv) => iv,
            MyFileType::RegularFile | MyFileType::Symlink => {
                return Err(LookupError::ParentInodeNotDir(parent_ino));
            }
        };

        let encrypted_name = match self.crypto.encrypt_filename(&name.to_string_lossy(), &iv) {
            Ok(name) => name,
            Err(e) => {
                return Err(LookupError::EncryptionFailed(e));
            }
        };

        let path = format!("{}/{}", parent.path, encrypted_name);

        let metadata = std::fs::symlink_metadata(&path).map_err(|_| LookupError::NotFound {
            parent: parent.path.clone(),
            child: name.into(),
        })?;

        let entry = match self.inodes.entry(metadata.ino()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let filetype = match Self::filetype(&metadata) {
                    FileType::RegularFile => MyFileType::RegularFile,
                    FileType::Directory => {
                        let mut dircfg = std::fs::File::open(path.clone() + "/.dircfg")
                            .map_err(LookupError::NoDirConfig)?;
                        let mut iv: Siv = [0u8; 16];
                        dircfg.read_exact(&mut iv)?;
                        MyFileType::Directory(iv)
                    }
                    FileType::Symlink => MyFileType::Symlink,
                    _ => {
                        return Err(LookupError::UnsupportedFiletype);
                    }
                };
                entry.insert(InodeData {
                    inode: metadata.ino(),
                    lookup_count: 0.into(),
                    filetype,
                    path: path.clone(),
                })
            }
        };

        entry.lookup_count.fetch_add(1, Ordering::Relaxed);

        Ok(entry)
    }

    fn fileattr(data: &InodeData) -> Result<fuser::FileAttr, IoError> {
        let value = std::fs::symlink_metadata(&data.path)?;
        let cr = match value.created() {
            Ok(time) => time,
            Err(_) => SystemTime::UNIX_EPOCH + Duration::new(0, 0),
        };

        let sz = match data.filetype {
            MyFileType::RegularFile => crypto::read_size(&data.path)?,
            _ => value.size(),
        };

        Ok(fuser::FileAttr {
            ino: data.inode,
            size: sz,
            blocks: value.blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.atime() as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.mtime() as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.ctime() as u64),
            crtime: cr,
            kind: Self::filetype(&value),
            perm: value.permissions().mode() as u16,
            nlink: value.nlink() as u32,
            uid: value.uid(),
            gid: value.gid(),
            rdev: value.rdev() as u32,
            blksize: value.blksize() as u32,
            flags: 0,
        })
    }

    fn fileattr_path(path: &str) -> Result<fuser::FileAttr, IoError> {
        let value = std::fs::symlink_metadata(path)?;

        let filetype = Self::filetype(&value);

        let size = if value.file_type().is_file() {
            crypto::read_size(path)?
        } else {
            value.size()
        };
        let cr = match value.created() {
            Ok(time) => time,
            Err(_) => SystemTime::UNIX_EPOCH + Duration::new(0, 0),
        };

        Ok(fuser::FileAttr {
            ino: value.ino(),
            size,
            blocks: value.blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.atime() as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.mtime() as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.ctime() as u64),
            crtime: cr,
            kind: filetype,
            perm: value.permissions().mode() as u16,
            nlink: value.nlink() as u32,
            uid: value.uid(),
            gid: value.gid(),
            rdev: value.rdev() as u32,
            blksize: value.blksize() as u32,
            flags: 0,
        })
    }

    fn new_file_handle(&mut self, file: CryptoFile<Cipher, Digest, E>) -> u64 {
        let x = self.counter.fetch_add(1, Ordering::Relaxed);

        self.file_handles.insert(x, HandleData { file });

        x
    }

    fn get_dir_contents(&self, path: &str) -> Result<Vec<std::fs::DirEntry>, IoError> {
        Ok(std::fs::read_dir(path)?
            .filter_map(|x| x.ok())
            .collect::<Vec<_>>())
    }
}

macro_rules! os_err_ret {
    ($e:ident, $reply:ident) => {
        match $e.raw_os_error() {
            Some(x) => $reply.error(x),
            None => $reply.error(libc::EIO),
        }
        return;
    };
}

macro_rules! get_inode {
    ($self:ident, $ino:ident, $reply:ident) => {
        match $self.inodes.get(&$ino) {
            Some(x) => x,
            None => {
                error!("no inode found");
                $reply.error(libc::EIO);
                return;
            }
        }
    };
}

macro_rules! get_dir_iv {
    ($parent_ino:ident, $reply:ident) => {
        match $parent_ino.filetype {
            MyFileType::RegularFile | MyFileType::Symlink => {
                error!("parent inode is not a directory");
                $reply.error(libc::EIO);
                return;
            }
            MyFileType::Directory(iv) => iv,
        }
    };
}

macro_rules! encrypt_filename {
    ($self:ident, $name:ident, $iv:ident, $reply:ident) => {
        match $self
            .crypto
            .encrypt_filename(&$name.to_string_lossy(), &$iv)
        {
            Ok(name) => name,
            Err(e) => {
                error!("failed encrypting filename; {e}");
                $reply.error(libc::EIO);
                return;
            }
        }
    };
}

macro_rules! get_inode_mut {
    ($self:ident, $ino:ident, $reply:ident) => {
        match $self.inodes.get_mut(&$ino) {
            Some(x) => x,
            None => {
                error!("no inode found");
                $reply.error(libc::EIO);
                return;
            }
        }
    };
}

macro_rules! get_file_handle_mut {
    ($self:ident, $fh:ident, $reply:ident) => {
        match $self.file_handles.get_mut(&$fh) {
            Some(x) => x,
            None => {
                error!("no file handle found");
                $reply.error(libc::EIO);
                return;
            }
        }
    };
}

macro_rules! get_file_attributes {
    ($ino:ident, $reply:ident) => {
        match Self::fileattr($ino) {
            Ok(x) => x,
            Err(e) => {
                error!("failed getting file attributes");
                os_err_ret!(e, $reply);
            }
        }
    };
}

macro_rules! get_file_attributes_path {
    ($path:ident, $reply:ident) => {
        match Self::fileattr_path(&$path) {
            Ok(x) => x,
            Err(e) => {
                error!("failed getting file attributes");
                os_err_ret!(e, $reply);
            }
        }
    };
}

// Helper functions for getting read and write flags
fn test_rd(flags: i32) -> bool {
    (flags & libc::O_ACCMODE == libc::O_RDONLY) || (flags & libc::O_ACCMODE == libc::O_RDWR)
}

fn test_wr(flags: i32) -> bool {
    (flags & libc::O_ACCMODE == libc::O_WRONLY) || (flags & libc::O_ACCMODE == libc::O_RDWR)
}

impl<Cipher, Digest, Mode> Filesystem for Fs<Cipher, Digest, Mode>
where
    Cipher: crypto::Cipher,
    Digest: crypto::Digest,
    Mode: crypto::Encoder,
    CryptoFile<Cipher, Digest, Mode>: crypto::traits::DigestHandler<Digest>,
{
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        use caps::{CapSet, Capability};

        std::os::unix::fs::chroot(&self.root_path).unwrap();
        std::env::set_current_dir("/").unwrap();
        debug!("current dir {:?}", std::env::current_dir().unwrap());

        let _ = caps::drop(None, CapSet::Effective, Capability::CAP_SYS_CHROOT);
        let _ = caps::drop(None, CapSet::Permitted, Capability::CAP_SYS_CHROOT);

        let effective = caps::read(None, CapSet::Effective).unwrap();
        let permitted = caps::read(None, CapSet::Permitted).unwrap();
        assert!(
            !effective.contains(&Capability::CAP_SYS_CHROOT),
            "effective capabilities contains CAP_SYS_CHROOT"
        );
        assert!(
            !permitted.contains(&Capability::CAP_SYS_CHROOT),
            "permitted capabilities contains CAP_SYS_CHROOT"
        );

        let iv: Siv = match std::fs::File::open("/.dircfg") {
            Ok(mut file) => {
                let mut buf = [0u8; 16];
                if let Err(e) = file.read_exact(&mut buf) {
                    let a = match e.raw_os_error() {
                        Some(x) => x,
                        None => libc::EIO,
                    };
                    return Err(a);
                }
                buf
            }
            Err(e) if e.kind() == IoErrorKind::NotFound => {
                let Ok(mut dircfg) = std::fs::File::create_new("/.dircfg") else {
                    return Err(libc::EIO);
                };

                let iv = <Aes256SivAead as aead::AeadCore>::generate_nonce(aead::OsRng);

                if let Err(e) = dircfg.write_all(&iv[..]) {
                    let a = match e.raw_os_error() {
                        Some(x) => x,
                        None => libc::EIO,
                    };
                    return Err(a);
                };
                iv[..].try_into().expect("dircfg is a vvalid iv")
            }

            Err(_) => {
                return Err(libc::EIO);
            }
        };

        self.inodes.insert(
            1,
            InodeData {
                inode: 1,
                lookup_count: 0.into(),
                filetype: MyFileType::Directory(iv),
                path: String::from("/"),
            },
        );

        info!("{:?}", self.inodes);

        Ok(())
    }

    fn destroy(&mut self) {}

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        match self.do_lookup(parent, name) {
            Ok(x) => match Self::fileattr(x) {
                Ok(fa) => reply.entry(&TTL, &fa, 0),
                Err(e) => {
                    debug!("lookup(): failed getting file attributes");
                    os_err_ret!(e, reply);
                }
            },
            Err(e) => match e {
                LookupError::NotFound { .. } => {
                    debug!("lookup(): {}", e);
                    reply.error(libc::ENOENT);
                }
                _ => {
                    error!("lookup(): {}", e);
                    reply.error(libc::EIO);
                }
            },
        }
    }

    fn forget(&mut self, _req: &fuser::Request<'_>, ino: u64, nlookup: u64) {
        match self.inodes.get_mut(&ino) {
            Some(ref x) => {
                let _ = x.lookup_count.fetch_sub(nlookup, Ordering::Relaxed);
                if x.lookup_count.load(Ordering::Relaxed) == 0 {
                    self.inodes.remove(&ino);
                }
            }
            None => {
                error!("forget(): supplied inode does not exist {}", ino);
            }
        }
    }

    fn batch_forget(&mut self, req: &fuser::Request<'_>, nodes: &[fuser::fuse_forget_one]) {
        for node in nodes {
            self.forget(req, node.nodeid, node.nlookup);
        }
    }

    #[instrument(skip_all)]
    fn getattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: Option<u64>,
        reply: fuser::ReplyAttr,
    ) {
        info!("[Called] getattr(ino: {:?}, fh: {:#x?})", ino, fh);

        let entry = get_inode!(self, ino, reply);
        let mut a = match Self::fileattr(entry) {
            Ok(x) => x,
            Err(e) => {
                debug!("lookup(): failed getting file attributes");
                os_err_ret!(e, reply);
            }
        };

        if ino == 1 {
            a.ino = 1;
        }

        reply.attr(&TTL, &a);
    }

    #[instrument(skip_all)]
    fn setattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        info!(
            "[Called] setattr(ino: {:#x?}, mode: {:?}, uid: {:?}, \
            gid: {:?}, size: {:?}, fh: {:?}, flags: {:?})",
            ino, mode, uid, gid, size, fh, flags
        );
        let inode = get_inode_mut!(self, ino, reply);

        if let Some(mode) = mode {
            debug!("chmod() called with {:?}, {:o}", inode, mode);

            if let Err(e) =
                std::fs::set_permissions(&inode.path, std::fs::Permissions::from_mode(mode))
            {
                error!("failed to chmod() file; {}", e);
                os_err_ret!(e, reply);
            };

            let fa = get_file_attributes!(inode, reply);
            reply.attr(&TTL, &fa);
            return;
        }

        if uid.is_some() || gid.is_some() {
            debug!("chown() called with {:?} {:?} {:?}", inode, uid, gid);

            if let Err(e) = std::os::unix::fs::lchown(&inode.path, uid, gid) {
                error!("failed to chown() file; {}", e);
                os_err_ret!(e, reply);
            };

            let fa = get_file_attributes!(inode, reply);
            reply.attr(&TTL, &fa);
            return;
        }

        if let Some(size) = size {
            match inode.filetype {
                MyFileType::RegularFile => {
                    debug!("truncate() called with {:?} {:?}", inode, size);
                    let file = if let Some(fh) = fh {
                        &mut self
                            .file_handles
                            .get_mut(&fh)
                            .expect("a valid filehandle")
                            .file
                    } else {
                        &mut match self.crypto.open_file(&inode.path, 0, libc::O_RDWR) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("truncate(): failed opening file");
                                os_err_ret!(e, reply);
                            }
                        }
                    };

                    if let Err(e) = file.truncate(size) {
                        os_err_ret!(e, reply);
                    };

                    let pos = match file.stream_position() {
                        Ok(x) => x,
                        Err(e) => {
                            error!("truncate(): failed getting current file position");
                            os_err_ret!(e, reply);
                        }
                    };
                    if size > pos {
                        let _ = file.seek(SeekFrom::End(0));
                    }
                }
                MyFileType::Directory(_) | MyFileType::Symlink => {
                    error!("called truncate() on a directory or symlink");
                    reply.error(libc::EOPNOTSUPP);
                    return;
                }
            }
        }

        let atime = if let Some(atime) = atime {
            debug!("utimens() called with {:?}, atime={:?}", inode, atime);
            match atime {
                fuser::TimeOrNow::SpecificTime(system_time) => {
                    filetime::FileTime::from_system_time(system_time)
                }
                fuser::TimeOrNow::Now => filetime::FileTime::now(),
            }
        } else {
            let metadata = match std::fs::symlink_metadata(&inode.path) {
                Ok(x) => x,
                Err(e) => {
                    error!("setattr(): failed getting metadta()");
                    os_err_ret!(e, reply);
                }
            };
            filetime::FileTime::from_last_access_time(&metadata)
        };

        let mtime = if let Some(mtime) = mtime {
            debug!("utimens() called with {:?}, mtime={:?}", inode, mtime);

            match mtime {
                fuser::TimeOrNow::SpecificTime(system_time) => {
                    filetime::FileTime::from_system_time(system_time)
                }
                fuser::TimeOrNow::Now => filetime::FileTime::now(),
            }
        } else {
            let metadata = match std::fs::symlink_metadata(&inode.path) {
                Ok(x) => x,
                Err(e) => {
                    error!("setattr(): failed getting metadta()");
                    os_err_ret!(e, reply);
                }
            };
            filetime::FileTime::from_last_modification_time(&metadata)
        };

        if let Err(e) = filetime::set_symlink_file_times(&inode.path, atime, mtime) {
            error!("failed to change times; {}", e);
            os_err_ret!(e, reply);
        };

        let fa = get_file_attributes!(inode, reply);
        reply.attr(&Duration::new(0, 0), &fa);
    }

    #[instrument(skip_all)]
    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        info!("[Called] readlink(ino: {:#x?})", ino);
        let inode = get_inode_mut!(self, ino, reply);

        let buf = match std::fs::read_link(&inode.path) {
            Ok(x) => x,
            Err(e) => {
                error!("readlink(): failed reading symlink");
                os_err_ret!(e, reply);
            }
        };

        let buf = match self.crypto.decrypt_symlink(buf) {
            Ok(x) => x,
            Err(e) => {
                error!("readlink(): failed decrypting symlink; {}", e);
                reply.error(libc::EIO);
                return;
            }
        };
        reply.data(buf.to_string_lossy().as_bytes());
    }

    fn mknod(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: fuser::ReplyEntry,
    ) {
        info!(
            "[Called] mknod(parent: {:#x?}, mode: {}, umask: {:#x?})",
            parent, mode, umask
        );
        if mode & libc::S_IFREG != libc::S_IFREG {
            reply.error(libc::EOPNOTSUPP);
            return;
        }

        let parent_ino = get_inode!(self, parent, reply);
        let iv = get_dir_iv!(parent_ino, reply);
        let name = encrypt_filename!(self, name, iv, reply);
        let path = format!("{}/{}", parent_ino.path, name);

        let _cryptofile =
            match self
                .crypto
                .create_file(path.clone().into(), None, libc::O_CREAT | libc::O_RDWR)
            {
                Ok(cryptofile) => cryptofile,
                Err(e) => {
                    debug!("failed creating cryptofile; {}", e);
                    os_err_ret!(e, reply);
                }
            };

        let metadata = std::fs::metadata(&path).expect("file just created");
        let x = metadata.ino();
        self.inodes.insert(
            x,
            InodeData {
                inode: metadata.ino(),
                lookup_count: 0.into(),
                filetype: MyFileType::RegularFile,
                path,
            },
        );

        let data = self.inodes.get(&x).expect("inode has just been inserted");

        let fa = get_file_attributes!(data, reply);
        reply.entry(&TTL, &fa, 0);
    }

    #[instrument(skip(self, _req, reply))]
    fn mkdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        info!(
            "[Called] mkdir(parent: {:#x?}, mode: {}, umask: {:#x?})",
            parent, mode, umask
        );
        let parent_ino = get_inode!(self, parent, reply);
        let parent_iv = get_dir_iv!(parent_ino, reply);
        let name = encrypt_filename!(self, name, parent_iv, reply);
        let path = format!("{}/{}", parent_ino.path, name);

        let iv = match self.crypto.create_dir(path.clone().into(), mode & !umask) {
            Ok(x) => x,
            Err(e) => {
                error!("failed to create dir; {}", e);
                os_err_ret!(e, reply);
            }
        };

        let metadata = std::fs::metadata(&path).expect("directory just created");
        let x = metadata.ino();
        self.inodes.insert(
            x,
            InodeData {
                inode: metadata.ino(),
                lookup_count: 0.into(),
                filetype: MyFileType::Directory(iv),
                path,
            },
        );

        let data = self.inodes.get(&x).expect("inode has been inserted before");

        let fa = get_file_attributes!(data, reply);
        reply.entry(&TTL, &fa, 0);
    }

    #[instrument(skip(self, _req, reply))]
    fn rmdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        info!("[Called] rmdir(parent: {:#x?})", parent);
        let parent_ino = get_inode!(self, parent, reply);
        let iv = get_dir_iv!(parent_ino, reply);
        let name = encrypt_filename!(self, name, iv, reply);
        let path = format!("{}/{}", parent_ino.path, name);

        let dir_contents = match self.get_dir_contents(&path) {
            Ok(x) => x,
            Err(e) => {
                error!("failed to get directory contents; {}", e);
                os_err_ret!(e, reply);
            }
        };

        if dir_contents.len() == 1 && dir_contents[0].file_name() == ".dircfg" {
            if let Err(e) = std::fs::remove_dir_all(path) {
                error!("failed to remove directory; {}", e);
                os_err_ret!(e, reply);
            }
            reply.ok();
        } else {
            reply.error(libc::ENOTEMPTY);
        }
    }

    fn rename(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        if flags != 0 && flags != 1 {
            error!("rename() received unsupported flag; flags={}", flags);
            reply.error(libc::EOPNOTSUPP);
            return;
        }

        let parent_ino = get_inode!(self, parent, reply);
        let iv = get_dir_iv!(parent_ino, reply);
        let name = encrypt_filename!(self, name, iv, reply);
        let mut path = format!("{}/{}", parent_ino.path, name);

        let new_parent_ino = get_inode!(self, newparent, reply);
        let new_iv = get_dir_iv!(new_parent_ino, reply);
        let new_name = encrypt_filename!(self, newname, new_iv, reply);
        let mut new_path = format!("{}/{}", new_parent_ino.path, new_name);

        // if NOREPLACE is set, check if new_path doesn't exist
        if flags == 1 && std::fs::metadata(&new_path).is_ok() {
            error!("failed renaming file, file exists at newpath");
            reply.error(libc::EEXIST);
            return;
        }

        let metadata = get_file_attributes_path!(path, reply);
        // reinsert the inode with new path
        let removed = self.inodes.remove(&metadata.ino).expect("inode exists");
        self.inodes.insert(
            metadata.ino,
            InodeData {
                inode: metadata.ino,
                lookup_count: removed.lookup_count,
                filetype: MyFileType::RegularFile,
                path: new_path.clone(),
            },
        );

        if let Err(e) = std::fs::rename(&path, &new_path) {
            error!("failed renaming file; {}", e);
            reply.error(libc::EIO);
            return;
        }

        if self.crypto.digest_check {
            path.push_str(".dg");
            new_path.push_str(".dg");
            if let Err(e) = std::fs::rename(&path, &new_path) {
                error!("failed renaming digest file; {}", e);
                reply.error(libc::EIO);
                return;
            }
        }
        reply.ok();
    }

    #[instrument(skip(self, _req, reply))]
    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        let inode = get_inode!(self, ino, reply);

        let file = match self
            .crypto
            .create_file(inode.path.clone().into(), None, flags)
        {
            Ok(file) => file,
            Err(e) => {
                error!("failed opening crypto file; {}", e);
                os_err_ret!(e, reply);
            }
        };

        let fh = self.new_file_handle(file);

        reply.opened(fh, flags as u32);
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let fd = get_file_handle_mut!(self, fh, reply);

        let mut buf = vec![0u8; size as usize];
        let Ok(_) = fd.file.seek(SeekFrom::Start(offset as u64)) else {
            reply.error(libc::EIO);
            return;
        };
        // Doing it in a loop due to reading beyond file size, otherwise could use read_exact()
        let mut bytes_read: usize = 0;
        while bytes_read < size as usize {
            match fd.file.read(&mut buf[bytes_read..]) {
                Ok(0) => break,
                Ok(x) => bytes_read += x,
                Err(e) => {
                    error!("failed reading data; {}", e);
                    os_err_ret!(e, reply);
                }
            }
        }

        debug!("read(): read {} bytes of data", bytes_read);
        reply.data(&buf[..bytes_read]);
    }

    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        let fd = get_file_handle_mut!(self, fh, reply);

        let Ok(_) = fd.file.seek(SeekFrom::Start(offset as u64)) else {
            reply.error(libc::EIO);
            return;
        };
        if let Err(e) = fd.file.write_all(data) {
            error!("write(): error when trying to write; {e}");
            os_err_ret!(e, reply);
        }
        reply.written(data.len() as u32);
    }

    fn flush(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        let fd = get_file_handle_mut!(self, fh, reply);

        if let Err(e) = fd.file.flush() {
            error!("flush(): error when trying to flush; {e}");
            os_err_ret!(e, reply);
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.file_handles.remove(&fh);
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let fd = get_file_handle_mut!(self, fh, reply);

        if let Err(e) = if datasync {
            fd.file.sync_data()
        } else {
            fd.file.sync_all()
        } {
            error!("fsync(): error when trying to sync; {e}");
            os_err_ret!(e, reply);
        }

        reply.ok();
    }

    #[instrument(skip(self, _req, reply))]
    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        let inode = get_inode!(self, ino, reply);

        let file = match std::fs::OpenOptions::new()
            .read(
                (flags & libc::O_ACCMODE == libc::O_RDONLY)
                    || (flags & libc::O_ACCMODE == libc::O_RDWR),
            )
            .write(
                (flags & libc::O_ACCMODE == libc::O_WRONLY)
                    || (flags & libc::O_ACCMODE == libc::O_RDWR),
            )
            .custom_flags(flags)
            .open(&inode.path)
        {
            Ok(file) => file,
            Err(e) => {
                error!("failed opening directory with inode {}", ino);
                os_err_ret!(e, reply);
            }
        };

        let mut dircfg = match std::fs::File::open(inode.path.clone() + "/.dircfg") {
            Ok(x) => x,
            Err(e) => {
                error!("directory does not contain directory config");
                os_err_ret!(e, reply);
            }
        };

        let mut iv: Siv = [0u8; 16];
        if let Err(e) = dircfg.read_exact(&mut iv) {
            error!("failed reading directory config");
            os_err_ret!(e, reply);
        }

        let x = self.counter.fetch_add(1, Ordering::Relaxed);

        self.dir_handles.insert(
            x,
            DirHandleData {
                iter: nix::dir::Dir::from(file)
                    .expect("File should be a directory")
                    .into_iter()
                    .peekable(),
            },
        );

        reply.opened(x, flags as u32);
    }

    #[instrument(skip(self, _req, reply))]
    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let x = get_inode!(self, ino, reply);
        let iv = get_dir_iv!(x, reply);

        let Some(&mut DirHandleData {
            iter: ref mut diriter,
        }) = self.dir_handles.get_mut(&fh)
        else {
            error!("readdir(): no dir handle");
            reply.error(libc::EIO);
            return;
        };

        let mut i = offset + 1;
        while let Some(entry) = diriter.peek() {
            let Ok(e) = entry else {
                error!("failed listing filename");
                diriter.next();
                continue;
            };

            let Ok(name) = e.file_name().to_str() else {
                error!("failed converting filename to string");
                diriter.next();
                continue;
            };

            if name.ends_with(".dg") || name == "fscryptrs.config" || name == ".dircfg" {
                diriter.next();
                continue;
            }

            let plaintext_name = if name == "." || name == ".." {
                name
            } else {
                &match self.crypto.decrypt_filename(name, &iv) {
                    Ok(x) => x,
                    Err(e) => {
                        error!("failed decrypting filename; {e}");
                        diriter.next();
                        continue;
                    }
                }
            };

            let path = format!("{}/{}", x.path, name);

            let fa = get_file_attributes_path!(path, reply);
            if reply.add(fa.ino, i, fa.kind, plaintext_name) {
                break;
            }
            i += 1;
            diriter.next();
        }

        reply.ok();
    }

    // Not needed to implement, kernel will call readdir and then open the entries with open() call
    fn readdirplus(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectoryPlus,
    ) {
        debug!(
            "[Not Implemented] readdirplus(ino: {:#x?}, fh: {}, offset: {})",
            ino, fh, offset
        );
        reply.error(libc::ENOSYS);
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        self.dir_handles.remove(&fh);
        reply.ok();
    }

    fn fsyncdir(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    // Nothing to report here
    fn statfs(&mut self, _req: &fuser::Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn access(&mut self, _req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        let x = get_inode!(self, ino, reply);

        let Some(flags) = nix::unistd::AccessFlags::from_bits(mask) else {
            error!("access(): received invalid access flags {}", mask);
            reply.error(libc::EINVAL);
            return;
        };

        if nix::unistd::access(x.path.as_str(), flags).is_ok() {
            reply.ok()
        } else {
            error!("access(): no access to specified file and flags={}", mask);
            reply.error(libc::EACCES)
        }
    }

    // Not implemented, use mknod() and open() instead
    fn create(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        _name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        debug!(
            "[Not Implemented] create(parent: {:#x?}, mode: {}, \
            umask: {:#x?}, flags: {})",
            parent, mode, umask, flags
        );
        reply.error(libc::ENOSYS);
    }

    fn lseek(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: fuser::ReplyLseek,
    ) {
        let fd = get_file_handle_mut!(self, fh, reply);

        let x = match whence {
            libc::SEEK_SET => SeekFrom::Start(offset as u64),
            libc::SEEK_CUR => SeekFrom::Current(offset),
            libc::SEEK_END => SeekFrom::End(offset),
            libc::SEEK_HOLE | libc::SEEK_DATA => {
                error!(
                    "lseek(): received unsupported whence; SEEK_HOLE or SEEK_DATA; flags={}",
                    whence
                );
                reply.error(libc::EOPNOTSUPP);
                return;
            }
            _ => unreachable!("all possible whence values are covered"),
        };

        let Ok(_) = fd.file.seek(x) else {
            reply.error(libc::EIO);
            return;
        };

        reply.error(libc::ENOSYS);
    }

    #[instrument(skip(self, _req, reply))]
    fn unlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let parent_ino = get_inode!(self, parent, reply);

        let iv = get_dir_iv!(parent_ino, reply);

        let enc_name = encrypt_filename!(self, name, iv, reply);

        let mut path = format!("{}/{}", parent_ino.path, enc_name);

        if let Err(e) = std::fs::remove_file(&path) {
            error!("failed removing file");
            os_err_ret!(e, reply);
        };

        if self.crypto.digest_check {
            path.push_str(".dg");

            if let Err(e) = std::fs::remove_file(&path) {
                error!("failed removing digest file");
                os_err_ret!(e, reply);
            };
        }

        reply.ok();
    }

    fn symlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        let parent_ino = get_inode!(self, parent, reply);
        let iv = get_dir_iv!(parent_ino, reply);
        let name = encrypt_filename!(self, link_name, iv, reply);
        let path = format!("{}/{}", parent_ino.path, name);

        let encrypted = match self.crypto.encrypt_symlink(target) {
            Ok(x) => x,
            Err(e) => {
                error!("failed encrypting symlink; {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        if let Err(e) = std::os::unix::fs::symlink(&encrypted, &path) {
            error!("failed creating symlink",);
            os_err_ret!(e, reply);
        }

        debug!("getting metadata of symlink at path {}", &path);

        let metadata = get_file_attributes_path!(path, reply);

        let ino = metadata.ino;
        self.inodes.insert(
            ino,
            InodeData {
                inode: ino,
                lookup_count: 0.into(),
                filetype: MyFileType::Symlink,
                path,
            },
        );

        let data = self.inodes.get(&ino).expect("inode has just been inserted");

        let fa = get_file_attributes!(data, reply);
        reply.entry(&TTL, &fa, 0);
    }

    fn link(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let entry = get_inode!(self, ino, reply);
        let new_parent = get_inode!(self, newparent, reply);
        let iv = get_dir_iv!(new_parent, reply);
        let enc_name = encrypt_filename!(self, newname, iv, reply);
        let new_path = format!("{}/{}", new_parent.path, enc_name);

        if let Err(e) = std::fs::hard_link(&entry.path, &new_path) {
            error!("failed linking file; {}", e);
            os_err_ret!(e, reply);
        }

        if self.crypto.digest_check {
            if let Err(e) = std::fs::hard_link(&entry.path, new_path + ".dg") {
                error!("failed linking digest file; {}", e);
                os_err_ret!(e, reply);
            }
        }

        reply.error(libc::EPERM);
    }

    fn fallocate(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: fuser::ReplyEmpty,
    ) {
        let fd = get_file_handle_mut!(self, fh, reply);

        if mode != 0 {
            reply.error(libc::EOPNOTSUPP);
            return;
        }

        let Ok(_) = fd.file.seek(SeekFrom::Start(offset as u64)) else {
            reply.error(libc::EIO);
            return;
        };

        let buf = [0u8; 4096];
        let mut written = 0;
        while written < length {
            match fd
                .file
                .write(&buf[0..std::cmp::min(length - written, BLOCK_SIZE as i64) as usize])
            {
                Ok(x) => written += x as i64,
                Err(e) => {
                    error!("failed fallocating file; {}", e);
                    os_err_ret!(e, reply);
                }
            }
        }

        reply.ok();
    }

    fn copy_file_range(
        &mut self,
        _req: &fuser::Request<'_>,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        _offset_out: i64,
        len: u64,
        _flags: u32,
        reply: fuser::ReplyWrite,
    ) {
        let mut buf = vec![0u8; len as usize];

        // We do not support opening one file multiple times
        if ino_in == ino_out {
            reply.error(libc::EOPNOTSUPP);
            return;
        }

        let fd_in = get_file_handle_mut!(self, fh_in, reply);

        let Ok(_) = fd_in.file.seek(SeekFrom::Start(offset_in as u64)) else {
            reply.error(libc::EIO);
            return;
        };

        if let Err(e) = fd_in.file.read_exact(&mut buf) {
            error!("copy_file_range(): error when trying to read; {}", e);
            os_err_ret!(e, reply);
        };

        let fd_out = get_file_handle_mut!(self, fh_out, reply);
        let Ok(_) = fd_out.file.seek(SeekFrom::Start(offset_in as u64)) else {
            reply.error(libc::EIO);
            return;
        };

        if let Err(e) = fd_out.file.write_all(&buf) {
            error!("copy_file_range(): error when trying to write; {}", e);
            os_err_ret!(e, reply);
        };

        reply.written(buf.len() as u32);
    }

    fn bmap(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        blocksize: u32,
        idx: u64,
        reply: fuser::ReplyBmap,
    ) {
        debug!(
            "[Not Implemented] bmap(ino: {:#x?}, blocksize: {}, idx: {})",
            ino, blocksize, idx,
        );
        reply.error(libc::ENOSYS);
    }

    fn ioctl(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {
        debug!(
            "[Not Implemented] ioctl(ino: {:#x?}, fh: {}, flags: {}, cmd: {}, \
            in_data.len(): {}, out_size: {})",
            ino,
            fh,
            flags,
            cmd,
            in_data.len(),
            out_size,
        );
        reply.error(libc::ENOSYS);
    }

    fn poll(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        ph: fuser::PollHandle,
        events: u32,
        flags: u32,
        reply: fuser::ReplyPoll,
    ) {
        debug!(
            "[Not Implemented] poll(ino: {:#x?}, fh: {}, ph: {:?}, events: {}, flags: {})",
            ino, fh, ph, events, flags
        );
        reply.error(libc::ENOSYS);
    }

    fn setxattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        _value: &[u8],
        flags: i32,
        position: u32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] setxattr(ino: {:#x?}, name: {:?}, flags: {:#x?}, position: {})",
            ino, name, flags, position
        );
        reply.error(libc::ENOSYS);
    }

    fn getxattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        debug!(
            "[Not Implemented] getxattr(ino: {:#x?}, name: {:?}, size: {})",
            ino, name, size
        );
        reply.error(libc::ENOSYS);
    }

    fn listxattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        debug!(
            "[Not Implemented] listxattr(ino: {:#x?}, size: {})",
            ino, size
        );
        reply.error(libc::ENOSYS);
    }

    fn removexattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] removexattr(ino: {:#x?}, name: {:?})",
            ino, name
        );
        reply.error(libc::ENOSYS);
    }
}
