pub(crate) mod block_file;
pub(crate) mod stream_file;
pub(crate) mod traits;

use aead::{OsRng, rand_core::RngCore};
use std::{
    collections::BTreeSet,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::FileExt},
    rc::Rc,
};

use anyhow::{Context, Result, bail};
use thiserror::Error;
use tracing::{debug, error, instrument};

use crate::BLOCK_SIZE;
use traits::{BlockHandler, DigestHandler, DigestKey};

pub(crate) type Iv = [u8; 12];
type AuthTag = [u8; 16];
type Block = [u8; 4096];

const METADATA_BLOCK_COUNT: u64 = 146;
const BLOCKS_PER_DIGEST: u64 = 28;
const DIGEST_SIZE: usize = 32;

pub type Key = [u8; 32];
pub type Blake2 = blake2::Blake2b<::digest::consts::U32>;
pub type Sha3 = sha3::Sha3_256;
pub type Aes256Gcm = aes_gcm::Aes256Gcm;
pub type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;

/// Helper Trait to constrain the possible File layouts
pub trait Encoder {}
impl Encoder for BlockOriented {}
impl Encoder for StreamOriented {}

/// Helper Trait to constrain the possible Ciphers
pub trait Cipher: aead::AeadInPlace + aead::KeySizeUser + crypto_common::KeyInit {}
impl Cipher for Aes256Gcm {}
impl Cipher for ChaCha20Poly1305 {}

/// Helper Trait to constrain the possible Digests
pub trait Digest: ::digest::Digest {}
impl Digest for Blake2 {}
impl Digest for Sha3 {}

#[derive(Debug)]
pub struct BlockOriented;
#[derive(Debug)]
pub struct StreamOriented;

/// Reads the logical file size
///
/// The size is located at the first 8 bytes of a valid file
pub fn read_size(path: &str) -> Result<u64, IoError> {
    let mut file = std::fs::OpenOptions::new().read(true).open(path)?;
    let mut size = [0u8; 8];
    file.read_exact(&mut size)?;

    let size = u64::from_le_bytes(size);
    Ok(size)
}

/// Generatess cryptographically secure 12 bytes
pub(crate) fn generate_12b_iv() -> [u8; 12] {
    let mut buf = [0u8; 12];
    OsRng.fill_bytes(&mut buf);
    buf
}

impl<C, D, E> std::fmt::Debug for CryptoFile<C, D, E>
where
    C: Cipher,
    D: Digest,
    E: Encoder,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoFile")
            .field("file", &self.file)
            .field("key", &self.key)
            .field("size", &self.size)
            .field("cache", &self.cache)
            .field("pos", &self.pos)
            .field("marker", &self.phantom_encoder)
            .field("_marker", &self.phantom_digest)
            .finish()
    }
}

/// Contains block IV and auth tags for the current file position
#[derive(Debug)]
pub(crate) struct FileCache {
    pub block_idx: u64,
    pub block: Block,
    /// Indicator if `block` was written to
    pub dirty: bool,
    /// Indicator if metadata block was written to
    pub md_dirty: bool,
    /// Contains `BlockMetadata` for the metadat block that the current `block_idx` is part of
    pub blocks: Vec<BlockMetadata>,
    /// Tracks digest indices which were already checked
    pub checked_digests: BTreeSet<u64>,
    /// Tracks digests which need to be recomputed on close
    pub dirty_digests: BTreeSet<u64>,
}

impl FileCache {
    pub fn new() -> Self {
        Self {
            block_idx: 0,
            block: [0u8; BLOCK_SIZE as usize],
            dirty: false,
            md_dirty: false,
            blocks: vec![],
            checked_digests: BTreeSet::new(),
            dirty_digests: BTreeSet::new(),
        }
    }

    /// Marks current block as written to
    fn mark_dirty(&mut self) {
        debug!("marking dirty block_idx={}", self.block_idx);
        self.dirty = true;
        self.md_dirty = true;

        self.dirty_digests
            .insert(self.block_idx / BLOCKS_PER_DIGEST);
        debug!(
            "inserting into dirty_digests digest_idx={}",
            self.block_idx % BLOCKS_PER_DIGEST
        );
    }

    /// Gets current `block.idx` metadata block index
    fn get_block_md(&mut self) -> &mut BlockMetadata {
        self.blocks
            .get_mut((self.block_idx % METADATA_BLOCK_COUNT) as usize)
            .expect("Metadata block exists")
    }

    #[instrument(skip_all)]
    /// Converts `blocks`containing `MetadataBlock`s into binary representation
    fn to_block(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(BLOCK_SIZE as usize);

        for x in &self.blocks {
            buf.extend_from_slice(&x.iv[..]);
            buf.extend_from_slice(&x.auth_tag[..]);
            debug!(target: "checksum_contents", "writing iv={:?} auth_tag={:?}", x.iv, x.auth_tag);
        }
        buf
    }
}

/// Contains specific block metadata, that is, its initialization vector and authentication tag
#[derive(Debug, Clone)]
pub(crate) struct BlockMetadata {
    pub iv: Iv,
    pub auth_tag: AuthTag,
}

/// Struct managing the encryption and decryption of data.
/// It transparently reads and writes when needed, and caches blocks
/// at the granularity of `BLOCK_SIZE=4096`, The caching is handled using
/// the `FileCache` struct.
pub struct CryptoFile<C, D, E>
where
    C: Cipher,
    D: Digest,
    E: Encoder,
{
    file: std::fs::File,
    digest_file: Option<std::fs::File>,
    cipher: C,
    key: crypto_common::Key<C>,
    digest_key: DigestKey,
    pub size: u64,
    size_at_open: u64,
    cache: FileCache,
    pos: u64,
    written: bool,
    phantom_encoder: std::marker::PhantomData<E>,
    phantom_digest: std::marker::PhantomData<D>,
}

impl<C, D, E> CryptoFile<C, D, E>
where
    C: Cipher,
    D: Digest,
    E: Encoder,
{
    /// Write logical file size, initial IV, master key into the header block
    #[instrument(skip_all)]
    fn prepare(file: &mut std::fs::File, master_key: &Rc<crypto_common::Key<C>>) -> Result<()> {
        let iv = generate_12b_iv();

        let key = C::generate_key(aead::OsRng);
        let size = 0u64;
        file.write_all(&size.to_le_bytes())?; // 8B
        file.write_all(&iv)?; // 12B
        file.seek(SeekFrom::Start(20))?;

        let cipher = C::new(master_key);

        let mut buf: Vec<u8> = Vec::with_capacity(4084);

        buf.extend(&key[..]); // 32B
        buf.extend([0u8; 4076 - 32 - 16]); // 4076 - 32 - 16 (for auth_tag)

        cipher.encrypt_in_place(iv[..].into(), &[], &mut buf)?;

        assert_eq!(buf.len(), 4076, "ciphertext size == 4076");

        file.write_all(&buf)
            .context("failed writing initial file config")?;
        let _ = file.rewind();
        Ok(())
    }

    /// Deciphers the file and loads the first header block into memory
    #[instrument(skip_all)]
    pub fn open(
        mut file: std::fs::File,
        digest_file: Option<std::fs::File>,
        master_key: Rc<crypto_common::Key<C>>,
        init: bool,
    ) -> Result<Self> {
        if init {
            Self::prepare(&mut file, &master_key).context("failed initializing CryptoFile")?;
        }

        let mut buf = [0u8; BLOCK_SIZE as usize];

        file.read_exact(&mut buf)?;

        let (sz, rest) = buf.split_at_mut(8);
        let (iv, rest) = rest.split_at_mut(12);
        let (data, auth_tag) = rest.split_at_mut(4060);
        let master_cipher = C::new(&*master_key);

        master_cipher
            .decrypt_in_place_detached(iv[..].into(), &[], data, auth_tag[..].into())
            .context("failed decrypting file during open")?;

        let (key, _rest) = data.split_at(32);

        let key: [u8; 32] = key.try_into()?;
        let cipher = C::new(data[..32].into());

        let size = u64::from_le_bytes(sz.try_into().map_err(|_| CryptoError::BadSize)?);

        debug!("serialized: size = {:?}, deserialized size = {}", sz, size);

        Ok(Self {
            file,
            digest_file,
            cipher,
            key: crypto_common::Key::<C>::clone_from_slice(data[..32].into()),
            digest_key: key,
            size,
            size_at_open: size,
            cache: FileCache::new(),
            pos: 0,
            written: false,
            phantom_encoder: std::marker::PhantomData,
            phantom_digest: std::marker::PhantomData,
        })
    }

    /// Check if `self.pos` points to the last block
    pub fn is_last_block(&self) -> bool {
        self.pos / BLOCK_SIZE == self.size / BLOCK_SIZE
    }

    /// Writes header block to file
    ///
    /// HEADER BLOCK:
    /// - 8B logical file size
    /// - 12B IV
    /// - encrypted:
    /// - 20-52B 32B file key
    /// - 52-4080B empty
    /// - 4080-4096B 16B auth tag
    pub fn write_header_block(&mut self) -> Result<()> {
        if self.written {
            debug!("writing: logical file size = {}", self.size);
            self.file
                .write_all_at(&self.size.to_le_bytes(), 0)
                .context("failed writing logical file size")?;
        }
        Ok(())
    }

    /// Handles the digests, loads the digest corresponding to the `data_block_idx`, computes
    /// digest correspondig to the `data_block_idx` and compares them
    #[instrument(skip(self))]
    fn handle_digest(&mut self, data_block_idx: u64) -> Result<()>
    where
        Self: DigestHandler<D>,
    {
        // Do not check digest if it's turned off
        if self.digest_file.is_none() {
            return Ok(());
        }

        let x = self.size_at_open / BLOCK_SIZE / BLOCKS_PER_DIGEST;
        let digest_idx = data_block_idx / BLOCKS_PER_DIGEST;
        // only if the file is not empty
        if digest_idx <= x && !self.cache.checked_digests.contains(&digest_idx) {
            let to = if digest_idx == x {
                (self.size_at_open.div_ceil(BLOCK_SIZE)) % BLOCKS_PER_DIGEST
            } else {
                BLOCKS_PER_DIGEST
            };

            debug!("to={}", to);
            if to > 0 {
                let new_digest =
                    Self::compute_digest_range(digest_idx, to, &mut self.file, &self.digest_key)?;

                if !self.check_digest_at(digest_idx, &new_digest)? {
                    error!(
                        "digest of blocks {}..{} does not match with the saved digest at idx={}",
                        data_block_idx,
                        data_block_idx + to,
                        digest_idx
                    );

                    bail!(CryptoError::DigestMismatch(data_block_idx, to));
                }
                self.cache.checked_digests.insert(digest_idx);
            }
        }
        Ok(())
    }

    pub fn set_permissions(&self, perm: std::fs::Permissions) -> Result<(), std::io::Error> {
        self.file.set_permissions(perm.clone())?;
        if let Some(df) = &self.digest_file {
            df.set_permissions(perm)?;
        }
        Ok(())
    }

    pub fn chown(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), std::io::Error> {
        std::os::unix::fs::fchown(&self.file, uid, gid)?;
        if let Some(df) = &self.digest_file {
            std::os::unix::fs::fchown(df, uid, gid)?;
        }
        Ok(())
    }

    pub fn sync_data(&mut self) -> Result<(), std::io::Error>
    where
        Self: DigestHandler<D>,
    {
        self.flush()?;
        self.file.sync_data()?;
        if let Some(df) = &self.digest_file {
            df.sync_data()?;
        }
        Ok(())
    }

    pub fn sync_all(&mut self) -> Result<(), std::io::Error>
    where
        Self: DigestHandler<D>,
    {
        self.file.sync_all()?;
        if let Some(df) = &self.digest_file {
            df.sync_all()?;
        }
        Ok(())
    }

    pub fn set_times(&self, times: std::fs::FileTimes) -> Result<(), std::io::Error> {
        self.file.set_times(times)?;
        if let Some(df) = &self.digest_file {
            df.set_times(times)?;
        }
        Ok(())
    }

    pub fn truncate(&mut self, size: u64) -> Result<(), IoError>
    where
        Self: DigestHandler<D>,
    {
        self.size = size;
        self.pos = size;
        self.update_cache().map_err(IoError::other)?;

        let len = Self::pos_to_filepos_ceil(size);
        nix::fcntl::fallocate(
            self.file.as_raw_fd(),
            nix::fcntl::FallocateFlags::empty(),
            0,
            len as i64,
        )?;

        if let Some(digest_file) = &self.digest_file {
            let digest_count = size / BLOCK_SIZE / BLOCKS_PER_DIGEST + 1;
            let digest_size = digest_count * DIGEST_SIZE as u64;
            nix::fcntl::fallocate(
                digest_file.as_raw_fd(),
                nix::fcntl::FallocateFlags::empty(),
                0,
                digest_size as i64,
            )?;
        }

        let x = (size % BLOCK_SIZE) as usize;
        if x != 0 {
            self.cache.block[x..].fill(0);
        }
        self.cache.mark_dirty();

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    AeadError(aead::Error),
    #[error("file contains ill-formed IV counter")]
    BadIvCounter,
    #[error("file contains ill-formed size")]
    BadSize,
    #[error("failed to deserialize block IV")]
    BadBlockIV,
    #[error("failed to deserialize block auth tag")]
    BadBlockAuthTag,
    #[error("file size is not a multiple of {BLOCK_SIZE}")]
    BadFileSize,
    #[error("digest from blocks {0} to {1} does not match")]
    DigestMismatch(u64, u64),
}

impl From<aead::Error> for CryptoError {
    fn from(value: aead::Error) -> Self {
        Self::AeadError(value)
    }
}

impl<C, D, E> Seek for CryptoFile<C, D, E>
where
    C: Cipher,
    D: Digest,
    E: Encoder,
{
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        debug!("seeking file to {:?}", pos);
        // FIXME: remove the casts
        let x = match pos {
            std::io::SeekFrom::Start(x) => Ok(x),
            std::io::SeekFrom::End(x) => (self.size as i64 - x).try_into(),
            std::io::SeekFrom::Current(x) => (self.pos as i64 + x).try_into(),
        };
        let Ok(x) = x else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Negative seek",
            ));
        };

        self.pos = x;
        Ok(self.pos)
    }
}

impl<C, D, E> Read for CryptoFile<C, D, E>
where
    C: Cipher,
    D: Digest,
    E: Encoder,
    Self: DigestHandler<D>,
{
    #[instrument(skip_all, fields(pos = self.pos, size = self.size))]
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        debug!("buf.len() = {}", buf.len());
        //debug!("buf= {:?}", buf);
        let mut bytes_read = 0;

        while bytes_read < buf.len() && self.pos < self.size {
            debug!("bytes_read = {}", bytes_read);
            let data_block_idx = self.pos / BLOCK_SIZE;

            if self.cache.block_idx != data_block_idx
                || (self.cache.block_idx == 0 && data_block_idx == 0 && self.pos == 0)
            {
                self.update_cache()
                    .map_err(|e| IoError::new(IoErrorKind::InvalidData, e))?;
            }

            let idx = (self.pos % BLOCK_SIZE) as usize;
            let to = if self.is_last_block() {
                self.size % BLOCK_SIZE
            } else {
                BLOCK_SIZE
            } as usize;

            debug!("reading cache block from {}..{}", idx, to);
            match buf.write(&self.cache.block[idx..to]) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    self.pos += n as u64;
                    debug!("incrementing self pos by {}, final value = {}", n, self.pos);
                    bytes_read += n
                }
                Err(e) => return Err(e),
            };
        }

        debug!("read {} bytes", bytes_read);
        Ok(bytes_read)
    }
}

impl<C, D, E> Write for CryptoFile<C, D, E>
where
    C: Cipher,
    D: Digest,
    E: Encoder,
    Self: DigestHandler<D>,
{
    #[instrument(skip_all, fields(pos = self.pos, size = self.size, buf_len = buf.len()))]
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        self.written = true;
        let mut bytes_written: usize = 0;
        let required_space = self.pos + (buf.len() as u64) - bytes_written as u64;
        let required_phys_space = Self::pos_to_filepos_ceil(required_space);

        let phys_size = self.file.metadata()?.len();
        if required_phys_space > phys_size {
            let required_space = 2 * required_space;
            let len = Self::pos_to_filepos_ceil(required_space);
            debug!(
                "data_file: required logical size = {}, physical file resizing to = {}",
                required_space, len
            );
            nix::fcntl::fallocate(
                self.file.as_raw_fd(),
                nix::fcntl::FallocateFlags::empty(),
                0,
                len as i64,
            )?;

            if let Some(digest_file) = &self.digest_file {
                let digest_count = required_space / BLOCK_SIZE / BLOCKS_PER_DIGEST + 1;
                let digest_size = digest_count * DIGEST_SIZE as u64;
                debug!(
                    "digest_file: required size for {} digests, physical file resizing to = {}",
                    digest_count, digest_size
                );
                nix::fcntl::fallocate(
                    digest_file.as_raw_fd(),
                    nix::fcntl::FallocateFlags::empty(),
                    0,
                    digest_size as i64,
                )?;
            }
        }
        if required_space > self.size {
            self.size = required_space;
        }

        debug!("bytes_written: {}", bytes_written);
        debug!("buf.len(): {}", buf.len());
        while bytes_written < buf.len() && self.pos < self.size {
            let data_block_idx = self.pos / BLOCK_SIZE;

            if self.cache.block_idx != data_block_idx
                || (self.cache.block_idx == 0 && data_block_idx == 0)
            {
                self.update_cache()
                    .map_err(|e| IoError::new(IoErrorKind::InvalidData, e))?;
            }

            let idx = (self.pos % BLOCK_SIZE) as usize;
            let to = if self.is_last_block() {
                self.size % BLOCK_SIZE
            } else {
                BLOCK_SIZE
            } as usize;

            debug!("writing {}..{}", idx, to);
            match (&mut self.cache.block[idx..to]).write(buf) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    self.cache.mark_dirty();
                    buf = &buf[n..];
                    self.pos += n as u64;
                    bytes_written += n;
                }
                Err(e) if e.kind() == IoErrorKind::WriteZero => return Ok(0),
                Err(e) => {
                    error!("{:?}", e);

                    return Err(e);
                }
            };
        }

        Ok(bytes_written)
    }

    #[instrument(skip_all)]
    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_impl()
            .map_err(|e| IoError::new(IoErrorKind::InvalidData, e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod enc_write {
        use crate::crypto;
        type BlockFile =
            crypto::CryptoFile<crypto::Aes256Gcm, crypto::Blake2, crypto::BlockOriented>;
        type StreamFile =
            crypto::CryptoFile<crypto::Aes256Gcm, crypto::Blake2, crypto::StreamOriented>;
        use aes_gcm::Aes256Gcm as Cipher;
        //use chacha20poly1305::ChaCha20Poly1305 as Cipher;

        macro_rules! test_enc_write {
            ($filename:ident, $outdir:expr_2021) => {
                #[test]
                #[serial]
                fn $filename() -> Result<()> {
                    let mut f = std::fs::OpenOptions::new()
                        .read(true)
                        .open(&(TEST_ROOT.to_owned() + stringify!($filename)))?;

                    let k = [0u8; 32];
                    let key: crypto_common::Key<Cipher> = k.into();
                    let key = Rc::from(key);

                    let mut buf = vec![];
                    f.read_to_end(&mut buf)?;

                    tracing::debug!("reading enc_file");

                    let path = TEST_ROOT.to_owned()
                        + "/"
                        + $outdir
                        + "/test_enc_write_"
                        + stringify!($filename);
                    let path_digest = path.clone() + ".dg";
                    {
                        let mut enc_f = File::open(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(&path)?,
                            Some(
                                std::fs::OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(true)
                                    .truncate(true)
                                    .open(&path_digest)?,
                            ),
                            key.clone(),
                            true,
                        )
                        .context("failed opening encrypted file")?;

                        enc_f.write_all(&buf)?;

                        enc_f.flush()?;
                    }

                    let mut enc_f = File::open(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)?,
                        Some(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .open(&path_digest)?,
                        ),
                        key.clone(),
                        false,
                    )
                    .context("failed creating encrypted file")?;

                    let mut buf2 = vec![];
                    enc_f.read_to_end(&mut buf2)?;

                    assert_eq!(buf.len(), buf2.len(), "buffer lengths do not match");
                    assert_eq!(buf, buf2, "buffer contents do not match");

                    std::fs::remove_file(path)?;
                    std::fs::remove_file(path_digest)?;
                    Ok(())
                }
            };
        }

        mod block {
            use std::{
                io::{Read, Write},
                rc::Rc,
            };

            const TEST_ROOT: &str = "./tests/";
            const TEST_OUTPUT: &str = "./tests/block/";

            use anyhow::{Context, Result};
            use rand::{Rng, distr::Uniform};
            use serial_test::serial;

            use super::{BlockFile as File, Cipher};

            test_enc_write!(file_4_kb, "block");
            test_enc_write!(file_16_kb, "block");
            test_enc_write!(file_4095_b, "block");
            test_enc_write!(file_4097_b, "block");
            test_enc_write!(file_1_gb, "block");

            #[test]
            fn file_range_0_1_m() -> Result<()> {
                let range = Uniform::try_from(0..255)?;

                for i in (521000..1000000).step_by(2048) {
                    tracing::debug!("testing file with {} bytes...", i);
                    let buf: Vec<u8> = rand::rng().sample_iter(&range).take(i).collect();

                    let k = [0u8; 32];
                    let key: crypto_common::Key<Cipher> = k.into();
                    let key = Rc::from(key);

                    tracing::debug!("reading enc_file");

                    let path = TEST_OUTPUT.to_owned() + "test_enc_write_0_1M";
                    let path_digest = path.clone() + ".dg";
                    {
                        let mut enc_f = File::open(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(&path)?,
                            Some(
                                std::fs::OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(true)
                                    .truncate(true)
                                    .open(&path_digest)?,
                            ),
                            key.clone(),
                            true,
                        )?;

                        enc_f.write_all(&buf)?;

                        enc_f.flush()?;
                    }

                    let mut enc_f = File::open(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)?,
                        Some(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .open(&path_digest)?,
                        ),
                        key.clone(),
                        false,
                    )
                    .context("failed creating encrypted file")?;

                    let mut buf2 = vec![];
                    enc_f.read_to_end(&mut buf2)?;

                    assert_eq!(buf.len(), buf2.len(), "buffer lengths do not match");
                    assert_eq!(buf, buf2, "buffer contents do not match");

                    std::fs::remove_file(path)?;
                    std::fs::remove_file(path_digest)?;
                    tracing::debug!("done.");
                }
                Ok(())
            }
        }
        mod stream {
            use std::{
                io::{Read, Write},
                rc::Rc,
            };

            const TEST_ROOT: &str = "./tests/";
            const TEST_OUTPUT: &str = "./tests/stream/";

            use anyhow::{Context, Result};
            use rand::{Rng, distr::Uniform};
            use serial_test::serial;

            use super::{Cipher, StreamFile as File};

            test_enc_write!(file_4_kb, "stream");
            test_enc_write!(file_16_kb, "stream");
            test_enc_write!(file_4095_b, "stream");
            test_enc_write!(file_4097_b, "stream");
            test_enc_write!(file_1_gb, "stream");

            #[test]
            fn file_range_0_1_m() -> Result<()> {
                let range = Uniform::try_from(0..255)?;

                for i in (521000..1000000).step_by(2048) {
                    tracing::debug!("testing file with {} bytes...", i);
                    let buf: Vec<u8> = rand::rng().sample_iter(&range).take(i).collect();

                    let k = [0u8; 32];
                    let key: crypto_common::Key<Cipher> = k.into();
                    let key = Rc::from(key);

                    tracing::debug!("reading enc_file");

                    let path = TEST_OUTPUT.to_owned() + "test_enc_write_0_1M";
                    let path_digest = path.clone() + ".dg";
                    {
                        let mut enc_f = File::open(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(&path)?,
                            Some(
                                std::fs::OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .create(true)
                                    .truncate(true)
                                    .open(&path_digest)?,
                            ),
                            key.clone(),
                            true,
                        )?;

                        enc_f.write_all(&buf)?;

                        enc_f.flush()?;
                    }

                    let mut enc_f = File::open(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)?,
                        Some(
                            std::fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .open(&path_digest)?,
                        ),
                        key.clone(),
                        false,
                    )?;

                    let mut buf2 = vec![];
                    enc_f.read_to_end(&mut buf2)?;

                    assert_eq!(buf.len(), buf2.len(), "buffer lengths do not match");
                    assert_eq!(buf, buf2, "buffer contents do not match");

                    std::fs::remove_file(path)?;
                    std::fs::remove_file(path_digest)?;
                    tracing::debug!("done.");
                }
                Ok(())
            }
        }
    }
}
