use std::ops::Deref;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType};

pub struct Metadata(pub std::fs::Metadata);

impl Metadata {
    pub fn from(value: std::fs::Metadata) -> Self {
        Self(value)
    }

    pub fn filetype(&self) -> FileType {
        let ft = self.file_type();
        if ft.is_file() {
            FileType::RegularFile
        } else if ft.is_dir() {
            FileType::Directory
        } else if ft.is_symlink() {
            FileType::Symlink
        } else if ft.is_block_device() {
            FileType::BlockDevice
        } else if ft.is_char_device() {
            FileType::CharDevice
        } else if ft.is_socket() {
            FileType::Socket
        } else if ft.is_fifo() {
            FileType::NamedPipe
        } else {
            unreachable!("missing filetype")
        }
    }
}

impl From<Metadata> for FileAttr {
    fn from(value: Metadata) -> Self {
        let cr = match value.created() {
            Ok(time) => time,
            Err(_) => SystemTime::UNIX_EPOCH + Duration::new(0, 0),
        };
        Self {
            ino: value.st_ino(),
            size: value.st_size(),
            blocks: value.st_blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.st_atime() as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.st_mtime() as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(value.st_ctime() as u64),
            crtime: cr,
            kind: value.filetype(),
            perm: value.permissions().mode() as u16,
            nlink: value.st_nlink() as u32,
            uid: value.st_uid(),
            gid: value.st_gid(),
            rdev: value.st_rdev() as u32,
            blksize: value.st_blksize() as u32,
            flags: 0,
        }
    }
}

impl Deref for Metadata {
    type Target = std::fs::Metadata;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Metadata {
    fn _st_dev(&self) -> u64 {
        self.0.st_dev()
    }

    fn st_ino(&self) -> u64 {
        self.0.st_dev()
    }

    fn _st_mode(&self) -> u32 {
        self.0.st_mode()
    }

    fn st_nlink(&self) -> u64 {
        self.0.st_nlink()
    }

    fn st_uid(&self) -> u32 {
        self.0.st_uid()
    }

    fn st_gid(&self) -> u32 {
        self.0.st_gid()
    }

    fn st_rdev(&self) -> u64 {
        self.0.st_rdev()
    }

    fn st_size(&self) -> u64 {
        self.0.st_size()
    }

    fn st_atime(&self) -> i64 {
        self.0.st_atime()
    }

    fn _st_atime_nsec(&self) -> i64 {
        self.0.st_atime_nsec()
    }

    fn st_mtime(&self) -> i64 {
        self.0.st_mtime()
    }

    fn _st_mtime_nsec(&self) -> i64 {
        self.0.st_mtime_nsec()
    }

    fn st_ctime(&self) -> i64 {
        self.0.st_ctime()
    }

    fn _st_ctime_nsec(&self) -> i64 {
        self.0.st_ctime_nsec()
    }

    fn st_blksize(&self) -> u64 {
        self.0.st_blksize()
    }

    fn st_blocks(&self) -> u64 {
        self.0.st_blocks()
    }
    //fn is_block_device(&self) -> bool {
    //    self.0.is_block_device()
    //
    //}
    //fn is_char_device(&self) -> bool{
    //    self.0.is_char_device()
    //
    //}
    //fn is_fifo(&self) -> bool{
    //    self.0.is_fifo()
    //}
    //fn is_socket(&self) -> bool{
    //    self.0.is_socket()
    //
    //}
}
