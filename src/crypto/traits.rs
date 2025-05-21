use std::os::unix::fs::FileExt;

use anyhow::{Context, Result};
use tracing::{debug, instrument};

use crate::BLOCK_SIZE;
use crate::IoError;

use crate::crypto::{BLOCKS_PER_DIGEST, DIGEST_SIZE};

pub type Digest = [u8; DIGEST_SIZE];
pub type DigestKey = [u8; DIGEST_SIZE];

pub trait BlockHandler {
    /// Converts from logical position to underlying file position aligned to nearest block such
    /// that data of size `pos` fits
    fn pos_to_filepos_ceil(pos: u64) -> u64;

    /// Converts `block index` to the underlying file position
    fn block_index_to_file_pos(index: u64) -> u64;

    /// Loads block at position `pos` from the beginning of the file
    fn load_block_at(
        file: &mut std::fs::File,
        pos: u64,
    ) -> Result<[u8; BLOCK_SIZE as usize], IoError> {
        let mut buf = [0u8; BLOCK_SIZE as usize];

        file.read_exact_at(&mut buf, pos)?;

        Ok(buf)
    }

    // TODO: handle block loading across metadata blocks

    ///// Loads `count` blocks at position `offset` from the beginning of the file
    //#[instrument(skip_all)]
    //fn load_bulk_blocks_at(
    //    file: &mut std::fs::File,
    //    count: usize,
    //    offset: u64,
    //) -> Result<Vec<u8>, IoError> {
    //    //let offset = index * DIGEST_SIZE as u64;
    //    //let x = count * DIGEST_SIZE;
    //
    //    let mut buf = vec![0u8; count * BLOCK_SIZE as usize];
    //
    //    file.read_exact_at(&mut buf, offset)?;
    //
    //    Ok(buf)
    //}

    /// Encrypts and writes a data block at `pos` from the beginning of file
    fn write_block_at(&mut self, pos: u64) -> Result<()>;

    /// Returns the encrypted data file descriptor
    fn data_file(&mut self) -> &mut std::fs::File;

    /// Updates `CryptoFile` cache, that is, if the cached block was written to, encrypts the
    /// contents, writes them, and then loads a new data block and decrypts it.
    fn update_cache(&mut self) -> Result<()>;

    /// Flushes the underlying file descriptors
    fn flush_impl(&mut self) -> Result<()>;
}

/// The digest check happens only during first read of the corresponding data block
/// We assume that modifications to the file happen only at rest
pub trait DigestHandler<D>: BlockHandler
where
    D: crate::crypto::Digest,
{
    /// Returns the digest file descriptor
    fn digest_file(&mut self) -> &mut std::fs::File;

    /// Loads `count` digests starting at `index` from the digest file
    #[instrument(skip(self))]
    fn load_bulk_digests_at(&mut self, count: usize, index: u64) -> Result<Vec<Digest>> {
        let offset = index * DIGEST_SIZE as u64;
        let x = count * DIGEST_SIZE;

        let mut buf = vec![0u8; x];
        debug!("reading {} digests at {}", count, offset);
        self.digest_file()
            .read_exact_at(&mut buf, offset)
            .context("failed to read {} digests")?;

        let out = buf
            .chunks_exact(DIGEST_SIZE)
            .map(|x| x.try_into())
            .collect::<Result<Vec<Digest>, _>>()?;

        Ok(out)
    }

    /// Loads a digest at `index` from the hash file
    fn load_digest_at(&mut self, index: u64) -> Result<Digest> {
        Ok(*self
            .load_bulk_digests_at(1, index)?
            .first()
            .expect("contains at least one digest"))
    }

    /// Checks if Digest of blocks starting at `index` matches with the `other` Digest
    fn check_digest_at(&mut self, index: u64, other: &Digest) -> Result<bool> {
        let dig = self
            .load_digest_at(index)
            .context("failed loading digest")?;
        Ok(dig == *other)
    }

    /// Writes `digest` Digest at `index`
    fn write_digest_at(digest: Digest, index: u64, digest_file: &mut std::fs::File) -> Result<()> {
        let offset = index * DIGEST_SIZE as u64;

        digest_file.write_all_at(&digest, offset)?;

        Ok(())
    }

    /// Computes digest made out of `to` blocks, starting at the `index`th block
    #[instrument(skip_all)]
    fn compute_digest_range(
        index: u64,
        to: u64,
        data_file: &mut std::fs::File,
        digest_key: &Digest,
    ) -> Result<Digest> {
        let start_idx = BLOCKS_PER_DIGEST * index;
        debug!(
            "computing digest of blocks {}..{}",
            start_idx,
            start_idx + to
        );

        let mut hasher = D::new();
        // keyed hashing to prevent anyone from recomputing them since digests are stored in plaintext
        hasher.update(digest_key);
        // add block index to the digest to prevent permutations of digests and data blocks
        hasher.update(index.to_le_bytes());

        for i in 0..to {
            let phys_pos = Self::block_index_to_file_pos(start_idx + i);
            let buf = Self::load_block_at(data_file, phys_pos);
            let buf = match buf {
                Ok(buf) => buf,
                Err(e) => Err(e).with_context(|| {
                    format!("failed to create digest of blocks starting at {}", index)
                })?,
            };
            hasher.update(buf);
        }

        Ok(hasher.finalize()[..].try_into()?)
    }
}
