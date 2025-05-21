use std::{
    io::{ErrorKind as IoErrorKind, Read, Seek, SeekFrom},
    os::unix::fs::FileExt,
};

use anyhow::{Result, bail};

use tracing::debug;

use tracing::instrument;

use crate::BLOCK_SIZE;
use crate::crypto::traits::{BlockHandler, DigestHandler};
use crate::crypto::*;

/// METADATA BLOCK:
/// 124x: 16B IV
///       16B auth tag
/// 4x 32B blake3 checksum for 31 data blocks
impl<C, D> CryptoFile<C, D, BlockOriented>
where
    C: Cipher,
    D: Digest,
{
    /// Updates the cache with metadata block depending on `self.pos`
    #[instrument(skip_all, fields(file_pos = self.pos, file_size = self.size))]
    fn update_metadata_cache(&mut self) -> Result<()> {
        if self.cache.md_dirty {
            self.write_metadata_block()
                .context("failed writing metadata block")?;
        }

        let mut blocks = Vec::new();
        let curr_md_block_idx = self.pos / (BLOCK_SIZE * METADATA_BLOCK_COUNT);
        let mut buf = [0u8; BLOCK_SIZE as usize];

        // get underlying file position to read the metadata block
        let idx = BLOCK_SIZE + curr_md_block_idx * (METADATA_BLOCK_COUNT + 1) * BLOCK_SIZE;
        self.file.seek(SeekFrom::Start(idx))?;

        // TODO: error handling
        //  file should always be a multiple of 4096B
        self.file.read_exact(&mut buf)?;

        // deserialize block IV and auth tags
        for i in 0..METADATA_BLOCK_COUNT as usize {
            let curr = i * 28;
            let iv = buf[curr..curr + 12]
                .try_into()
                .map_err(|_| CryptoError::BadBlockIV)?;
            let auth_tag = buf[curr + 12..curr + 28]
                .try_into()
                .map_err(|_| CryptoError::BadBlockAuthTag)?;
            let block = BlockMetadata { iv, auth_tag };
            debug!(target: "checksum_contents",
                "deserialized block: {:?}", block);
            blocks.push(block);
        }

        self.cache.dirty = false;
        self.cache.md_dirty = false;
        self.cache.blocks = blocks;

        Ok(())
    }

    #[instrument(skip_all)]
    fn load_block(file: &mut std::fs::File) -> Result<[u8; BLOCK_SIZE as usize]> {
        let mut buf = [0u8; BLOCK_SIZE as usize];

        file.read_exact(&mut buf)?;

        Ok(buf)
    }

    #[instrument(skip_all)]
    fn write_metadata_block(&mut self) -> Result<()> {
        let p = self.cache.block_idx / METADATA_BLOCK_COUNT;
        let x = BLOCK_SIZE + (METADATA_BLOCK_COUNT + 1) * p * BLOCK_SIZE;
        debug!("writing metadata block at physical_pos={}", x);
        self.file.write_at(&self.cache.to_block(), x)?;

        Ok(())
    }
}

impl<C, D> BlockHandler for CryptoFile<C, D, BlockOriented>
where
    C: Cipher,
    D: Digest,
{
    fn pos_to_filepos_ceil(pos: u64) -> u64 {
        let at_most = pos.div_ceil(BLOCK_SIZE);
        let data_block_count = pos / BLOCK_SIZE;
        let metadata_block_count = data_block_count / METADATA_BLOCK_COUNT + 1;
        // header block + data blocks + metadata blocks
        BLOCK_SIZE                              // header block
        + metadata_block_count * BLOCK_SIZE     // metadata blocks
        + at_most*BLOCK_SIZE // data blocks
    }

    fn block_index_to_file_pos(block_idx: u64) -> u64 {
        let data_block_count = block_idx;
        let metadata_block_count = data_block_count / METADATA_BLOCK_COUNT + 1;
        // header block + data blocks + metadata blocks
        BLOCK_SIZE + metadata_block_count * BLOCK_SIZE + data_block_count * BLOCK_SIZE
    }

    #[instrument(skip_all)]
    fn write_block_at(&mut self, pos: u64) -> Result<()> {
        let new_iv = generate_12b_iv();

        let x = self
            .cipher
            .encrypt_in_place_detached(new_iv[..].into(), &[], &mut self.cache.block)
            .with_context(|| format!("failed encrypting block at pos {}", pos))?;

        let BlockMetadata { iv, auth_tag } = self.cache.get_block_md();

        iv.copy_from_slice(&new_iv[..]);
        auth_tag.copy_from_slice(&x);

        debug!("new iv={:?}, auth_tag={:?}", iv, auth_tag);
        debug!(
            "write cached block with idx={} physical_pos={}",
            self.cache.block_idx, pos
        );

        self.file.write_all_at(&self.cache.block, pos)?;
        self.cache.dirty = false;
        Ok(())
    }

    fn data_file(&mut self) -> &mut std::fs::File {
        &mut self.file
    }

    #[instrument(skip_all, fields(pos = self.pos))]
    fn update_cache(&mut self) -> Result<()> {
        let data_block_idx = self.pos / BLOCK_SIZE;

        // dirty indicates if the current cached block was written to
        // generates new unique IV for the block and writes to disk
        if self.cache.dirty {
            let pos = Self::block_index_to_file_pos(self.cache.block_idx);
            self.write_block_at(pos)
                .context("failed writing cached block")?;
        }

        let md_block_idx_old = self.cache.block_idx / METADATA_BLOCK_COUNT;
        let md_block_idx_new = data_block_idx / METADATA_BLOCK_COUNT;

        // if file pos is 0 create/load new metadata block
        if md_block_idx_old != md_block_idx_new || self.cache.blocks.is_empty() {
            self.update_metadata_cache()?;
        }

        // check digest
        self.handle_digest(data_block_idx)
            .context("failed digest checking")?;

        let file_pos = Self::block_index_to_file_pos(self.pos / BLOCK_SIZE);
        self.file.seek(SeekFrom::Start(file_pos))?;
        debug!("read at physical_pos={}", file_pos);

        let BlockMetadata { iv, auth_tag } = self
            .cache
            .blocks
            .get((data_block_idx % METADATA_BLOCK_COUNT) as usize)
            .context("block metadata index exists")?;
        debug!(
            "using iv and auth_tag of block {}, pos in md block {}",
            data_block_idx,
            data_block_idx % METADATA_BLOCK_COUNT
        );
        debug!("iv={:?}, auth_tag={:?}", iv, auth_tag);

        let mut buf: [u8; BLOCK_SIZE as usize] = [0u8; BLOCK_SIZE as usize];

        match self.file.read_exact(&mut buf) {
            Ok(_) => (),
            Err(e) if e.kind() == IoErrorKind::UnexpectedEof => (),
            Err(e) => bail!(e),
        };

        // FIXME: don't decrypt if it's empty block??
        if buf != [0u8; BLOCK_SIZE as usize] {
            self.cipher.decrypt_in_place_detached(
                iv[..].into(),
                &[],
                &mut buf,
                auth_tag[..].into(),
            )?;
        }

        self.cache.block = buf;
        self.cache.block_idx = data_block_idx;

        Ok(())
    }

    fn flush_impl(&mut self) -> Result<()> {
        if self.written {
            if self.cache.dirty {
                let pos = Self::block_index_to_file_pos(self.cache.block_idx);
                self.write_block_at(pos)
                    .context("failed writing cached block")?;
            }
            if self.cache.md_dirty {
                self.write_metadata_block()
                    .context("failed writing metadata block")?;
            }
            self.write_header_block()?;
            self.written = false;
        }

        if self.digest_file.is_some() {
            for idx in self.cache.dirty_digests.iter() {
                let to = if *idx == self.size / BLOCK_SIZE / BLOCKS_PER_DIGEST {
                    (self.size.div_ceil(BLOCK_SIZE)) % BLOCKS_PER_DIGEST
                } else {
                    BLOCKS_PER_DIGEST
                };

                let new_digest =
                    Self::compute_digest_range(*idx, to, &mut self.file, &self.digest_key)?;

                Self::write_digest_at(
                    new_digest,
                    *idx,
                    self.digest_file.as_mut().expect("digest file exists"),
                )?;
            }
        }

        Ok(())
    }
}

impl<C, D> DigestHandler<D> for CryptoFile<C, D, BlockOriented>
where
    C: Cipher,
    D: Digest,
{
    fn digest_file(&mut self) -> &mut std::fs::File {
        self.digest_file
            .as_mut()
            .expect("digest file existence checked before")
    }
}
