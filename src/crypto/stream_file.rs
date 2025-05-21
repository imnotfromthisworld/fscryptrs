use std::{
    io::{ErrorKind as IoErrorKind, Read, Seek, SeekFrom},
    os::unix::fs::FileExt,
};

use anyhow::{Result, bail};

use tracing::{debug, instrument};

use crate::BLOCK_SIZE;
use crate::crypto::*;

use crate::crypto::traits::{BlockHandler, DigestHandler};

pub const IV_AUTHTAG_SIZE: u64 = 28;

impl<C, D> BlockHandler for CryptoFile<C, D, StreamOriented>
where
    C: Cipher,
    D: Digest,
{
    fn pos_to_filepos_ceil(pos: u64) -> u64 {
        let data_block_count = pos.div_ceil(BLOCK_SIZE);
        // header block + data blocks + ivs and auth tags
        BLOCK_SIZE                              // header block
        + data_block_count * ( IV_AUTHTAG_SIZE + BLOCK_SIZE ) // block iv and auth tag and data 
    }

    fn block_index_to_file_pos(index: u64) -> u64 {
        let data_block_count = index;
        // header block + data blocks + metadata blocks
        BLOCK_SIZE                              // header block
        + data_block_count * BLOCK_SIZE
        + data_block_count * IV_AUTHTAG_SIZE
    }

    #[instrument(skip_all)]
    fn write_block_at(&mut self, pos: u64) -> Result<()> {
        let new_iv = generate_12b_iv();

        let mut out = Vec::with_capacity(4124);

        out.extend_from_slice(&new_iv);

        let x = self
            .cipher
            .encrypt_in_place_detached(new_iv[..].into(), &[], &mut self.cache.block)
            .with_context(|| format!("failed encrypting block at pos {}", pos))?;

        debug!("new iv={:?}, auth_tag={:?}", new_iv, x);
        debug!(
            "write cached block with idx={} physical_pos={}",
            self.cache.block_idx, pos
        );

        self.file.write_all_at(&new_iv, pos)?;
        self.file.write_all_at(&self.cache.block, pos + 12)?;
        self.file.write_all_at(&x, pos + 12 + BLOCK_SIZE)?;
        self.cache.dirty = false;
        Ok(())
    }

    fn data_file(&mut self) -> &mut std::fs::File {
        &mut self.file
    }

    #[instrument(skip_all, fields(pos = self.pos))]
    fn update_cache(&mut self) -> Result<()> {
        let data_block_idx = self.pos / BLOCK_SIZE;

        //let max_cache_size = BLOCK_SIZE * 256;

        // dirty indicates if the current cached block was written to
        // generates new unique IV for the block and writes to disk
        if self.cache.dirty {
            let pos = Self::block_index_to_file_pos(self.cache.block_idx);
            self.write_block_at(pos)?;
        }

        self.handle_digest(data_block_idx)
            .context("failed digest checking")?;

        let file_pos = Self::block_index_to_file_pos(self.pos / BLOCK_SIZE);

        self.file.seek(SeekFrom::Start(file_pos))?;
        debug!("read at physical_pos={}", file_pos);

        let mut buf: [u8; (BLOCK_SIZE + IV_AUTHTAG_SIZE) as usize] =
            [0u8; (BLOCK_SIZE + IV_AUTHTAG_SIZE) as usize];

        match self.file.read_exact(&mut buf) {
            Ok(_) => (),
            Err(e) if e.kind() == IoErrorKind::UnexpectedEof => (),
            Err(e) if e.kind() == IoErrorKind::WriteZero => (),
            Err(e) => bail!(e),
        };

        let (iv, rest) = buf.split_at_mut(12);
        let (data, auth_tag) = rest.split_at_mut(BLOCK_SIZE as usize);

        debug!("using iv and auth_tag of block {}", data_block_idx);
        debug!("iv={:?}, auth_tag={:?}", iv, auth_tag);

        if data != [0u8; BLOCK_SIZE as usize] {
            self.cipher
                .decrypt_in_place_detached(iv[..].into(), &[], data, auth_tag[..].into())?;
        }

        self.cache.block = data[..]
            .try_into()
            .expect("data should be multiple of 4096");
        self.cache.block_idx = data_block_idx;

        Ok(())
    }

    fn flush_impl(&mut self) -> Result<()> {
        if self.written {
            if self.cache.dirty {
                let pos = Self::block_index_to_file_pos(self.cache.block_idx);
                self.write_block_at(pos)?;
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

impl<C, D> DigestHandler<D> for CryptoFile<C, D, StreamOriented>
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

#[cfg(test)]
mod tests {
    mod stream_file {
        use crate::crypto::{
            Blake2, ChaCha20Poly1305, CryptoFile, StreamOriented, traits::BlockHandler,
        };

        #[test]
        fn test_filepos_ceil() {
            assert_eq!(
                CryptoFile::<ChaCha20Poly1305, Blake2, StreamOriented>::pos_to_filepos_ceil(2048),
                8220
            );
        }
    }
}
