use std::convert::TryInto;

use crate::{aes::RijndaelMode, padding::Padding};

type Block<M: RijndaelMode> = [u8; <M as RijndaelMode>::NB_WORDS * 4];
type KeyBlock<M: RijndaelMode> = [u8; <M as RijndaelMode>::NK_WORDS * 4];

pub trait Streamer<M: RijndaelMode, P: Padding>
where
    [(); <M as RijndaelMode>::NB_WORDS * 4]:,
    [(); M::NR_KEY * M::NB_WORDS]:,
    [(); M::NK_WORDS]:,
    [(); M::NK_WORDS * 4]:
{
    fn new(iv: Block<M>, key: KeyBlock<M>) -> Self
    where
        Self: Sized,
    {
        Self::new_with_ext_key(
            iv,
            crate::aes::KeyExpander::<M>::key_expansion(
                &crate::aes::KeyExpander::<M>::convert_key(&key),
            ),
        )
    }
    fn new_with_ext_key(iv: Block<M>, key: [u32; M::NR_KEY * M::NB_WORDS]) -> Self;

    fn stream_encrypt_iter(&mut self, data: &Block<M>) -> Block<M>;
    fn stream_decrypt_iter(&mut self, data: &Block<M>) -> Block<M>;

    fn stream_encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let data = P::pad_eat(data.to_owned(), M::NB_WORDS * 4);
        let mut result = Vec::new();
        for bid in (0..data.len()).step_by(M::NB_WORDS * 4) {
            let bout = self.stream_encrypt_iter(
                &data[bid..(bid + M::NB_WORDS * 4)].try_into().unwrap(),
            );
            result = [result, bout.to_vec()].concat();
        }
        result
    }
    fn stream_decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        for bid in (0..data.len()).step_by(M::NB_WORDS * 4) {
            let bout = self.stream_decrypt_iter(
                &data[bid..(bid + M::NB_WORDS * 4)].try_into().unwrap(),
            );
            result = [result, bout.to_vec()].concat();
        }
        P::unpad_eat(result, M::NB_WORDS * 4)
    }
}

mod ecb;
pub use ecb::ElectronicCodeBook;
mod cbc;
pub use cbc::CipherBlockChaining;
