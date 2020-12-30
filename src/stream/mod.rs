use crate::{aes::RijndaelMode, padding::Padding};
use generic_array::GenericArray;
use typenum::Prod;

type Block<M> = GenericArray<u8, Prod<<M as RijndaelMode>::NbWords, typenum::U4>>;

pub trait Streamer<M: RijndaelMode, P: Padding>
where
    M::NbWords: std::ops::Mul<typenum::U4>,
    Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    M::NrKey: std::ops::Mul<M::NbWords>,
    Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
{
    fn new(iv: Block<M>, key: GenericArray<u32, M::NkWords>) -> Self
    where
        Self: Sized,
        M::NkWords: generic_array::ArrayLength<u32>,
    {
        Self::new_with_ext_key(iv, crate::aes::KeyExpander::<M>::key_expansion(&key))
    }
    fn new_with_ext_key(iv: Block<M>, key: GenericArray<u32, Prod<M::NrKey, M::NbWords>>) -> Self;

    fn stream_encrypt_iter(&mut self, data: &Block<M>) -> Block<M>;
    fn stream_decrypt_iter(&mut self, data: &Block<M>) -> Block<M>;

    fn stream_encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        todo!()
    }
    fn stream_decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        todo!()
    }
}

mod ecb;
pub use ecb::ElectronicCodeBook;
mod cbc;
pub use cbc::CipherBlockChaining;
