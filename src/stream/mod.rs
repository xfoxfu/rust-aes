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
    fn new(iv: Block<M>, key: GenericArray<u8, Prod<M::NkWords, typenum::U4>>) -> Self
    where
        Self: Sized,
        M::NkWords: generic_array::ArrayLength<u8>,
        M::NkWords: generic_array::ArrayLength<u32>,
        M::NkWords: std::ops::Mul<typenum::U4>,
        Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
    {
        Self::new_with_ext_key(
            iv,
            crate::aes::KeyExpander::<M>::key_expansion(
                &crate::aes::KeyExpander::<M>::convert_key(&key),
            ),
        )
    }
    fn new_with_ext_key(iv: Block<M>, key: GenericArray<u32, Prod<M::NrKey, M::NbWords>>) -> Self;

    fn stream_encrypt_iter(&mut self, data: &Block<M>) -> Block<M>;
    fn stream_decrypt_iter(&mut self, data: &Block<M>) -> Block<M>;

    fn stream_encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        use typenum::Unsigned;
        let data = P::pad_eat(data.to_owned(), M::NbWords::to_usize() * 4);
        let mut result = Vec::new();
        for bid in (0..data.len()).step_by(M::NbWords::to_usize() * 4) {
            let bout = self.stream_encrypt_iter(GenericArray::from_slice(
                &data[bid..(bid + M::NbWords::to_usize() * 4)],
            ));
            result = [result, bout.to_vec()].concat();
        }
        result
    }
    fn stream_decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        use typenum::Unsigned;
        let mut result = Vec::new();
        for bid in (0..data.len()).step_by(M::NbWords::to_usize() * 4) {
            let bout = self.stream_decrypt_iter(GenericArray::from_slice(
                &data[bid..(bid + M::NbWords::to_usize() * 4)],
            ));
            result = [result, bout.to_vec()].concat();
        }
        P::unpad_eat(result, M::NbWords::to_usize() * 4)
    }
}

mod ecb;
pub use ecb::ElectronicCodeBook;
mod cbc;
pub use cbc::CipherBlockChaining;
