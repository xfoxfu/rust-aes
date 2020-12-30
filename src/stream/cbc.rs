use super::{Block, Streamer};
use crate::aes::{RijndaelCryptor, RijndaelMode};
use crate::padding::Padding;
use generic_array::GenericArray;
use std::marker::PhantomData;

pub struct CipherBlockChaining<M: RijndaelMode>
where
    M::NbWords: std::ops::Mul<typenum::U4>,
    typenum::Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    M::NrKey: std::ops::Mul<M::NbWords>,
    typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
    M::NbWords: std::ops::Mul<typenum::U4>,
    typenum::Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    nalgebra::DefaultAllocator:
        nalgebra::allocator::Allocator<u8, nalgebra::U4, <M::NbWords as nalgebra::NamedDim>::Name>,
    M::NrKey: generic_array::ArrayLength<crate::aes::State<M>>,
    M::NbWords: generic_array::ArrayLength<u32>,
    M::NkWords: std::ops::Mul<typenum::U4>,
    typenum::Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
    M::NkWords: generic_array::ArrayLength<u32>,
{
    key: GenericArray<u32, typenum::Prod<M::NrKey, M::NbWords>>,
    acc: Block<M>,
}

impl<M: RijndaelMode, P: Padding> Streamer<M, P> for CipherBlockChaining<M>
where
    M::NbWords: std::ops::Mul<typenum::U4>,
    typenum::Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    M::NrKey: std::ops::Mul<M::NbWords>,
    typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
    M::NbWords: std::ops::Mul<typenum::U4>,
    typenum::Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    nalgebra::DefaultAllocator:
        nalgebra::allocator::Allocator<u8, nalgebra::U4, <M::NbWords as nalgebra::NamedDim>::Name>,
    M::NrKey: generic_array::ArrayLength<crate::aes::State<M>>,
    M::NbWords: generic_array::ArrayLength<u32>,
    M::NkWords: std::ops::Mul<typenum::U4>,
    typenum::Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
    M::NkWords: generic_array::ArrayLength<u32>,
{
    fn new_with_ext_key(
        iv: super::Block<M>,
        key: GenericArray<u32, typenum::Prod<M::NrKey, M::NbWords>>,
    ) -> Self
    where
        typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
    {
        Self { key, acc: iv }
    }

    fn stream_encrypt_iter(&mut self, data: &super::Block<M>) -> super::Block<M> {
        for i in 0..data.len() {
            self.acc[i] ^= data[i];
        }
        let res = RijndaelCryptor::<M>::new_with_raw_data_key(data.as_slice(), &self.key)
            .encrypt_to_arr();
        self.acc = res.clone();
        res
    }

    fn stream_decrypt_iter(&mut self, data: &super::Block<M>) -> super::Block<M> {
        self.acc = data.clone();
        let mut res = RijndaelCryptor::<M>::new_with_raw_data_key(data.as_slice(), &self.key)
            .decrypt_to_arr();
        for i in 0..data.len() {
            res[i] ^= data[i];
        }
        res
    }
}
