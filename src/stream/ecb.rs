use super::Streamer;
use crate::{
    aes::{bytes_to_word_arr, RijndaelCryptor, RijndaelMode},
    padding::Padding,
};
use generic_array::GenericArray;
use std::marker::PhantomData;

pub struct ElectronicCodeBook<M: RijndaelMode, P: Padding>
where
    M::NbWords: generic_array::ArrayLength<u32>,
    M::NbWords: std::ops::Mul<typenum::U4>,
    M::NkWords: generic_array::ArrayLength<u32>,
    M::NkWords: std::ops::Mul<typenum::U4>,
    M::NrKey: generic_array::ArrayLength<crate::aes::State<M>>,
    M::NrKey: std::ops::Mul<M::NbWords>,
    nalgebra::DefaultAllocator:
        nalgebra::allocator::Allocator<u8, nalgebra::U4, <M::NbWords as nalgebra::NamedDim>::Name>,
    typenum::Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    typenum::Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
    typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
{
    key: GenericArray<u32, typenum::Prod<M::NrKey, M::NbWords>>,
    _m: PhantomData<M>,
    _p: PhantomData<P>,
}

impl<M: RijndaelMode, P: Padding> Streamer<M, P> for ElectronicCodeBook<M, P>
where
    M::NbWords: generic_array::ArrayLength<u32>,
    M::NbWords: std::ops::Mul<typenum::U4>,
    M::NkWords: generic_array::ArrayLength<u32>,
    M::NkWords: std::ops::Mul<typenum::U4>,
    M::NrKey: generic_array::ArrayLength<crate::aes::State<M>>,
    M::NrKey: std::ops::Mul<M::NbWords>,
    nalgebra::DefaultAllocator:
        nalgebra::allocator::Allocator<u8, nalgebra::U4, <M::NbWords as nalgebra::NamedDim>::Name>,
    typenum::Prod<M::NbWords, typenum::U4>: generic_array::ArrayLength<u8>,
    typenum::Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
    typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
{
    fn new_with_ext_key(
        _: super::Block<M>,
        key: GenericArray<u32, typenum::Prod<M::NrKey, M::NbWords>>,
    ) -> Self
    where
        typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
    {
        Self {
            key,
            _m: PhantomData::default(),
            _p: PhantomData::default(),
        }
    }

    fn stream_encrypt_iter(&mut self, data: &super::Block<M>) -> super::Block<M> {
        RijndaelCryptor::<M>::new_with_raw_data_key(data.as_slice(), &self.key).encrypt_to_arr()
    }

    fn stream_decrypt_iter(&mut self, data: &super::Block<M>) -> super::Block<M> {
        RijndaelCryptor::<M>::new_with_raw_data_key(data.as_slice(), &self.key).decrypt_to_arr()
    }
}

#[cfg(test)]
macro_rules! impl_test_block_en {
    ($cipher: ident : $in: literal => $out: literal) => {
        assert_eq!(
            hex::encode(
                $cipher.stream_encrypt_iter(&GenericArray::clone_from_slice(
                    &hex::decode($in).unwrap()
                ))
            ),
            $out
        );
    };
}
#[cfg(test)]
macro_rules! impl_test_block_de {
    ($cipher: ident : $in: literal => $out: literal) => {
        assert_eq!(
            hex::encode(
                $cipher.stream_decrypt_iter(&GenericArray::clone_from_slice(
                    &hex::decode($in).unwrap()
                ))
            ),
            $out
        );
    };
}

#[cfg(test)]
#[test]
pub fn test() {
    // The following test cases are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let mut cipher = ElectronicCodeBook::<crate::aes::AES128, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("00000000000000000000000000000000").unwrap()),
        GenericArray::clone_from_slice(&[0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]),
    );
    impl_test_block_en!(cipher : "6bc1bee22e409f96e93d7e117393172a" => "3ad77bb40d7a3660a89ecaf32466ef97");
    impl_test_block_en!(cipher : "ae2d8a571e03ac9c9eb76fac45af8e51" => "f5d3d58503b9699de785895a96fdbaaf");
    impl_test_block_en!(cipher : "30c81c46a35ce411e5fbc1191a0a52ef" => "43b1cd7f598ece23881b00e3ed030688");
    impl_test_block_en!(cipher : "f69f2445df4f9b17ad2b417be66c3710" => "7b0c785e27e8ad3f8223207104725dd4");

    let mut cipher = ElectronicCodeBook::<crate::aes::AES128, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("00000000000000000000000000000000").unwrap()),
        GenericArray::clone_from_slice(&[0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c]),
    );
    impl_test_block_de!(cipher : "3ad77bb40d7a3660a89ecaf32466ef97" => "6bc1bee22e409f96e93d7e117393172a");
    impl_test_block_de!(cipher : "f5d3d58503b9699de785895a96fdbaaf" => "ae2d8a571e03ac9c9eb76fac45af8e51");
    impl_test_block_de!(cipher : "43b1cd7f598ece23881b00e3ed030688" => "30c81c46a35ce411e5fbc1191a0a52ef");
    impl_test_block_de!(cipher : "7b0c785e27e8ad3f8223207104725dd4" => "f69f2445df4f9b17ad2b417be66c3710");

    let mut cipher = ElectronicCodeBook::<crate::aes::AES192, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("00000000000000000000000000000000").unwrap()),
        GenericArray::clone_from_slice(&[
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
        ]),
    );
    impl_test_block_en!(cipher : "6bc1bee22e409f96e93d7e117393172a" => "bd334f1d6e45f25ff712a214571fa5cc");
    impl_test_block_en!(cipher : "ae2d8a571e03ac9c9eb76fac45af8e51" => "974104846d0ad3ad7734ecb3ecee4eef");
    impl_test_block_en!(cipher : "30c81c46a35ce411e5fbc1191a0a52ef" => "ef7afd2270e2e60adce0ba2face6444e");
    impl_test_block_en!(cipher : "f69f2445df4f9b17ad2b417be66c3710" => "9a4b41ba738d6c72fb16691603c18e0e");

    let mut cipher = ElectronicCodeBook::<crate::aes::AES192, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("00000000000000000000000000000000").unwrap()),
        GenericArray::clone_from_slice(&[
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
        ]),
    );
    impl_test_block_de!(cipher : "bd334f1d6e45f25ff712a214571fa5cc" => "6bc1bee22e409f96e93d7e117393172a");
    impl_test_block_de!(cipher : "974104846d0ad3ad7734ecb3ecee4eef" => "ae2d8a571e03ac9c9eb76fac45af8e51");
    impl_test_block_de!(cipher : "ef7afd2270e2e60adce0ba2face6444e" => "30c81c46a35ce411e5fbc1191a0a52ef");
    impl_test_block_de!(cipher : "9a4b41ba738d6c72fb16691603c18e0e" => "f69f2445df4f9b17ad2b417be66c3710");

    let mut cipher = ElectronicCodeBook::<crate::aes::AES256, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("00000000000000000000000000000000").unwrap()),
        GenericArray::clone_from_slice(&[
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4,
        ]),
    );
    impl_test_block_en!(cipher : "6bc1bee22e409f96e93d7e117393172a" => "f3eed1bdb5d2a03c064b5a7e3db181f8");
    impl_test_block_en!(cipher : "ae2d8a571e03ac9c9eb76fac45af8e51" => "591ccb10d410ed26dc5ba74a31362870");
    impl_test_block_en!(cipher : "30c81c46a35ce411e5fbc1191a0a52ef" => "b6ed21b99ca6f4f9f153e7b1beafed1d");
    impl_test_block_en!(cipher : "f69f2445df4f9b17ad2b417be66c3710" => "23304b7a39f9f3ff067d8d8f9e24ecc7");

    let mut cipher = ElectronicCodeBook::<crate::aes::AES256, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("00000000000000000000000000000000").unwrap()),
        GenericArray::clone_from_slice(&[
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4,
        ]),
    );
    impl_test_block_de!(cipher : "f3eed1bdb5d2a03c064b5a7e3db181f8" => "6bc1bee22e409f96e93d7e117393172a");
    impl_test_block_de!(cipher : "591ccb10d410ed26dc5ba74a31362870" => "ae2d8a571e03ac9c9eb76fac45af8e51");
    impl_test_block_de!(cipher : "b6ed21b99ca6f4f9f153e7b1beafed1d" => "30c81c46a35ce411e5fbc1191a0a52ef");
    impl_test_block_de!(cipher : "23304b7a39f9f3ff067d8d8f9e24ecc7" => "f69f2445df4f9b17ad2b417be66c3710");
}
