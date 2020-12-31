use super::{Block, Streamer};
use crate::{
    aes::{bytes_to_word_arr, RijndaelCryptor, RijndaelMode},
    padding::Padding,
};
use generic_array::GenericArray;
use std::marker::PhantomData;

pub struct CipherBlockChaining<M: RijndaelMode, P: Padding>
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
    acc: Block<M>,
    _p: PhantomData<P>,
}

impl<M: RijndaelMode, P: Padding> Streamer<M, P> for CipherBlockChaining<M, P>
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
        iv: super::Block<M>,
        key: GenericArray<u32, typenum::Prod<M::NrKey, M::NbWords>>,
    ) -> Self
    where
        typenum::Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
    {
        Self {
            key,
            acc: iv,
            _p: PhantomData::default(),
        }
    }

    fn stream_encrypt_iter(&mut self, data: &super::Block<M>) -> super::Block<M> {
        for i in 0..data.len() {
            self.acc[i] ^= data[i];
        }
        let res =
            RijndaelCryptor::<M>::new_with_raw_data_key(&self.acc, &self.key).encrypt_to_arr();
        self.acc = res.clone();
        res
    }

    fn stream_decrypt_iter(&mut self, data: &super::Block<M>) -> super::Block<M> {
        let mut res = RijndaelCryptor::<M>::new_with_raw_data_key(data.as_slice(), &self.key)
            .decrypt_to_arr();
        for i in 0..data.len() {
            res[i] ^= self.acc[i];
        }
        self.acc = data.clone();
        res
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
    let mut cipher = CipherBlockChaining::<crate::aes::AES128, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()),
        GenericArray::clone_from_slice(&hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap()),
    );
    impl_test_block_en!(cipher : "6bc1bee22e409f96e93d7e117393172a" => "7649abac8119b246cee98e9b12e9197d");
    impl_test_block_en!(cipher : "ae2d8a571e03ac9c9eb76fac45af8e51" => "5086cb9b507219ee95db113a917678b2");
    impl_test_block_en!(cipher : "30c81c46a35ce411e5fbc1191a0a52ef" => "73bed6b8e3c1743b7116e69e22229516");
    impl_test_block_en!(cipher : "f69f2445df4f9b17ad2b417be66c3710" => "3ff1caa1681fac09120eca307586e1a7");

    let mut cipher = CipherBlockChaining::<crate::aes::AES128, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()),
        GenericArray::clone_from_slice(&hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap()),
    );
    impl_test_block_de!(cipher : "7649abac8119b246cee98e9b12e9197d" => "6bc1bee22e409f96e93d7e117393172a");
    impl_test_block_de!(cipher : "5086cb9b507219ee95db113a917678b2" => "ae2d8a571e03ac9c9eb76fac45af8e51");
    impl_test_block_de!(cipher : "73bed6b8e3c1743b7116e69e22229516" => "30c81c46a35ce411e5fbc1191a0a52ef");
    impl_test_block_de!(cipher : "3ff1caa1681fac09120eca307586e1a7" => "f69f2445df4f9b17ad2b417be66c3710");

    let mut cipher = CipherBlockChaining::<crate::aes::AES192, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()),
        GenericArray::clone_from_slice(
            &hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        ),
    );
    impl_test_block_en!(cipher : "6bc1bee22e409f96e93d7e117393172a" => "4f021db243bc633d7178183a9fa071e8");
    impl_test_block_en!(cipher : "ae2d8a571e03ac9c9eb76fac45af8e51" => "b4d9ada9ad7dedf4e5e738763f69145a");
    impl_test_block_en!(cipher : "30c81c46a35ce411e5fbc1191a0a52ef" => "571b242012fb7ae07fa9baac3df102e0");
    impl_test_block_en!(cipher : "f69f2445df4f9b17ad2b417be66c3710" => "08b0e27988598881d920a9e64f5615cd");

    let mut cipher = CipherBlockChaining::<crate::aes::AES192, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()),
        GenericArray::clone_from_slice(
            &hex::decode("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap(),
        ),
    );
    impl_test_block_de!(cipher : "4f021db243bc633d7178183a9fa071e8" => "6bc1bee22e409f96e93d7e117393172a");
    impl_test_block_de!(cipher : "b4d9ada9ad7dedf4e5e738763f69145a" => "ae2d8a571e03ac9c9eb76fac45af8e51");
    impl_test_block_de!(cipher : "571b242012fb7ae07fa9baac3df102e0" => "30c81c46a35ce411e5fbc1191a0a52ef");
    impl_test_block_de!(cipher : "08b0e27988598881d920a9e64f5615cd" => "f69f2445df4f9b17ad2b417be66c3710");

    let mut cipher = CipherBlockChaining::<crate::aes::AES256, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()),
        GenericArray::clone_from_slice(
            &hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .unwrap(),
        ),
    );
    impl_test_block_en!(cipher : "6bc1bee22e409f96e93d7e117393172a" => "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    impl_test_block_en!(cipher : "ae2d8a571e03ac9c9eb76fac45af8e51" => "9cfc4e967edb808d679f777bc6702c7d");
    impl_test_block_en!(cipher : "30c81c46a35ce411e5fbc1191a0a52ef" => "39f23369a9d9bacfa530e26304231461");
    impl_test_block_en!(cipher : "f69f2445df4f9b17ad2b417be66c3710" => "b2eb05e2c39be9fcda6c19078c6a9d1b");

    let mut cipher = CipherBlockChaining::<crate::aes::AES256, crate::padding::PKCS7>::new(
        GenericArray::clone_from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()),
        GenericArray::clone_from_slice(
            &hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .unwrap(),
        ),
    );
    impl_test_block_de!(cipher : "f58c4c04d6e5f1ba779eabfb5f7bfbd6" => "6bc1bee22e409f96e93d7e117393172a");
    impl_test_block_de!(cipher : "9cfc4e967edb808d679f777bc6702c7d" => "ae2d8a571e03ac9c9eb76fac45af8e51");
    impl_test_block_de!(cipher : "39f23369a9d9bacfa530e26304231461" => "30c81c46a35ce411e5fbc1191a0a52ef");
    impl_test_block_de!(cipher : "b2eb05e2c39be9fcda6c19078c6a9d1b" => "f69f2445df4f9b17ad2b417be66c3710");
}
