use super::encrypt::{galois_mul, State};
use super::{
    consts::sbox_get,
    converter::{byte_to_word, word_to_bytes},
    key_expansion::KeyExpander,
    matrix_to_words, words_to_matrix, RijndaelMode,
};
use generic_array::{ArrayLength, GenericArray};
use nalgebra::{allocator::Allocator, DefaultAllocator, NamedDim, U4};
use std::ops::Mul;
use typenum::{Prod, Unsigned};

pub struct RijndaelDecryptor<M: RijndaelMode>
where
    M::NrKey: ArrayLength<State<M>>,
    DefaultAllocator: Allocator<u8, U4, <M::NbWords as NamedDim>::Name>,
{
    state: State<M>,
    keys: GenericArray<State<M>, M::NrKey>,
}

impl<M: RijndaelMode> RijndaelDecryptor<M>
where
    M::NrKey: ArrayLength<State<M>>,
    DefaultAllocator: Allocator<u8, U4, <M::NbWords as NamedDim>::Name>,
{
    pub fn new(
        input: &GenericArray<u32, M::NbWords>,
        key: &GenericArray<u32, Prod<M::NrKey, M::NbWords>>,
    ) -> Self
    where
        M::NbWords: ArrayLength<u32>,
        M::NrKey: Mul<M::NbWords>,
        Prod<M::NrKey, M::NbWords>: ArrayLength<u32>,
    {
        let state = words_to_matrix::<M>(input);
        let keys = GenericArray::from_exact_iter((0..key.len()).step_by(4).map(|i| {
            words_to_matrix::<M>(GenericArray::from_slice(&[
                key[i],
                key[i + 1],
                key[i + 2],
                key[i + 3],
            ]))
        }))
        .unwrap();
        Self { state, keys }
    }

    pub fn new_from_arr(input: &[u8], key: &[u8]) -> Self
    where
        M::NkWords: ArrayLength<u32>,
        M::NkWords: Mul<typenum::U4>,
        Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
        M::NbWords: ArrayLength<u32>,
        M::NrKey: Mul<M::NbWords>,
        Prod<M::NrKey, M::NbWords>: ArrayLength<u32>,
    {
        assert_eq!(input.len(), M::NbWords::to_usize() * 4);
        assert_eq!(key.len(), M::NkWords::to_usize() * 4);
        let mut input_arr = GenericArray::default();
        let mut key_arr = GenericArray::<u32, M::NbWords>::default();
        for i in 0..M::NbWords::to_usize() {
            input_arr[i] = byte_to_word(&[
                input[i * 4],
                input[i * 4 + 1],
                input[i * 4 + 2],
                input[i * 4 + 3],
            ]);
        }
        for i in 0..M::NbWords::to_usize() {
            key_arr[i] =
                byte_to_word(&[key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        let key_arr = KeyExpander::<M>::key_expansion(&KeyExpander::<M>::convert_key(
            GenericArray::from_slice(&key),
        ));
        Self::new(&input_arr, &key_arr)
    }

    #[cfg(test)]
    pub fn _test_get_state(&self) -> &State<M> {
        &self.state
    }

    pub fn add_round_key(&mut self, key_idx: usize) {
        let key = &self.keys[key_idx];
        for (i, mut row) in self.state.row_iter_mut().enumerate() {
            for (j, cell) in row.iter_mut().enumerate() {
                *cell ^= key[(i, j)];
            }
        }
    }

    pub fn sub_bytes(&mut self) {
        for mut row in self.state.row_iter_mut() {
            for cell in row.iter_mut() {
                *cell = sbox_get(*cell);
            }
        }
    }

    pub fn shift_row(&mut self, row_id: usize, count: usize) {
        let row_len = self.state.row(row_id).len();
        for _ in 0..count {
            for i in 0..(row_len - 1) {
                self.state.swap((row_id, i), (row_id, (i + 1) % row_len));
            }
        }
    }

    pub fn shift_rows(&mut self) {
        for i in 0..4 {
            self.shift_row(i, i);
        }
    }

    pub fn mix_column(&mut self, c: usize) {
        use galois_mul as gm;
        let s0 = self.state[(0, c)];
        let s1 = self.state[(1, c)];
        let s2 = self.state[(2, c)];
        let s3 = self.state[(3, c)];
        self.state[(0, c)] = gm(0x02, s0) ^ gm(0x03, s1) ^ s2 ^ s3;
        self.state[(1, c)] = s0 ^ gm(0x02, s1) ^ gm(0x03, s2) ^ s3;
        self.state[(2, c)] = s0 ^ s1 ^ gm(0x02, s2) ^ gm(0x03, s3);
        self.state[(3, c)] = gm(0x03, s0) ^ s1 ^ s2 ^ gm(0x02, s3);
    }

    pub fn mix_columns(&mut self) {
        for col in 0..self.state.column_iter().len() {
            self.mix_column(col);
        }
    }

    pub fn decrypt(mut self) -> GenericArray<u32, M::NbWords>
    where
        M::NbWords: ArrayLength<u32>,
    {
        self.add_round_key(0);

        for i in 0..M::Nr::to_usize() {
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(i + 1);
        }

        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(M::Nr::to_usize() + 1);

        matrix_to_words::<M>(&self.state)
    }

    pub fn decrypt_to_arr(self) -> GenericArray<u8, Prod<M::NbWords, typenum::U4>>
    where
        M::NbWords: ArrayLength<u32>,
        M::NbWords: std::ops::Mul<typenum::U4>,
        Prod<M::NbWords, typenum::U4>: ArrayLength<u8>,
    {
        let res = self.decrypt();
        let mut ret = GenericArray::default();
        for i in 0..res.len() {
            let (r0, r1, r2, r3) = word_to_bytes(res[i]);
            ret[i * 4] = r0;
            ret[i * 4 + 1] = r1;
            ret[i * 4 + 2] = r2;
            ret[i * 4 + 3] = r3;
        }
        ret
    }
}

macro_rules! _make_test {
    ($mode:ty, $key:literal, $val:literal, $enc:literal) => {
        let plain = hex::decode($val).unwrap();
        let key = hex::decode($key).unwrap();
        let decryptor = RijndaelDecryptor::<$mode>::new_from_arr(&plain, &key);
        let ciphertext = decryptor.decrypt_to_arr();
        assert_eq!(hex::encode(ciphertext), $enc);
    };
}

#[cfg(test)]
#[test]
pub fn test_rijndael_decrypt_iter() {
    let plain = hex::decode("f34481ec3cc627bacd5dc3fbdb135345").unwrap();
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let mut decryptor = RijndaelDecryptor::<super::AES128>::new_from_arr(&plain, &key);
    decryptor.add_round_key(0);
    assert_eq!(
        decryptor._test_get_state(),
        &State::<super::AES128>::from_column_slice(&[
            0xf3, 0x44, 0x81, 0xec, //
            0x3c, 0xc6, 0x27, 0xba, //
            0xcd, 0x5d, 0xc3, 0xfb, //
            0xdb, 0x13, 0x53, 0x45, //
        ])
    );
    decryptor.shift_rows();
    assert_eq!(
        decryptor._test_get_state(),
        &State::<super::AES128>::from_row_slice(&[
            0xf3, 0x3c, 0xcd, 0xdb, //
            0xc6, 0x5d, 0x13, 0x44, //
            0xc3, 0x53, 0x81, 0x27, //
            0x45, 0xec, 0xba, 0xfb, //
        ])
    );
    decryptor.sub_bytes();
    assert_eq!(
        decryptor._test_get_state(),
        &State::<super::AES128>::from_row_slice(&[
            0x0d, 0xeb, 0xbd, 0xb9, //
            0xb4, 0x4c, 0x7d, 0x1b, //
            0x2e, 0xed, 0x0c, 0xcc, //
            0x6e, 0xce, 0xf4, 0x0f, //
        ])
    );
    decryptor.mix_columns();
    assert_eq!(
        decryptor._test_get_state(),
        &State::<super::AES128>::from_row_slice(&[
            0x9d, 0x3a, 0x1e, 0x87, //
            0x62, 0x91, 0xa7, 0xcf, //
            0x57, 0x2f, 0xdf, 0x30, //
            0x51, 0x00, 0x5e, 0x19, //
        ])
    );
}

#[rustfmt::skip]
#[cfg(test)]
#[test]
pub fn test_rijndael_decrypt_enc() {
    _make_test!(super::AES128, "00000000000000000000000000000000", "f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e");
    _make_test!(super::AES128, "00000000000000000000000000000000", "9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589");
    _make_test!(super::AES128, "00000000000000000000000000000000", "96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597");
    _make_test!(super::AES128, "00000000000000000000000000000000", "6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209");
    _make_test!(super::AES128, "00000000000000000000000000000000", "cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce");
    _make_test!(super::AES128, "00000000000000000000000000000000", "b26aeb1874e47ca8358ff22378f09144", "459264f4798f6a78bacb89c15ed3d601");
    _make_test!(super::AES128, "00000000000000000000000000000000", "58c8e00b2631686d54eab84b91f0aca1", "08a4e2efec8a8e3312ca7460b9040bbf");
    _make_test!(super::AES192, "000000000000000000000000000000000000000000000000", "1b077a6af4b7f98229de786d7516b639", "275cfc0413d8ccb70513c3859b1d0f72");
    _make_test!(super::AES192, "000000000000000000000000000000000000000000000000", "9c2d8842e5f48f57648205d39a239af1", "c9b8135ff1b5adc413dfd053b21bd96d");
    _make_test!(super::AES192, "000000000000000000000000000000000000000000000000", "bff52510095f518ecca60af4205444bb", "4a3650c3371ce2eb35e389a171427440");
    _make_test!(super::AES192, "000000000000000000000000000000000000000000000000", "51719783d3185a535bd75adc65071ce1", "4f354592ff7c8847d2d0870ca9481b7c");
    _make_test!(super::AES192, "000000000000000000000000000000000000000000000000", "26aa49dcfe7629a8901a69a9914e6dfd", "d5e08bf9a182e857cf40b3a36ee248cc");
    _make_test!(super::AES192, "000000000000000000000000000000000000000000000000", "941a4773058224e1ef66d10e0a6ee782", "067cd9d3749207791841562507fa9626");
    _make_test!(super::AES256, "0000000000000000000000000000000000000000000000000000000000000000", "014730f80ac625fe84f026c60bfd547d","5c9d844ed46f9885085e5d6a4f94c7d7");
    _make_test!(super::AES256, "0000000000000000000000000000000000000000000000000000000000000000", "0b24af36193ce4665f2825d7b4749c98","a9ff75bd7cf6613d3731c77c3b6d0c04");
    _make_test!(super::AES256, "0000000000000000000000000000000000000000000000000000000000000000", "761c1fe41a18acf20d241650611d90f1","623a52fcea5d443e48d9181ab32c7421");
    _make_test!(super::AES256, "0000000000000000000000000000000000000000000000000000000000000000", "8a560769d605868ad80d819bdba03771","38f2c7ae10612415d27ca190d27da8b4");
    _make_test!(super::AES256, "0000000000000000000000000000000000000000000000000000000000000000", "91fbef2d15a97816060bee1feaa49afe","1bc704f1bce135ceb810341b216d7abe");
    _make_test!(super::AES128, "10a58869d74be5a374cf867cfb473859", "00000000000000000000000000000000", "6d251e6944b051e04eaa6fb4dbf78465");
    _make_test!(super::AES128, "caea65cdbb75e9169ecd22ebe6e54675", "00000000000000000000000000000000", "6e29201190152df4ee058139def610bb");
    _make_test!(super::AES128, "a2e2fa9baf7d20822ca9f0542f764a41", "00000000000000000000000000000000", "c3b44b95d9d2f25670eee9a0de099fa3");
    _make_test!(super::AES128, "b6364ac4e1de1e285eaf144a2415f7a0", "00000000000000000000000000000000", "5d9b05578fc944b3cf1ccf0e746cd581");
    _make_test!(super::AES128, "64cf9c7abc50b888af65f49d521944b2", "00000000000000000000000000000000", "f7efc89d5dba578104016ce5ad659c05");
    _make_test!(super::AES128, "47d6742eefcc0465dc96355e851b64d9", "00000000000000000000000000000000", "0306194f666d183624aa230a8b264ae7");
    _make_test!(super::AES128, "3eb39790678c56bee34bbcdeccf6cdb5", "00000000000000000000000000000000", "858075d536d79ccee571f7d7204b1f67");
    _make_test!(super::AES128, "64110a924f0743d500ccadae72c13427", "00000000000000000000000000000000", "35870c6a57e9e92314bcb8087cde72ce");
    _make_test!(super::AES128, "18d8126516f8a12ab1a36d9f04d68e51", "00000000000000000000000000000000", "6c68e9be5ec41e22c825b7c7affb4363");
    _make_test!(super::AES128, "f530357968578480b398a3c251cd1093", "00000000000000000000000000000000", "f5df39990fc688f1b07224cc03e86cea");
    _make_test!(super::AES128, "da84367f325d42d601b4326964802e8e", "00000000000000000000000000000000", "bba071bcb470f8f6586e5d3add18bc66");
    _make_test!(super::AES128, "e37b1c6aa2846f6fdb413f238b089f23", "00000000000000000000000000000000", "43c9f7e62f5d288bb27aa40ef8fe1ea8");
    _make_test!(super::AES128, "6c002b682483e0cabcc731c253be5674", "00000000000000000000000000000000", "3580d19cff44f1014a7c966a69059de5");
    _make_test!(super::AES128, "143ae8ed6555aba96110ab58893a8ae1", "00000000000000000000000000000000", "806da864dd29d48deafbe764f8202aef");
    _make_test!(super::AES128, "b69418a85332240dc82492353956ae0c", "00000000000000000000000000000000", "a303d940ded8f0baff6f75414cac5243");
    _make_test!(super::AES128, "71b5c08a1993e1362e4d0ce9b22b78d5", "00000000000000000000000000000000", "c2dabd117f8a3ecabfbb11d12194d9d0");
    _make_test!(super::AES128, "e234cdca2606b81f29408d5f6da21206", "00000000000000000000000000000000", "fff60a4740086b3b9c56195b98d91a7b");
    _make_test!(super::AES128, "13237c49074a3da078dc1d828bb78c6f", "00000000000000000000000000000000", "8146a08e2357f0caa30ca8c94d1a0544");
    _make_test!(super::AES128, "3071a2a48fe6cbd04f1a129098e308f8", "00000000000000000000000000000000", "4b98e06d356deb07ebb824e5713f7be3");
    _make_test!(super::AES128, "90f42ec0f68385f2ffc5dfc03a654dce", "00000000000000000000000000000000", "7a20a53d460fc9ce0423a7a0764c6cf2");
    _make_test!(super::AES128, "febd9a24d8b65c1c787d50a4ed3619a9", "00000000000000000000000000000000", "f4a70d8af877f9b02b4c40df57d45b17");
    // find more test cases from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
}
