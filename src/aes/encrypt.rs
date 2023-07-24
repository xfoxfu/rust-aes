use super::{
    consts::{inv_sbox_get, sbox_get},
    converter::{byte_to_word, word_to_bytes},
    key_expansion::KeyExpander,
    matrix_to_words, words_to_matrix, RijndaelMode,
};
use nalgebra::{allocator::Allocator, DefaultAllocator, SMatrix};
use std::{convert::TryInto, ops::Mul};

pub fn galois_mul(mut a: u8, mut b: u8) -> u8 {
    // Galois Field (256) Multiplication of two Bytes
    let mut p = 0;

    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }

        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }

    p
}

pub type State<M: RijndaelMode> = SMatrix<u8, 4, { <M as RijndaelMode>::NB_WORDS }>;

pub struct RijndaelCryptor<M: RijndaelMode>
where
    [(); M::NB_WORDS]:,
    [(); M::NR_KEY]:,
{
    state: State<M>,
    keys: [State<M>; M::NR_KEY],
}

impl<M: RijndaelMode> RijndaelCryptor<M>
where
    [(); M::NB_WORDS]:,
    [(); M::NR_KEY]:,
    [(); M::NR_KEY * M::NB_WORDS]:,
    [(); M::NK_WORDS]:,
    [(); M::NK_WORDS * 4]:,
{
    pub fn new(input: &[u32; M::NB_WORDS], key: &[u32; M::NR_KEY * M::NB_WORDS]) -> Self {
        let state = words_to_matrix::<M>(input);
        let mut keys = [SMatrix::zeros(); M::NR_KEY];
        // (0..key.len()).step_by(4).map(|i| {
        //     words_to_matrix::<M>(
        //         &[key[i], key[i + 1], key[i + 2], key[i + 3]]
        //             .try_into()
        //             .unwrap(),
        //     )
        // });
        for i in 0..M::NR_KEY {
            keys[i] =
                words_to_matrix::<M>(&key[(i * 4)..(i * 4 + M::NB_WORDS)].try_into().unwrap());
        }
        Self { state, keys }
    }

    pub fn new_with_raw_data(input: &[u8], key: &[u8]) -> Self {
        assert_eq!(input.len(), M::NB_WORDS * 4);
        assert_eq!(key.len(), M::NK_WORDS * 4);
        let mut input_arr = [0; M::NB_WORDS];
        let mut key_arr = [0; M::NB_WORDS];
        for i in 0..M::NB_WORDS {
            input_arr[i] = byte_to_word(&[
                input[i * 4],
                input[i * 4 + 1],
                input[i * 4 + 2],
                input[i * 4 + 3],
            ]);
        }
        for i in 0..M::NB_WORDS {
            key_arr[i] =
                byte_to_word(&[key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        let key_arr = KeyExpander::<M>::key_expansion(&KeyExpander::<M>::convert_key(
            key.try_into().unwrap(),
        ));
        Self::new(&input_arr, &key_arr)
    }

    pub fn new_with_raw_data_key(input: &[u8], key: &[u32; M::NR_KEY * M::NB_WORDS]) -> Self {
        assert_eq!(input.len(), M::NB_WORDS * 4);
        let mut input_arr = [0; M::NB_WORDS];
        for i in 0..M::NB_WORDS {
            input_arr[i] = byte_to_word(&[
                input[i * 4],
                input[i * 4 + 1],
                input[i * 4 + 2],
                input[i * 4 + 3],
            ]);
        }
        Self::new(&input_arr, key)
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

    pub fn inv_sub_bytes(&mut self) {
        for mut row in self.state.row_iter_mut() {
            for cell in row.iter_mut() {
                *cell = inv_sbox_get(*cell);
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

    pub fn inv_shift_row(&mut self, row_id: usize, count: usize) {
        let row_len = self.state.row(row_id).len();
        for _ in 0..count {
            for i in (0..(row_len - 1)).rev() {
                self.state.swap((row_id, i), (row_id, (i + 1) % row_len));
            }
        }
    }

    pub fn shift_rows(&mut self) {
        for i in 0..4 {
            self.shift_row(i, i);
        }
    }

    pub fn inv_shift_rows(&mut self) {
        for i in 0..4 {
            self.inv_shift_row(i, i);
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

    pub fn inv_mix_column(&mut self, c: usize) {
        use galois_mul as gm;
        let s0 = self.state[(0, c)];
        let s1 = self.state[(1, c)];
        let s2 = self.state[(2, c)];
        let s3 = self.state[(3, c)];

        self.state[(0, c)] = gm(0x0e, s0) ^ gm(0x0b, s1) ^ gm(0x0d, s2) ^ gm(0x09, s3);
        self.state[(1, c)] = gm(0x09, s0) ^ gm(0x0e, s1) ^ gm(0x0b, s2) ^ gm(0x0d, s3);
        self.state[(2, c)] = gm(0x0d, s0) ^ gm(0x09, s1) ^ gm(0x0e, s2) ^ gm(0x0b, s3);
        self.state[(3, c)] = gm(0x0b, s0) ^ gm(0x0d, s1) ^ gm(0x09, s2) ^ gm(0x0e, s3);
    }

    pub fn mix_columns(&mut self) {
        for col in 0..self.state.column_iter().len() {
            self.mix_column(col);
        }
    }

    pub fn inv_mix_columns(&mut self) {
        for col in 0..self.state.column_iter().len() {
            self.inv_mix_column(col);
        }
    }

    pub fn encrypt(mut self) -> [u32; M::NB_WORDS] {
        self.add_round_key(0);

        for i in 0..M::NR {
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(i + 1);
        }

        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(M::NR + 1);

        matrix_to_words::<M>(&self.state)
    }

    pub fn decrypt(mut self) -> [u32; M::NB_WORDS] {
        self.add_round_key(M::NR + 1);

        for i in (0..M::NR).rev() {
            self.inv_shift_rows();
            self.inv_sub_bytes();
            self.add_round_key(i + 1);
            self.inv_mix_columns();
        }

        self.inv_shift_rows();
        self.inv_sub_bytes();
        self.add_round_key(0);

        matrix_to_words::<M>(&self.state)
    }

    pub fn encrypt_to_arr(self) -> [u8; M::NB_WORDS * 4] {
        let res = self.encrypt();
        let mut ret = [0; M::NB_WORDS * 4];
        for i in 0..res.len() {
            let (r0, r1, r2, r3) = word_to_bytes(res[i]);
            ret[i * 4] = r0;
            ret[i * 4 + 1] = r1;
            ret[i * 4 + 2] = r2;
            ret[i * 4 + 3] = r3;
        }
        ret
    }

    pub fn decrypt_to_arr(self) -> [u8; M::NB_WORDS * 4] {
        let res = self.decrypt();
        let mut ret = [0; M::NB_WORDS * 4];
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
        let enc = hex::decode($enc).unwrap();
        let key = hex::decode($key).unwrap();
        let cryptor = RijndaelCryptor::<$mode>::new_with_raw_data(&plain, &key);
        let ciphertext = cryptor.encrypt_to_arr();
        assert_eq!(hex::encode(ciphertext), $enc);
        let cryptor = RijndaelCryptor::<$mode>::new_with_raw_data(&enc, &key);
        let plaintext = cryptor.decrypt_to_arr();
        assert_eq!(hex::encode(plaintext), $val);
    };
}

#[cfg(test)]
#[test]
pub fn test_rijndael_iter() {
    let plain = hex::decode("f34481ec3cc627bacd5dc3fbdb135345").unwrap();
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let mut cryptor = RijndaelCryptor::<super::AES128>::new_with_raw_data(&plain, &key);
    cryptor.add_round_key(0);
    assert_eq!(
        cryptor._test_get_state(),
        &State::<super::AES128>::from_column_slice(&[
            0xf3, 0x44, 0x81, 0xec, //
            0x3c, 0xc6, 0x27, 0xba, //
            0xcd, 0x5d, 0xc3, 0xfb, //
            0xdb, 0x13, 0x53, 0x45, //
        ])
    );
    cryptor.shift_rows();
    assert_eq!(
        cryptor._test_get_state(),
        &State::<super::AES128>::from_row_slice(&[
            0xf3, 0x3c, 0xcd, 0xdb, //
            0xc6, 0x5d, 0x13, 0x44, //
            0xc3, 0x53, 0x81, 0x27, //
            0x45, 0xec, 0xba, 0xfb, //
        ])
    );
    cryptor.sub_bytes();
    assert_eq!(
        cryptor._test_get_state(),
        &State::<super::AES128>::from_row_slice(&[
            0x0d, 0xeb, 0xbd, 0xb9, //
            0xb4, 0x4c, 0x7d, 0x1b, //
            0x2e, 0xed, 0x0c, 0xcc, //
            0x6e, 0xce, 0xf4, 0x0f, //
        ])
    );
    cryptor.mix_columns();
    assert_eq!(
        cryptor._test_get_state(),
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
pub fn test_rijndael_enc() {
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
    // the following is from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    _make_test!(super::AES128, "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a");
    _make_test!(super::AES192, "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191");
    _make_test!(super::AES256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089");
    _make_test!(super::AES128, "2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97");
}
