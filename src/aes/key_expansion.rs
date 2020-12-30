use super::{byte_to_word, rcon_get, rot_word, sub_word, RijndaelMode};
use generic_array::GenericArray;
use std::marker::PhantomData;
use typenum::{Prod, Unsigned};

pub struct KeyExpander<M: RijndaelMode>(PhantomData<M>);

impl<M: RijndaelMode> KeyExpander<M>
where
    M::NkWords: generic_array::ArrayLength<u32>,
    M::NkWords: std::ops::Mul<typenum::U4>,
    Prod<M::NkWords, typenum::U4>: generic_array::ArrayLength<u8>,
{
    pub fn convert_key(
        raw: &GenericArray<u8, Prod<M::NkWords, typenum::U4>>,
    ) -> GenericArray<u32, M::NkWords> {
        let mut r = GenericArray::default();
        for i in 0..M::NkWords::to_usize() {
            r[i] = byte_to_word(&[raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2], raw[i * 4 + 3]]);
        }
        r
    }
}

impl<M: RijndaelMode> KeyExpander<M>
where
    M::NrKey: std::ops::Mul<M::NbWords>,
    M::NkWords: generic_array::ArrayLength<u32>,
    Prod<M::NrKey, M::NbWords>: generic_array::ArrayLength<u32>,
{
    #[allow(clippy::many_single_char_names)]
    /// AES key schedule algorithm
    /// # See
    /// See [AES Key Schedule](https://en.wikipedia.org/wiki/AES_key_expansion#The_key_expansion)
    pub fn key_expansion(
        k: &GenericArray<u32, M::NkWords>,
    ) -> GenericArray<u32, Prod<M::NrKey, M::NbWords>> {
        let n = M::NkWords::to_usize();
        let b = M::NbWords::to_usize();
        let r = M::NrKey::to_usize();

        let mut w = GenericArray::default();
        for i in 0..(b * r) {
            if i < n {
                w[i] = k[i];
            } else if i >= n && i % n == 0 {
                w[i] = w[i - n] ^ sub_word(rot_word(w[i - 1])) ^ rcon_get(i / n);
            } else if i >= n && n > 6 && i % n == 4 {
                w[i] = w[i - n] ^ sub_word(w[i - 1]);
            } else {
                w[i] = w[i - n] ^ w[i - 1];
            }
        }

        w
    }
}

#[cfg(test)]
#[test]
fn test_key_expansion() {
    type Expander = KeyExpander<super::AES128>;

    let k = b"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
    let w = Expander::key_expansion(&Expander::convert_key(GenericArray::from_slice(k)));
    assert_eq!(
        &w,
        GenericArray::from_slice(&[
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6
        ])
    );
}
