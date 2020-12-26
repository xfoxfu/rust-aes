use std::marker::PhantomData;

use super::{rcon_get, sbox_get, LengthMode};
use generic_array::GenericArray;
use typenum::{Prod, Unsigned};

pub struct KeyExpander<M: LengthMode>(PhantomData<M>);

fn byte_to_word(bs: &[u8; 4]) -> u32 {
    ((bs[0] as u32) << 24) | ((bs[1] as u32) << 16) | ((bs[2] as u32) << 8) | bs[3] as u32
}

#[cfg(test)]
#[test]
fn test_byte_to_word() {
    assert_eq!(byte_to_word(&[0x12, 0x34, 0x56, 0x78]), 0x12345678);
}

impl<M: LengthMode> KeyExpander<M>
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

fn rot_word(w: u32) -> u32 {
    (w << 8) | (w >> 24)
}

#[cfg(test)]
#[test]
fn test_rot_word() {
    assert_eq!(rot_word(0x12345678), 0x34567812);
    assert_eq!(rot_word(0x80123456), 0x12345680);
}

fn sub_word(w: u32) -> u32 {
    ((sbox_get((0xFF & (w >> 24)) as u8) as u32) << 24)
        | ((sbox_get((0xFF & (w >> 16)) as u8) as u32) << 16)
        | ((sbox_get((0xFF & (w >> 8)) as u8) as u32) << 8)
        | (sbox_get((0xFF & w) as u8) as u32)
}

#[cfg(test)]
#[test]
fn test_sub_word() {
    assert_eq!(sub_word(0x12345678), 0xC918B1BC);
}

impl<M: LengthMode> KeyExpander<M>
where
    M: LengthMode,
    M::NrKey: std::ops::Mul<typenum::U4>,
    M::NkWords: generic_array::ArrayLength<u32>,
    Prod<M::NrKey, typenum::U4>: generic_array::ArrayLength<u32>,
{
    /// AES key schedule algorithm
    /// # Panics
    /// When input key size does not match given mode `M`.
    /// # See
    /// See [AES Key Schedule](https://en.wikipedia.org/wiki/AES_key_expansion#The_key_expansion)
    pub fn key_expansion(
        k: &GenericArray<u32, M::NkWords>,
    ) -> GenericArray<u32, Prod<M::NrKey, typenum::U4>> {
        let n = M::NkWords::to_usize();
        let r = M::NrKey::to_usize();

        let mut w = GenericArray::default();
        for i in 0..(4 * r) {
            if i < n {
                w[i] = dbg!(i, k[i]).1;
            } else if i >= n && i % n == 0 {
                w[i] = dbg!(i, w[i - n] ^ sub_word(rot_word(w[i - 1])) ^ rcon_get(i / n)).1;
            } else if i >= n && n > 6 && i % n == 4 {
                w[i] = dbg!(i, w[i - n] ^ sub_word(w[i - 1])).1;
            } else {
                w[i] = dbg!(i, w[i - n] ^ w[i - 1]).1;
            }
        }

        w
    }
}

#[cfg(test)]
#[test]
pub fn test_key_expansion() {
    type Expander = KeyExpander<super::AES128>;

    let k = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
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
