use super::{encrypt::State, sbox_get, RijndaelMode};

pub fn byte_to_word(bs: &[u8; 4]) -> u32 {
    ((bs[0] as u32) << 24) | ((bs[1] as u32) << 16) | ((bs[2] as u32) << 8) | bs[3] as u32
}

#[cfg(test)]
#[test]
fn test_byte_to_word() {
    assert_eq!(byte_to_word(&[0x12, 0x34, 0x56, 0x78]), 0x12345678);
}

pub fn rot_word(w: u32) -> u32 {
    (w << 8) | (w >> 24)
}

#[cfg(test)]
#[test]
fn test_rot_word() {
    assert_eq!(rot_word(0x12345678), 0x34567812);
    assert_eq!(rot_word(0x80123456), 0x12345680);
}

pub fn sub_word(w: u32) -> u32 {
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

pub fn word_to_bytes(w: u32) -> (u8, u8, u8, u8) {
    (
        (0xFF & (w >> 24)) as u8,
        (0xFF & (w >> 16)) as u8,
        (0xFF & (w >> 8)) as u8,
        (0xFF & w) as u8,
    )
}

#[cfg(test)]
#[test]
fn test_word_to_bytes() {
    assert_eq!(word_to_bytes(0x12345678), (0x12, 0x34, 0x56, 0x78));
    assert_eq!(word_to_bytes(0x89ABCDEF), (0x89, 0xAB, 0xCD, 0xEF));
}

pub fn words_to_matrix<M: RijndaelMode>(input: &[u32; M::NB_WORDS]) -> State<M> {
    let mut state = State::<M>::zeros();
    for i in 0..M::NB_WORDS {
        let (b0, b1, b2, b3) = word_to_bytes(input[i]);
        state[(0, i)] = b0;
        state[(1, i)] = b1;
        state[(2, i)] = b2;
        state[(3, i)] = b3;
    }
    state
}

#[cfg(test)]
#[test]
fn test_words_to_matrix() {
    use super::AES128;
    assert_eq!(
        words_to_matrix::<AES128>(&[
            0x12345678, 0x89ABCDEF, 0x42424242, 0x66CCFF00
        ]),
        State::<AES128>::from_column_slice(&[
            0x12, 0x34, 0x56, 0x78, // col 0
            0x89, 0xAB, 0xCD, 0xEF, // col 1
            0x42, 0x42, 0x42, 0x42, // col 2
            0x66, 0xCC, 0xFF, 0x00, // col 3
        ]),
    );
}

pub fn matrix_to_words<M: RijndaelMode>(state: &State<M>) -> [u32; M::NB_WORDS] {
    let mut output = [0;M::NB_WORDS];
    for i in 0..M::NB_WORDS {
        output[i] = byte_to_word(&[state[(0, i)], state[(1, i)], state[(2, i)], state[(3, i)]]);
    }
    output
}

#[cfg(test)]
#[test]
fn test_matrix_to_words() {
    use super::AES128;
    assert_eq!(
        matrix_to_words::<AES128>(&State::<AES128>::from_column_slice(&[
            0x12, 0x34, 0x56, 0x78, // col 0
            0x89, 0xAB, 0xCD, 0xEF, // col 1
            0x42, 0x42, 0x42, 0x42, // col 2
            0x66, 0xCC, 0xFF, 0x00, // col 3
        ])),
        [0x12345678, 0x89ABCDEF, 0x42424242, 0x66CCFF00]
    );
}

pub fn bytes_to_word_arr<const L: usize>(arr: [u8; L * 4]) -> [u32; L] {
    let mut ret = [0;L];
    for i in 0..L {
        ret[i] = byte_to_word(&[arr[i * 4], arr[i * 4 + 1], arr[i * 4 + 2], arr[i * 4 + 3]]);
    }
    ret
}
