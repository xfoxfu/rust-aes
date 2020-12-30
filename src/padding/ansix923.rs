use super::Padding;

pub struct X923;

impl Padding for X923 {
    fn pad_block(ds_byte: usize, bs_byte: usize) -> Vec<u8> {
        let mut ret = vec![0x00; bs_byte - ds_byte - 1];
        ret.push((bs_byte - ds_byte) as u8);
        ret
    }
}

#[cfg(test)]
#[test]
#[rustfmt::skip]
fn test() {
    assert_eq!(&X923::pad_eat(vec![0xFF; 8], 8), b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
    assert_eq!(&X923::pad_eat(vec![0xFF; 1], 8), b"\xFF\x00\x00\x00\x00\x00\x00\x07");
    assert_eq!(&X923::pad_eat(vec![0xFF; 2], 8), b"\xFF\xFF\x00\x00\x00\x00\x00\x06");
    assert_eq!(&X923::pad_eat(vec![0xFF; 3], 8), b"\xFF\xFF\xFF\x00\x00\x00\x00\x05");
    assert_eq!(&X923::pad_eat(vec![0xFF; 4], 8), b"\xFF\xFF\xFF\xFF\x00\x00\x00\x04");
    assert_eq!(&X923::pad_eat(vec![0xFF; 5], 8), b"\xFF\xFF\xFF\xFF\xFF\x00\x00\x03");
    assert_eq!(&X923::pad_eat(vec![0xFF; 6], 8), b"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x02");
    assert_eq!(&X923::pad_eat(vec![0xFF; 7], 8), b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01");
}
