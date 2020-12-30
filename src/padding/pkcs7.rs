use super::Padding;

pub struct PKCS7;

impl Padding for PKCS7 {
    fn pad_block(ds_byte: usize, bs_byte: usize) -> Vec<u8> {
        vec![(bs_byte - ds_byte) as u8; bs_byte - ds_byte]
    }
}

#[cfg(test)]
#[test]
#[rustfmt::skip]
fn test() {
    assert_eq!(PKCS7::pad_block(1, 8), vec![0x08 - 0x01; 0x08 - 0x01]);
    assert_eq!(PKCS7::pad_block(2, 8), vec![0x08 - 0x02; 0x08 - 0x02]);
    assert_eq!(PKCS7::pad_block(3, 8), vec![0x08 - 0x03; 0x08 - 0x03]);
    assert_eq!(PKCS7::pad_block(4, 8), vec![0x08 - 0x04; 0x08 - 0x04]);
    assert_eq!(PKCS7::pad_block(5, 8), vec![0x08 - 0x05; 0x08 - 0x05]);
    assert_eq!(PKCS7::pad_block(6, 8), vec![0x08 - 0x06; 0x08 - 0x06]);
    assert_eq!(PKCS7::pad_block(7, 8), vec![0x08 - 0x07; 0x08 - 0x07]);
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 8], 8), b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 1], 8), b"\xFF\x07\x07\x07\x07\x07\x07\x07");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 2], 8), b"\xFF\xFF\x06\x06\x06\x06\x06\x06");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 3], 8), b"\xFF\xFF\xFF\x05\x05\x05\x05\x05");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 4], 8), b"\xFF\xFF\xFF\xFF\x04\x04\x04\x04");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 5], 8), b"\xFF\xFF\xFF\xFF\xFF\x03\x03\x03");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 6], 8), b"\xFF\xFF\xFF\xFF\xFF\xFF\x02\x02");
    assert_eq!(&PKCS7::pad_eat(vec![0xFF; 7], 8), b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x01");
}
