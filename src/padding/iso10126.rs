use super::Padding;
use rand::prelude::*;

pub struct ISO10126;

impl Padding for ISO10126 {
    fn pad_block(ds_byte: usize, bs_byte: usize) -> Vec<u8> {
        let mut ret = vec![0x00; bs_byte - ds_byte];
        rand::thread_rng().fill_bytes(&mut ret);
        *ret.last_mut().unwrap() = (bs_byte - ds_byte) as u8;
        ret
    }
}

#[cfg(test)]
#[test]
#[rustfmt::skip]
fn test() {
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 8], 8).last().unwrap(), 0xFF);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 1], 8).last().unwrap(), 0x07);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 2], 8).last().unwrap(), 0x06);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 3], 8).last().unwrap(), 0x05);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 4], 8).last().unwrap(), 0x04);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 5], 8).last().unwrap(), 0x03);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 6], 8).last().unwrap(), 0x02);
    assert_eq!(*ISO10126::pad_eat(vec![0xFF; 7], 8).last().unwrap(), 0x01);
}
