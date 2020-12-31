pub trait Padding {
    fn pad_block(ds_byte: usize, bs_byte: usize) -> Vec<u8>;
    #[allow(unused_variables)]
    fn unpad_block(data: &[u8], bs_byte: usize) -> usize {
        *data.last().unwrap() as usize
    }
    fn pad(data: &mut Vec<u8>, bs_byte: usize) {
        data.append(&mut Self::pad_block(data.len() % bs_byte, bs_byte));
    }
    fn pad_eat(mut data: Vec<u8>, bs_byte: usize) -> Vec<u8> {
        Self::pad(&mut data, bs_byte);
        data
    }
    fn unpad(data: &mut Vec<u8>, bs_byte: usize) {
        data.resize_with(
            data.len() - Self::unpad_block(&data[(data.len() - bs_byte)..data.len()], bs_byte),
            Default::default,
        );
    }
    fn unpad_eat(mut data: Vec<u8>, bs_byte: usize) -> Vec<u8> {
        Self::unpad(&mut data, bs_byte);
        data
    }
}

mod ansix923;
pub use ansix923::X923;
mod iso10126;
pub use iso10126::ISO10126;
mod pkcs7;
pub use pkcs7::PKCS7;
