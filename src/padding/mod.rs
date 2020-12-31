pub trait Padding {
    fn pad_block(ds_byte: usize, bs_byte: usize) -> Vec<u8>;
    fn pad(data: &mut Vec<u8>, bs_byte: usize) {
        data.append(&mut Self::pad_block(data.len() % bs_byte, bs_byte));
    }
    fn pad_eat(mut data: Vec<u8>, bs_byte: usize) -> Vec<u8> {
        if data.len() % bs_byte > 0 {
            data.append(&mut Self::pad_block(data.len() % bs_byte, bs_byte));
        }
        data
    }
}

mod ansix923;
pub use ansix923::X923;
mod iso10126;
pub use iso10126::ISO10126;
mod pkcs7;
pub use pkcs7::PKCS7;
