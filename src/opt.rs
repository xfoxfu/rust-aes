use crate::aes::{AES128, AES192, AES256};
use crate::stream::{CipherBlockChaining, Streamer};
use clap::{crate_authors, crate_version, Clap};

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap, Debug)]
#[clap(version = crate_version!(), author = crate_authors!())]
pub struct Opts {
    /// Input file name, use a `-` for standard input
    #[clap(default_value = "-")]
    input: String,
    /// Output file name, use a `-` for standard output
    #[clap(default_value = "-")]
    output: String,
    /// Encode output with base64.
    #[clap(short = 'a', long)]
    base64: bool,
    /// Log verbosity. May be used multiple times.
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,
    /// Operation mode, `encrypt` or `decrypt`
    #[clap(short, long)]
    op: Operation,
    // /// AES / Rijndael Modes
    // #[clap(short, long)]
    // mode: Box<dyn StreamCipher>,
}

impl Opts {
    pub fn parse() -> Self {
        Clap::parse()
    }

    pub fn is_encrypt(&self) -> bool {
        match self.op {
            Operation::Encrypt => true,
            Operation::Decrypt => false,
        }
    }

    pub fn is_decrypt(&self) -> bool {
        match self.op {
            Operation::Encrypt => false,
            Operation::Decrypt => true,
        }
    }
}

#[derive(Debug)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl std::str::FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "encrypt" | "enc" | "e" => Ok(Self::Encrypt),
            "decrypt" | "dec" | "d" => Ok(Self::Decrypt),
            _ => Err(format!(
                "unexpected value `{}`, expecting `encrypt`, `enc`, `e`, `decrypt`, `dec`, `d`",
                s
            )),
        }
    }
}

pub trait StreamCipher {
    fn new(key: &[u8], iv: &[u8]) -> Self
    where
        Self: Sized;
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

macro_rules! impl_cipherset {
    ($vis: vis $name: ident => $m: ident, $st: ident, $pad: ident) => {
        $vis struct $name($st<$m>);

        impl StreamCipher for $name {
            fn new(key: &[u8], iv: &[u8]) -> Self
            where
                Self: Sized,
            {
                Self($st::<$m>::new(
                    generic_array::GenericArray::clone_from_slice(key),
                    generic_array::GenericArray::clone_from_slice(iv),
                ))
            }

            fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
                todo!()
            }

            fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
                todo!()
            }
        }
    };
}

// impl_cipherset!(pub AES128CBCPKCS7 => AES128, CipherBlockChaining, PKCS7Padding);
