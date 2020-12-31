use std::str::FromStr;

use crate::padding::{ISO10126, PKCS7, X923};
use crate::stream::{CipherBlockChaining, Streamer};
use crate::{
    aes::{AES128, AES192, AES256},
    stream::ElectronicCodeBook,
};
use clap::{crate_authors, crate_version, Clap};

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap, Debug)]
#[clap(version = crate_version!(), author = crate_authors!())]
pub struct Opts {
    /// Input file name, use a `-` for standard input
    #[clap(default_value = "-")]
    pub input: String,
    /// Output file name, use a `-` for standard output
    #[clap(default_value = "-")]
    pub output: String,
    /// Key in hex format.
    #[clap(short, long, default_value = "-")]
    pub key: String,
    /// IV in hex format.
    #[clap(short, long, default_value = "-")]
    pub iv: String,
    /// Indicates input and output are hex strings.
    #[clap(short = 'a', long)]
    pub hex: bool,
    /// Log verbosity. May be used multiple times.
    #[clap(short, long, parse(from_occurrences))]
    pub verbose: i32,
    /// Operation mode, `encrypt` or `decrypt`
    #[clap(short, long)]
    pub op: Operation,
    /// AES / Rijndael Modes
    #[clap(short, long)]
    pub mode: Cipherset,
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
        $vis struct $name($st<$m, $pad>);

        impl StreamCipher for $name {
            fn new(key: &[u8], iv: &[u8]) -> Self
            where
                Self: Sized,
            {
                Self($st::<$m, $pad>::new(
                    generic_array::GenericArray::clone_from_slice(iv),
                    generic_array::GenericArray::clone_from_slice(key),
                ))
            }

            fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
                self.0.stream_encrypt(data)
            }

            fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
                self.0.stream_decrypt(data)
            }
        }
    };
}

impl_cipherset!(pub Aes128CbcIso10126 => AES128, CipherBlockChaining, ISO10126);
impl_cipherset!(pub Aes128CbcPkcs7 => AES128, CipherBlockChaining, PKCS7);
impl_cipherset!(pub Aes128CbcX923 => AES128, CipherBlockChaining, X923);
impl_cipherset!(pub Aes128EcbIso10126 => AES128, ElectronicCodeBook, ISO10126);
impl_cipherset!(pub Aes128EcbPkcs7 => AES128, ElectronicCodeBook, PKCS7);
impl_cipherset!(pub Aes128EcbX923 => AES128, ElectronicCodeBook, X923);
impl_cipherset!(pub Aes192CbcIso10126 => AES192, CipherBlockChaining, ISO10126);
impl_cipherset!(pub Aes192CbcPkcs7 => AES192, CipherBlockChaining, PKCS7);
impl_cipherset!(pub Aes192CbcX923 => AES192, CipherBlockChaining, X923);
impl_cipherset!(pub Aes192EcbIso10126 => AES192, ElectronicCodeBook, ISO10126);
impl_cipherset!(pub Aes192EcbPkcs7 => AES192, ElectronicCodeBook, PKCS7);
impl_cipherset!(pub Aes192EcbX923 => AES192, ElectronicCodeBook, X923);
impl_cipherset!(pub Aes256CbcIso10126 => AES256, CipherBlockChaining, ISO10126);
impl_cipherset!(pub Aes256CbcPkcs7 => AES256, CipherBlockChaining, PKCS7);
impl_cipherset!(pub Aes256CbcX923 => AES256, CipherBlockChaining, X923);
impl_cipherset!(pub Aes256EcbIso10126 => AES256, ElectronicCodeBook, ISO10126);
impl_cipherset!(pub Aes256EcbPkcs7 => AES256, ElectronicCodeBook, PKCS7);
impl_cipherset!(pub Aes256EcbX923 => AES256, ElectronicCodeBook, X923);

#[derive(Debug)]
pub enum Cipherset {
    Aes128CbcIso10126,
    Aes128CbcPkcs7,
    Aes128CbcX923,
    Aes128EcbIso10126,
    Aes128EcbPkcs7,
    Aes128EcbX923,
    Aes192CbcIso10126,
    Aes192CbcPkcs7,
    Aes192CbcX923,
    Aes192EcbIso10126,
    Aes192EcbPkcs7,
    Aes192EcbX923,
    Aes256CbcIso10126,
    Aes256CbcPkcs7,
    Aes256CbcX923,
    Aes256EcbIso10126,
    Aes256EcbPkcs7,
    Aes256EcbX923,
}

impl FromStr for Cipherset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes-128-cbc" => Ok(Cipherset::Aes128CbcPkcs7),
            "aes-128-cbc-iso10126" => Ok(Cipherset::Aes128CbcIso10126),
            "aes-128-cbc-pkcs7" => Ok(Cipherset::Aes128CbcPkcs7),
            "aes-128-cbc-x923" => Ok(Cipherset::Aes128CbcX923),
            "aes-128-ecb" => Ok(Cipherset::Aes128EcbPkcs7),
            "aes-128-ecb-iso10126" => Ok(Cipherset::Aes128EcbIso10126),
            "aes-128-ecb-pkcs7" => Ok(Cipherset::Aes128EcbPkcs7),
            "aes-128-ecb-x923" => Ok(Cipherset::Aes128EcbX923),
            "aes-192-cbc" => Ok(Cipherset::Aes192CbcPkcs7),
            "aes-192-cbc-iso10126" => Ok(Cipherset::Aes192CbcIso10126),
            "aes-192-cbc-pkcs7" => Ok(Cipherset::Aes192CbcPkcs7),
            "aes-192-cbc-x923" => Ok(Cipherset::Aes192CbcX923),
            "aes-192-ecb" => Ok(Cipherset::Aes192EcbPkcs7),
            "aes-192-ecb-iso10126" => Ok(Cipherset::Aes192EcbIso10126),
            "aes-192-ecb-pkcs7" => Ok(Cipherset::Aes192EcbPkcs7),
            "aes-192-ecb-x923" => Ok(Cipherset::Aes192EcbX923),
            "aes-256-cbc" => Ok(Cipherset::Aes256CbcPkcs7),
            "aes-256-cbc-iso10126" => Ok(Cipherset::Aes256CbcIso10126),
            "aes-256-cbc-pkcs7" => Ok(Cipherset::Aes256CbcPkcs7),
            "aes-256-cbc-x923" => Ok(Cipherset::Aes256CbcX923),
            "aes-256-ecb" => Ok(Cipherset::Aes256EcbPkcs7),
            "aes-256-ecb-iso10126" => Ok(Cipherset::Aes256EcbIso10126),
            "aes-256-ecb-pkcs7" => Ok(Cipherset::Aes256EcbPkcs7),
            "aes-256-ecb-x923" => Ok(Cipherset::Aes256EcbX923),
            _ => Err("invalid cipher set".to_string()),
        }
    }
}

impl Cipherset {
    pub fn get_cipher(&self, key: &[u8], iv: &[u8]) -> Box<dyn StreamCipher> {
        match self {
            Cipherset::Aes128CbcIso10126 => Box::new(Aes128CbcIso10126::new(key, iv)),
            Cipherset::Aes128CbcPkcs7 => Box::new(Aes128CbcPkcs7::new(key, iv)),
            Cipherset::Aes128CbcX923 => Box::new(Aes128CbcX923::new(key, iv)),
            Cipherset::Aes128EcbIso10126 => Box::new(Aes128EcbIso10126::new(key, iv)),
            Cipherset::Aes128EcbPkcs7 => Box::new(Aes128EcbPkcs7::new(key, iv)),
            Cipherset::Aes128EcbX923 => Box::new(Aes128EcbX923::new(key, iv)),
            Cipherset::Aes192CbcIso10126 => Box::new(Aes192CbcIso10126::new(key, iv)),
            Cipherset::Aes192CbcPkcs7 => Box::new(Aes192CbcPkcs7::new(key, iv)),
            Cipherset::Aes192CbcX923 => Box::new(Aes192CbcX923::new(key, iv)),
            Cipherset::Aes192EcbIso10126 => Box::new(Aes192EcbIso10126::new(key, iv)),
            Cipherset::Aes192EcbPkcs7 => Box::new(Aes192EcbPkcs7::new(key, iv)),
            Cipherset::Aes192EcbX923 => Box::new(Aes192EcbX923::new(key, iv)),
            Cipherset::Aes256CbcIso10126 => Box::new(Aes256CbcIso10126::new(key, iv)),
            Cipherset::Aes256CbcPkcs7 => Box::new(Aes256CbcPkcs7::new(key, iv)),
            Cipherset::Aes256CbcX923 => Box::new(Aes256CbcX923::new(key, iv)),
            Cipherset::Aes256EcbIso10126 => Box::new(Aes256EcbIso10126::new(key, iv)),
            Cipherset::Aes256EcbPkcs7 => Box::new(Aes256EcbPkcs7::new(key, iv)),
            Cipherset::Aes256EcbX923 => Box::new(Aes256EcbX923::new(key, iv)),
        }
    }
}
