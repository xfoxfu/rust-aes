#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(associated_type_defaults)]

//! https://songlee24.github.io/2014/12/13/aes-encrypt/

use std::{
    fs::File,
    io::{stdin, stdout, Read, Write},
};

mod aes;
mod opt;
mod padding;
mod stream;

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

fn main() -> anyhow::Result<()> {
    let opts = opt::Opts::parse();

    let mut input = Vec::new();
    if opts.input != "-" {
        File::open(&opts.input)?.read_to_end(&mut input)?;
    } else {
        stdin().read_to_end(&mut input)?;
    }
    if opts.hex {
        input = hex::decode(String::from_utf8(input)?.trim())?;
    }

    let key = hex::decode(&opts.key)?;
    let iv = hex::decode(&opts.iv)?;

    let mut cipher = opts.mode.get_cipher(&key, &iv);
    let mut result = if opts.is_encrypt() {
        cipher.encrypt(&input)
    } else {
        assert!(opts.is_decrypt());
        cipher.decrypt(&input)
    };

    if opts.hex {
        result = hex::encode(&result).as_bytes().to_vec();
    }
    if opts.output != "-" {
        File::create(&opts.output)?.write_all(&result)?;
    } else {
        stdout().write_all(&result)?;
    }

    Ok(())
}
