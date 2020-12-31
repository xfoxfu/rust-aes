//! https://songlee24.github.io/2014/12/13/aes-encrypt/

use std::{
    fs::File,
    io::{Read, Write},
};

mod aes;
mod opt;
mod padding;
mod stream;

fn main() -> anyhow::Result<()> {
    let opts = opt::Opts::parse();

    let mut input = Vec::new();
    File::open(&opts.input)?.read_to_end(&mut input)?;

    let key = hex::decode(&opts.key)?;
    let iv = hex::decode(&opts.iv)?;

    let mut cipher = opts.mode.get_cipher(&key, &iv);
    let result = if opts.is_encrypt() {
        cipher.encrypt(&input)
    } else {
        cipher.decrypt(&input)
    };

    File::create(&opts.output)?.write_all(&result)?;

    Ok(())
}
