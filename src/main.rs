//! https://songlee24.github.io/2014/12/13/aes-encrypt/

mod aes;
mod opt;
mod padding;
mod stream;

fn main() -> std::io::Result<()> {
    let opts = opt::Opts::parse();
    println!("{:?}", opts);

    Ok(())
}
