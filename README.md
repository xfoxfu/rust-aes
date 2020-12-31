# rust-aes

An AES implementation in Rust.

## Compiling

The code can be compiled with [cargo](https://doc.rust-lang.org/cargo/). Users may install Cargo with [rustup](https://rustup.rs/) to establish a Rust compiling and running environment.

With cargo installed, compiling is simply

```bash
cargo build
```

and the resulting binary lays in `/target/debug/aes`.

The software speed may benefit from a release mode (optimizations).

```bash
cargo build --release
```

The resulting binary lays in `/target/release/aes`.

## Running

```console
aes 0.1.0
Yuze Fu <i@xfox.me>

USAGE:
    aes [FLAGS] [OPTIONS] --op <op> --mode <mode> [ARGS]

ARGS:
    <input>     Input file name, use a `-` for standard input [default: -]
    <output>    Output file name, use a `-` for standard output [default: -]

FLAGS:
    -h, --help       Prints help information
    -a, --hex        Indicates input and output are hex strings
    -v, --verbose    Log verbosity. May be used multiple times
    -V, --version    Prints version information

OPTIONS:
    -i, --iv <iv>        IV in hex format [default: -]
    -k, --key <key>      Key in hex format [default: -]
    -m, --mode <mode>    AES / Rijndael Modes
    -o, --op <op>        Operation mode, `encrypt` or `decrypt`
```

For example,

```bash
# AES-128-CBC with PKCS7 padding
#                       key                                 iv                                enc/dec
./aes -m aes-128-cbc -k 2b7e151628aed2a6abf7158809cf4f3c -i ae2d8a571e03ac9c9eb76fac45af8e51 -o enc p.txt c.aes
./aes -m aes-128-cbc -k 2b7e151628aed2a6abf7158809cf4f3c -i ae2d8a571e03ac9c9eb76fac45af8e51 -o dec c.aes p.txt
```

## Testing

Use cargo to run test cases.

```bash
cargo test
```

```console
running 16 tests
test aes::consts::test_sbox ... ok
test aes::converter::test_rot_word ... ok
test aes::consts::test_rcon ... ok
test aes::converter::test_sub_word ... ok
test aes::converter::test_byte_to_word ... ok
test aes::converter::test_word_to_bytes ... ok
test aes::converter::test_matrix_to_words ... ok
test aes::converter::test_words_to_matrix ... ok
test aes::key_expansion::test_key_expansion ... ok
test padding::ansix923::test ... ok
test padding::pkcs7::test ... ok
test aes::encrypt::test_rijndael_iter ... ok
test padding::iso10126::test ... ok
test stream::ecb::test ... ok
test stream::cbc::test ... ok
test aes::encrypt::test_rijndael_enc ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
