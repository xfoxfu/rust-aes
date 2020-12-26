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
    mode: Mode,
}

impl Opts {
    pub fn parse() -> Self {
        Clap::parse()
    }

    pub fn is_encrypt(&self) -> bool {
        match self.mode {
            Mode::Encrypt => true,
            Mode::Decrypt => false,
        }
    }

    pub fn is_decrypt(&self) -> bool {
        match self.mode {
            Mode::Encrypt => false,
            Mode::Decrypt => true,
        }
    }
}

#[derive(Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl std::str::FromStr for Mode {
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
