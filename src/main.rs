mod opt;

fn main() -> std::io::Result<()> {
    let opts = opt::Opts::parse();
    println!("{:?}", opts);

    Ok(())
}
