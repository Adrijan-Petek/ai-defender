use anyhow::Context;

fn main() -> anyhow::Result<()> {
  let args: Vec<String> = std::env::args().collect();

  if args.iter().any(|a| a == "--version") {
    println!("{}", env!("CARGO_PKG_VERSION"));
    return Ok(());
  }

  let mode = scanner::ScanMode::from_args(&args)?;
  scanner::run(mode).context("scanner run")
}

