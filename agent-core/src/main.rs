use anyhow::Context;

fn main() -> anyhow::Result<()> {
  let args: Vec<String> = std::env::args().collect();

  if args.iter().any(|a| a == "--version") {
    println!("{}", env!("CARGO_PKG_VERSION"));
    return Ok(());
  }

  if args.iter().any(|a| a == "--console") {
    return agent_core::run_console(&args).context("run console mode");
  }

  agent_core::service::run_service().context("start Windows Service dispatcher")
}
