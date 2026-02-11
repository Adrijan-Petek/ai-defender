use anyhow::Context;

fn main() -> anyhow::Result<()> {
  let args: Vec<String> = std::env::args().collect();
  let dry_run = agent_core::runtime::configure_from_args(&args);

  if args.iter().any(|a| a == "--version") {
    println!("{}", env!("CARGO_PKG_VERSION"));
    return Ok(());
  }

  if args.iter().any(|a| a == "--console") {
    return agent_core::run_console(&args).context("run console mode");
  }

  if dry_run {
    eprintln!("DRY-RUN MODE ACTIVE: service mode does not run with --dry-run; exiting cleanly.");
    return Ok(());
  }

  agent_core::service::run_service().context("start Windows Service dispatcher")
}
