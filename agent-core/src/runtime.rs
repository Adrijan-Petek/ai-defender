use std::sync::atomic::{AtomicBool, Ordering};

static DRY_RUN: AtomicBool = AtomicBool::new(false);

pub fn configure_from_args(args: &[String]) -> bool {
  let enabled = args.iter().any(|arg| arg == "--dry-run");
  set_dry_run(enabled);
  enabled
}

pub fn set_dry_run(enabled: bool) {
  DRY_RUN.store(enabled, Ordering::SeqCst);
}

pub fn is_dry_run() -> bool {
  DRY_RUN.load(Ordering::SeqCst)
}
