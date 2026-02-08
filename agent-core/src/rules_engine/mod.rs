mod engine;
pub mod protected_paths;
pub mod rules;

pub use engine::Engine;

pub fn active_rule_ids() -> &'static [&'static str] {
  rules::ACTIVE_RULE_IDS
}
