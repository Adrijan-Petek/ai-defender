use crate::config::Config;

use super::engine::ProtectedTarget;

pub fn classify_protected_target(cfg: &Config, file_path: &str) -> Option<ProtectedTarget> {
  let p = file_path.to_ascii_lowercase();

  let local = std::env::var("LOCALAPPDATA")
    .unwrap_or_else(|_| "C:\\Users\\User\\AppData\\Local".to_string())
    .to_ascii_lowercase();
  let roam = std::env::var("APPDATA")
    .unwrap_or_else(|_| "C:\\Users\\User\\AppData\\Roaming".to_string())
    .to_ascii_lowercase();

  let chrome_base = chrome_user_data_root(&local);
  let edge_base = edge_user_data_root(&local);
  let brave_base = brave_user_data_root(&local);
  let firefox_base = firefox_profiles_root(&roam);

  if p.starts_with(&chrome_base) || p.starts_with(&edge_base) || p.starts_with(&brave_base) {
    for name in &cfg.protected.chrome_targets {
      let n = name.to_ascii_lowercase();
      if p.ends_with(&format!("\\{n}")) || p.ends_with(&format!("/{n}")) {
        return match n.as_str() {
          "login data" => Some(ProtectedTarget::ChromeLoginData),
          "cookies" => Some(ProtectedTarget::ChromeCookies),
          "local state" => Some(ProtectedTarget::ChromeLocalState),
          _ => None,
        };
      }
    }
  }

  if p.starts_with(&firefox_base) {
    for name in &cfg.protected.firefox_targets {
      let n = name.to_ascii_lowercase();
      if p.ends_with(&format!("\\{n}")) || p.ends_with(&format!("/{n}")) {
        return match n.as_str() {
          "logins.json" => Some(ProtectedTarget::FirefoxLoginsJson),
          "key4.db" => Some(ProtectedTarget::FirefoxKey4Db),
          "cookies.sqlite" => Some(ProtectedTarget::FirefoxCookiesSqlite),
          _ => None,
        };
      }
    }
  }

  None
}

pub fn is_under_protected_root(file_path: &str) -> bool {
  let p = file_path.to_ascii_lowercase();
  let local = std::env::var("LOCALAPPDATA")
    .unwrap_or_else(|_| "C:\\Users\\User\\AppData\\Local".to_string())
    .to_ascii_lowercase();
  let roam = std::env::var("APPDATA")
    .unwrap_or_else(|_| "C:\\Users\\User\\AppData\\Roaming".to_string())
    .to_ascii_lowercase();

  let chrome_base = chrome_user_data_root(&local);
  let edge_base = edge_user_data_root(&local);
  let brave_base = brave_user_data_root(&local);
  let firefox_base = firefox_profiles_root(&roam);

  p.starts_with(&chrome_base)
    || p.starts_with(&edge_base)
    || p.starts_with(&brave_base)
    || p.starts_with(&firefox_base)
}

fn chrome_user_data_root(localappdata_lower: &str) -> String {
  format!("{localappdata_lower}\\google\\chrome\\user data\\")
}

fn edge_user_data_root(localappdata_lower: &str) -> String {
  format!("{localappdata_lower}\\microsoft\\edge\\user data\\")
}

fn brave_user_data_root(localappdata_lower: &str) -> String {
  format!("{localappdata_lower}\\bravesoftware\\brave-browser\\user data\\")
}

fn firefox_profiles_root(appdata_lower: &str) -> String {
  format!("{appdata_lower}\\mozilla\\firefox\\profiles\\")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classify_chrome_login_data() {
    std::env::set_var("LOCALAPPDATA", "C:\\Users\\Me\\AppData\\Local");
    std::env::set_var("APPDATA", "C:\\Users\\Me\\AppData\\Roaming");
    let cfg = crate::config::Config::default();
    let p = "C:\\Users\\Me\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
    let t = classify_protected_target(&cfg, p);
    assert!(matches!(t, Some(ProtectedTarget::ChromeLoginData)));
  }

  #[test]
  fn classify_firefox_key4() {
    std::env::set_var("LOCALAPPDATA", "C:\\Users\\Me\\AppData\\Local");
    std::env::set_var("APPDATA", "C:\\Users\\Me\\AppData\\Roaming");
    let cfg = crate::config::Config::default();
    let p = "C:\\Users\\Me\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abcd.default\\key4.db";
    let t = classify_protected_target(&cfg, p);
    assert!(matches!(t, Some(ProtectedTarget::FirefoxKey4Db)));
  }
}
