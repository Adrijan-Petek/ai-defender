use super::{FIREWALL_RULE_GROUP, RULE_IN_NAME, RULE_OUT_NAME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
  Com,
  NetshFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallRuleStatus {
  pub outbound_ok: bool,
  pub inbound_ok: bool,
  pub backend: FirewallBackend,
}

pub fn enable_rules() -> anyhow::Result<FirewallBackend> {
  #[cfg(windows)]
  {
    match com::enable_rules() {
      Ok(()) => Ok(FirewallBackend::Com),
      Err(e) => {
        // Only fall back when COM initialization/activation is unavailable.
        // For access-denied or other errors, fallback likely won't help and could reduce clarity.
        let msg = e.to_string();
        if msg.starts_with("COM unavailable:") {
          netsh::enable_rules()?;
          return Ok(FirewallBackend::NetshFallback);
        }
        Err(e)
      }
    }
  }
  #[cfg(not(windows))]
  {
    Err(anyhow::anyhow!("kill switch is only supported on Windows"))
  }
}

pub fn disable_rules() -> anyhow::Result<FirewallBackend> {
  #[cfg(windows)]
  {
    match com::disable_rules() {
      Ok(()) => Ok(FirewallBackend::Com),
      Err(e) => {
        let msg = e.to_string();
        if msg.starts_with("COM unavailable:") {
          netsh::disable_rules()?;
          return Ok(FirewallBackend::NetshFallback);
        }
        Err(e)
      }
    }
  }
  #[cfg(not(windows))]
  {
    Err(anyhow::anyhow!("kill switch is only supported on Windows"))
  }
}

pub fn rules_status() -> anyhow::Result<FirewallRuleStatus> {
  #[cfg(windows)]
  {
    match com::rules_status() {
      Ok(st) => Ok(FirewallRuleStatus {
        outbound_ok: st.outbound_ok,
        inbound_ok: st.inbound_ok,
        backend: FirewallBackend::Com,
      }),
      Err(e) => {
        let msg = e.to_string();
        if msg.starts_with("COM unavailable:") {
          let st = netsh::rules_status()?;
          return Ok(FirewallRuleStatus {
            outbound_ok: st.outbound_ok,
            inbound_ok: st.inbound_ok,
            backend: FirewallBackend::NetshFallback,
          });
        }
        Err(e)
      }
    }
  }
  #[cfg(not(windows))]
  {
    Err(anyhow::anyhow!("kill switch is only supported on Windows"))
  }
}

#[cfg(windows)]
mod com {
  use super::*;
  use windows::core::{BSTR, ComInterface, Result as WinResult};
  use windows::Win32::Foundation::{
    E_ACCESSDENIED, ERROR_FILE_NOT_FOUND, HRESULT_FROM_WIN32, VARIANT_TRUE,
  };
  use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIRECTION_IN,
    NET_FW_RULE_DIRECTION_OUT,
  };
  use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
  };

  pub fn enable_rules() -> anyhow::Result<()> {
    with_com(|| {
      let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }?;
      let rules = policy.Rules()?;

      ensure_rule(&rules, RULE_OUT_NAME, NET_FW_RULE_DIRECTION_OUT)?;
      ensure_rule(&rules, RULE_IN_NAME, NET_FW_RULE_DIRECTION_IN)?;

      Ok(())
    })
  }

  pub fn disable_rules() -> anyhow::Result<()> {
    with_com(|| {
      let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }?;
      let rules = policy.Rules()?;

      remove_rule_if_ours(&rules, RULE_OUT_NAME)?;
      remove_rule_if_ours(&rules, RULE_IN_NAME)?;

      Ok(())
    })
  }

  pub fn rules_status() -> anyhow::Result<FirewallRuleStatus> {
    with_com(|| {
      let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }?;
      let rules = policy.Rules()?;

      let out_ok = is_rule_ours(&rules, RULE_OUT_NAME).unwrap_or(false);
      let in_ok = is_rule_ours(&rules, RULE_IN_NAME).unwrap_or(false);

      Ok(FirewallRuleStatus {
        outbound_ok: out_ok,
        inbound_ok: in_ok,
        backend: FirewallBackend::Com,
      })
    })
  }

  fn with_com<T>(f: impl FnOnce() -> WinResult<T>) -> anyhow::Result<T> {
    // SAFETY: Windows Firewall management is exposed via COM APIs. `CoInitializeEx`,
    // `CoUninitialize`, and `CoCreateInstance` require `unsafe` calls in the Windows bindings.
    // We keep the unsafe surface minimal and scoped.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
      .map_err(|e| anyhow::anyhow!("COM unavailable: CoInitializeEx failed: {e:?}"))?;
    let _guard = ComGuard;
    let res = f().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(res)
  }

  struct ComGuard;
  impl Drop for ComGuard {
    fn drop(&mut self) {
      unsafe { CoUninitialize() };
    }
  }

  fn ensure_rule(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    name: &str,
    direction: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIRECTION,
  ) -> WinResult<()> {
    match rules.Item(&BSTR::from(name)) {
      Ok(rule) => {
        // Ownership check: never modify a rule not in our group.
        let grouping = rule.Grouping()?;
        if grouping.to_string() != FIREWALL_RULE_GROUP {
          return Err(windows::core::Error::new(
            E_ACCESSDENIED,
            "rule name collision (not in AI_DEFENDER_KILLSWITCH group)".into(),
          ));
        }
        apply_rule_properties(&rule, name, direction)?;
        Ok(())
      }
      Err(e) => {
        let not_found = e.code() == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND.0);
        if !not_found {
          return Err(e);
        }
        let rule: INetFwRule =
          unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }?;
        apply_rule_properties(&rule, name, direction)?;
        rules.Add(&rule)?;
        Ok(())
      }
    }
  }

  fn apply_rule_properties(
    rule: &INetFwRule,
    name: &str,
    direction: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIRECTION,
  ) -> WinResult<()> {
    rule.put_Name(&BSTR::from(name))?;
    rule.put_Grouping(&BSTR::from(FIREWALL_RULE_GROUP))?;
    rule.put_Enabled(VARIANT_TRUE)?;
    rule.put_Action(NET_FW_ACTION_BLOCK)?;
    rule.put_Direction(direction)?;
    rule.put_Profiles(NET_FW_PROFILE2_ALL.0 as i32)?;
    rule.put_Protocol(NET_FW_IP_PROTOCOL_ANY.0 as i32)?;
    rule.put_LocalAddresses(&BSTR::from("*"))?;
    rule.put_RemoteAddresses(&BSTR::from("*"))?;
    rule.put_Description(&BSTR::from(
      "AI Defender: emergency network kill switch (blocks all inbound+outbound).",
    ))?;
    Ok(())
  }

  fn is_rule_ours(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    name: &str,
  ) -> WinResult<bool> {
    let rule = match rules.Item(&BSTR::from(name)) {
      Ok(r) => r,
      Err(e) => {
        let not_found = e.code() == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND.0);
        if not_found {
          return Ok(false);
        }
        return Err(e);
      }
    };
    let grouping = rule.Grouping()?;
    Ok(grouping.to_string() == FIREWALL_RULE_GROUP)
  }

  fn remove_rule_if_ours(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    name: &str,
  ) -> WinResult<()> {
    let rule = match rules.Item(&BSTR::from(name)) {
      Ok(r) => r,
      Err(e) => {
        let not_found = e.code() == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND.0);
        if not_found {
          return Ok(());
        }
        return Err(e);
      }
    };

    let grouping = rule.Grouping()?;
    if grouping.to_string() != FIREWALL_RULE_GROUP {
      // Not ours; do not delete.
      return Ok(());
    }

    let _ = rules.Remove(&BSTR::from(name));
    Ok(())
  }
}

#[cfg(windows)]
mod netsh {
  use super::*;
  use std::process::Command;

  pub fn enable_rules() -> anyhow::Result<()> {
    // Idempotent: remove only our two rules first, then add exactly two rules.
    let _ = disable_rules();

    netsh(&[
      "advfirewall",
      "firewall",
      "add",
      "rule",
      &format!("name={RULE_OUT_NAME}"),
      "dir=out",
      "action=block",
      "program=any",
      "protocol=any",
      "profile=any",
      "localip=any",
      "remoteip=any",
      &format!("group={FIREWALL_RULE_GROUP}"),
      "enable=yes",
    ])?;

    netsh(&[
      "advfirewall",
      "firewall",
      "add",
      "rule",
      &format!("name={RULE_IN_NAME}"),
      "dir=in",
      "action=block",
      "program=any",
      "protocol=any",
      "profile=any",
      "localip=any",
      "remoteip=any",
      &format!("group={FIREWALL_RULE_GROUP}"),
      "enable=yes",
    ])?;

    Ok(())
  }

  pub fn disable_rules() -> anyhow::Result<()> {
    // Remove only our known rules. Never touch any other rule names.
    let _ = netsh(&[
      "advfirewall",
      "firewall",
      "delete",
      "rule",
      &format!("name={RULE_OUT_NAME}"),
      &format!("group={FIREWALL_RULE_GROUP}"),
    ]);
    let _ = netsh(&[
      "advfirewall",
      "firewall",
      "delete",
      "rule",
      &format!("name={RULE_IN_NAME}"),
      &format!("group={FIREWALL_RULE_GROUP}"),
    ]);
    Ok(())
  }

  pub fn rules_status() -> anyhow::Result<FirewallRuleStatus> {
    let out_ok = has_rule(RULE_OUT_NAME)?;
    let in_ok = has_rule(RULE_IN_NAME)?;
    Ok(FirewallRuleStatus {
      outbound_ok: out_ok,
      inbound_ok: in_ok,
      backend: FirewallBackend::NetshFallback,
    })
  }

  fn has_rule(name: &str) -> anyhow::Result<bool> {
    // Best-effort: netsh output is locale-dependent; we only use this as a fallback.
    let output = Command::new("netsh")
      .args([
        "advfirewall",
        "firewall",
        "show",
        "rule",
        &format!("name={name}"),
        &format!("group={FIREWALL_RULE_GROUP}"),
      ])
      .output()?;

    if !output.status.success() {
      return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(name))
  }

  fn netsh(args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("netsh").args(args).output()?;
    if !output.status.success() {
      let stderr = String::from_utf8_lossy(&output.stderr);
      let stdout = String::from_utf8_lossy(&output.stdout);
      return Err(anyhow::anyhow!(
        "netsh failed ({}): stdout='{}' stderr='{}'",
        output.status,
        stdout.trim(),
        stderr.trim()
      ));
    }
    Ok(())
  }
}
