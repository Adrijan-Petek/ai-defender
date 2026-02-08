use std::path::Path;

#[cfg(windows)]
pub fn set_low_priority() -> anyhow::Result<()> {
  use windows::Win32::System::Threading::{
    GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS,
  };
  // SAFETY: Calls into Win32 to set the current process priority class.
  // This does not escalate privileges and is scoped to the scanner process.
  unsafe {
    let proc = GetCurrentProcess();
    if SetPriorityClass(proc, BELOW_NORMAL_PRIORITY_CLASS).is_err() {
      return Err(anyhow::anyhow!("SetPriorityClass failed"));
    }
  }
  Ok(())
}

#[cfg(not(windows))]
pub fn set_low_priority() -> anyhow::Result<()> {
  Ok(())
}

#[cfg(windows)]
pub fn fixed_drives() -> Vec<std::path::PathBuf> {
  use windows::Win32::Storage::FileSystem::GetDriveTypeW;
  use windows::core::PCWSTR;
  let mut out = Vec::new();
  const DRIVE_FIXED_U32: u32 = 3;
  for letter in b'C'..=b'Z' {
    let root = format!("{}:\\", letter as char);
    let wide: Vec<u16> = root.encode_utf16().chain([0]).collect();
    // SAFETY: `wide` is null-terminated.
    let t = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };
    if t == DRIVE_FIXED_U32 {
      out.push(std::path::PathBuf::from(root));
    }
  }
  out
}

#[cfg(not(windows))]
pub fn fixed_drives() -> Vec<std::path::PathBuf> {
  vec![std::path::PathBuf::from("/")]
}

#[cfg(windows)]
pub fn is_trusted_signed(path: &Path) -> anyhow::Result<bool> {
  use std::ffi::OsStr;
  use std::os::windows::ffi::OsStrExt;
  use windows::core::GUID;
  use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HWND, PWSTR};
  use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WTD_CACHE_ONLY_URL_RETRIEVAL, WINTRUST_DATA_UICONTEXT,
  };

  // SAFETY: WinVerifyTrust requires Win32 structs and pointers. We keep this isolated.
  let wide: Vec<u16> = OsStr::new(path)
    .encode_wide()
    .chain(std::iter::once(0))
    .collect();

  let mut file_info = WINTRUST_FILE_INFO {
    cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
    pcwszFilePath: windows::core::PCWSTR(wide.as_ptr()),
    hFile: HANDLE::default(),
    pgKnownSubject: std::ptr::null_mut(),
  };

  let mut data = WINTRUST_DATA {
    cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
    pPolicyCallbackData: std::ptr::null_mut(),
    pSIPClientData: std::ptr::null_mut(),
    dwUIChoice: WTD_UI_NONE,
    fdwRevocationChecks: WTD_REVOKE_NONE,
    dwUnionChoice: WTD_CHOICE_FILE,
    Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
    dwStateAction: WTD_STATEACTION_VERIFY,
    hWVTStateData: HANDLE::default(),
    pwszURLReference: PWSTR::null(),
    // Offline-first: do not allow URL retrieval during signature verification.
    dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
    dwUIContext: WINTRUST_DATA_UICONTEXT(0),
    pSignatureSettings: std::ptr::null_mut(),
  };

  let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  let status = unsafe { WinVerifyTrust(HWND(0), &mut action, &mut data as *mut _ as *mut _) };

  // Close state data if created.
  data.dwStateAction = WTD_STATEACTION_CLOSE;
  let _ = unsafe { WinVerifyTrust(HWND(0), &mut action, &mut data as *mut _ as *mut _) };

  Ok(status == ERROR_SUCCESS.0 as i32)
}

#[cfg(not(windows))]
pub fn is_trusted_signed(_path: &Path) -> anyhow::Result<bool> {
  Ok(false)
}
