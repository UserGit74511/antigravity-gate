//! Antigravity IDE patching and account eligibility module.

use std::fs;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::Command;

// Protobuf string signature gating regional and account access
pub const INELIGIBLE_FROM: &[u8] = b"ineligible";
pub const INELIGIBLE_TO: &[u8] = b"inexigible";

// Redirect language server proxy lookups to an isolated variable
pub const PROXY_VAR_FROM: &[u8] = b"https_proxy";
pub const PROXY_VAR_TO: &[u8] = b"AG_LS_PROXY";

pub const BACKUP_SUFFIX: &str = ".bak";
pub const TEMP_SUFFIX: &str = ".agtmp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetStatus {
    Patched,
    Unpatched,
    SignatureMissing,
    NotFound,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct BinaryReport {
    pub path: PathBuf,
    pub status: TargetStatus,
    pub proxy_renamed: bool,
    pub backup_present: bool,
}

#[derive(Debug, Clone)]
pub struct PatchReport {
    pub path: PathBuf,
    pub eligibility_replaced: usize,
    pub proxy_replaced: usize,
    pub backup_created: bool,
    pub restored_from_backup: bool,
}

pub fn replace_all(data: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    assert_eq!(
        from.len(),
        to.len(),
        "Pattern and replacement must have equal length"
    );
    if data.len() < from.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + from.len() <= data.len() {
        if &data[i..i + from.len()] == from {
            data[i..i + to.len()].copy_from_slice(to);
            count += 1;
            i += from.len();
        } else {
            i += 1;
        }
    }
    count
}

pub fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if haystack.len() < needle.len() {
        return 0;
    }
    (0..=haystack.len() - needle.len())
        .filter(|&i| &haystack[i..i + needle.len()] == needle)
        .count()
}

pub fn backup_path_for(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

pub fn temp_path_for(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(format!(".{}{}", std::process::id(), TEMP_SUFFIX));
    PathBuf::from(s)
}

pub fn kill_holder_if_needed(target: &Path) {
    let Some(file_name) = target.file_name().and_then(|n| n.to_str()) else {
        return;
    };

    #[cfg(target_os = "windows")]
    {
        use std::process::Stdio;
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", file_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Stdio;
        let _ = Command::new("pkill")
            .args(["-f", file_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub fn write_atomic(target: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = temp_path_for(target);
    if let Err(e) = fs::write(&tmp, data) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(target) {
            let mode = meta.permissions().mode();
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
        }
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        if let Ok(meta) = fs::metadata(target) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(target, perms);
            }
        }
    }

    match fs::rename(&tmp, target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn discover_antigravity_installs(custom_path: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(custom) = custom_path {
        if custom.exists() {
            dirs.push(custom.to_path_buf());
        }
        return dirs;
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(local_app_data)
                .join("Programs")
                .join("antigravity");
            if p.exists() {
                dirs.push(p);
            }
        }
        if let Ok(program_files) = std::env::var("ProgramFiles") {
            let p = PathBuf::from(program_files).join("Antigravity");
            if p.exists() && !dirs.contains(&p) {
                dirs.push(p);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let p = PathBuf::from("/Applications/Antigravity.app");
        if p.exists() {
            dirs.push(p);
        }
    }

    #[cfg(target_os = "linux")]
    {
        for path in &["/usr/share/antigravity", "/opt/antigravity"] {
            let p = PathBuf::from(path);
            if p.exists() {
                dirs.push(p);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join(".local/share/antigravity");
            if p.exists() {
                dirs.push(p);
            }
        }
    }

    dirs
}

pub fn find_binaries_in_install(install_dir: &Path) -> Vec<PathBuf> {
    let mut targets = Vec::new();

    if install_dir.is_file() {
        targets.push(install_dir.to_path_buf());
        return targets;
    }

    let candidates = [
        install_dir.join("language_server.exe"),
        install_dir.join("language_server"),
        install_dir
            .join("resources")
            .join("bin")
            .join("language_server.exe"),
        install_dir
            .join("resources")
            .join("bin")
            .join("language_server"),
        install_dir
            .join("resources")
            .join("app")
            .join("extensions")
            .join("antigravity")
            .join("bin")
            .join("language_server_windows_x64.exe"),
        install_dir
            .join("resources")
            .join("app")
            .join("extensions")
            .join("antigravity")
            .join("bin")
            .join("language_server.exe"),
        install_dir.join("agy.exe"),
        install_dir.join("agy"),
    ];

    for c in candidates {
        if c.exists() && !targets.contains(&c) {
            targets.push(c);
        }
    }

    let scan_dirs = [
        install_dir.to_path_buf(),
        install_dir.join("resources").join("bin"),
        install_dir
            .join("resources")
            .join("app")
            .join("extensions")
            .join("antigravity")
            .join("bin"),
    ];

    for dir in scan_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("language_server")
                        && !name.ends_with(BACKUP_SUFFIX)
                        && !name.ends_with(TEMP_SUFFIX)
                        && path.is_file()
                        && !targets.contains(&path)
                    {
                        targets.push(path);
                    }
                }
            }
        }
    }

    targets
}

pub fn inspect_binary(path: &Path) -> BinaryReport {
    let backup_present = backup_path_for(path).exists();

    if !path.exists() {
        return BinaryReport {
            path: path.to_path_buf(),
            status: TargetStatus::NotFound,
            proxy_renamed: false,
            backup_present,
        };
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return BinaryReport {
                path: path.to_path_buf(),
                status: TargetStatus::Error(e.to_string()),
                proxy_renamed: false,
                backup_present,
            }
        }
    };

    let has_patched = count_occurrences(&data, INELIGIBLE_TO) > 0;
    let has_unpatched = count_occurrences(&data, INELIGIBLE_FROM) > 0;
    let proxy_renamed = count_occurrences(&data, PROXY_VAR_TO) > 0;

    let status = if has_patched {
        TargetStatus::Patched
    } else if has_unpatched {
        TargetStatus::Unpatched
    } else {
        TargetStatus::SignatureMissing
    };

    BinaryReport {
        path: path.to_path_buf(),
        status,
        proxy_renamed,
        backup_present,
    }
}

pub fn patch_binary(path: &Path) -> io::Result<PatchReport> {
    if !path.exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("Target binary not found: {}", path.display()),
        ));
    }

    kill_holder_if_needed(path);
    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut data = fs::read(path)?;

    let bak = backup_path_for(path);
    let mut backup_created = false;
    if !bak.exists() {
        fs::copy(path, &bak)?;
        backup_created = true;
    }

    let eligibility_replaced = replace_all(&mut data, INELIGIBLE_FROM, INELIGIBLE_TO);
    let proxy_replaced = replace_all(&mut data, PROXY_VAR_FROM, PROXY_VAR_TO);

    if eligibility_replaced == 0 && count_occurrences(&data, INELIGIBLE_TO) == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Eligibility signature 'ineligible' not found in binary",
        ));
    }

    write_atomic(path, &data)?;

    Ok(PatchReport {
        path: path.to_path_buf(),
        eligibility_replaced,
        proxy_replaced,
        backup_created,
        restored_from_backup: false,
    })
}

pub fn unpatch_binary(path: &Path) -> io::Result<PatchReport> {
    kill_holder_if_needed(path);
    std::thread::sleep(std::time::Duration::from_millis(100));

    let bak = backup_path_for(path);
    if bak.exists() {
        let bak_data = fs::read(&bak)?;
        write_atomic(path, &bak_data)?;
        let _ = fs::remove_file(&bak);
        return Ok(PatchReport {
            path: path.to_path_buf(),
            eligibility_replaced: 0,
            proxy_replaced: 0,
            backup_created: false,
            restored_from_backup: true,
        });
    }

    if !path.exists() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("Target binary not found: {}", path.display()),
        ));
    }

    let mut data = fs::read(path)?;
    let eligibility_replaced = replace_all(&mut data, INELIGIBLE_TO, INELIGIBLE_FROM);
    let proxy_replaced = replace_all(&mut data, PROXY_VAR_TO, PROXY_VAR_FROM);

    if eligibility_replaced == 0 && count_occurrences(&data, INELIGIBLE_FROM) == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Patched signature 'inexigible' not found in binary",
        ));
    }

    write_atomic(path, &data)?;

    Ok(PatchReport {
        path: path.to_path_buf(),
        eligibility_replaced,
        proxy_replaced,
        backup_created: false,
        restored_from_backup: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_all_basic() {
        let mut buffer = b"hello ineligible and https_proxy test".to_vec();
        let replaced_elig = replace_all(&mut buffer, INELIGIBLE_FROM, INELIGIBLE_TO);
        assert_eq!(replaced_elig, 1);
        assert!(buffer.windows(10).any(|w| w == INELIGIBLE_TO));
        assert!(!buffer.windows(10).any(|w| w == INELIGIBLE_FROM));

        let replaced_proxy = replace_all(&mut buffer, PROXY_VAR_FROM, PROXY_VAR_TO);
        assert_eq!(replaced_proxy, 1);
        assert!(buffer.windows(11).any(|w| w == PROXY_VAR_TO));
        assert!(!buffer.windows(11).any(|w| w == PROXY_VAR_FROM));
    }

    #[test]
    fn test_patch_and_unpatch_flow() {
        let temp_dir = std::env::temp_dir().join(format!("ag_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let test_bin = temp_dir.join("mock_language_server.exe");

        let initial_data = b"prefix ineligible middle https_proxy suffix".to_vec();
        fs::write(&test_bin, &initial_data).unwrap();

        let report = inspect_binary(&test_bin);
        assert_eq!(report.status, TargetStatus::Unpatched);
        assert!(!report.proxy_renamed);
        assert!(!report.backup_present);

        let patch_res = patch_binary(&test_bin).unwrap();
        assert_eq!(patch_res.eligibility_replaced, 1);
        assert_eq!(patch_res.proxy_replaced, 1);
        assert!(patch_res.backup_created);

        let report_after = inspect_binary(&test_bin);
        assert_eq!(report_after.status, TargetStatus::Patched);
        assert!(report_after.proxy_renamed);
        assert!(report_after.backup_present);

        let unpatch_res = unpatch_binary(&test_bin).unwrap();
        assert!(unpatch_res.restored_from_backup);

        let report_reverted = inspect_binary(&test_bin);
        assert_eq!(report_reverted.status, TargetStatus::Unpatched);
        assert!(!report_reverted.proxy_renamed);
        assert!(!report_reverted.backup_present);

        let restored_bytes = fs::read(&test_bin).unwrap();
        assert_eq!(restored_bytes, initial_data);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
