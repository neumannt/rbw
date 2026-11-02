use crate::prelude::*;

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&cache_dir(), 0o700)?;
    create_dir_all_with_permissions(&runtime_dir(), 0o700)?;
    create_dir_all_with_permissions(&data_dir(), 0o700)?;

    Ok(())
}

fn create_dir_all_with_permissions(
    path: &std::path::Path,
    mode: u32,
) -> Result<()> {
    // ensure the initial directory creation happens with the correct mode,
    // to avoid race conditions
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // but also make sure to forcibly set the mode, in case the directory
    // already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');
pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server =
        percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH)
            .to_string();
    cache_dir().join(format!("{server}:{email}.json"))
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

pub fn ssh_agent_socket_file() -> std::path::PathBuf {
    runtime_dir().join("ssh-agent-socket")
}

fn config_dir() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home_dir().join("Library/Application Support")
    } else {
        xdg_dir("XDG_CONFIG_HOME")
            .unwrap_or_else(|| home_dir().join(".config"))
    }
    .join(project_dir_name())
}

fn cache_dir() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home_dir().join("Library/Caches")
    } else {
        xdg_dir("XDG_CACHE_HOME").unwrap_or_else(|| home_dir().join(".cache"))
    }
    .join(project_dir_name())
}

fn data_dir() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home_dir().join("Library/Application Support")
    } else {
        xdg_dir("XDG_DATA_HOME")
            .unwrap_or_else(|| home_dir().join(".local/share"))
    }
    .join(project_dir_name())
}

fn runtime_dir() -> std::path::PathBuf {
    let runtime_dir = if cfg!(target_os = "macos") {
        None
    } else {
        xdg_dir("XDG_RUNTIME_DIR")
    };
    runtime_dir.map_or_else(
        || {
            format!(
                "{}/{}-{}",
                std::env::temp_dir().to_string_lossy(),
                &profile(),
                rustix::process::getuid().as_raw()
            )
            .into()
        },
        |dir| dir.join(project_dir_name()),
    )
}

// these match the paths previously chosen by the directories crate

fn project_dir_name() -> String {
    let profile = profile();
    if cfg!(target_os = "macos") {
        profile.replace(' ', "-")
    } else {
        profile.split_whitespace().map(str::to_lowercase).collect()
    }
}

// the xdg base directory spec says to ignore relative paths
fn xdg_dir(var: &str) -> Option<std::path::PathBuf> {
    std::env::var_os(var)
        .map(std::path::PathBuf::from)
        .filter(|dir| dir.is_absolute())
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            // falls back to the passwd database, since HOME is unset
            #[allow(deprecated)]
            std::env::home_dir()
        })
        .filter(|home| !home.as_os_str().is_empty())
        .expect("couldn't determine home directory")
}

pub fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(profile) if !profile.is_empty() => format!("rbw-{profile}"),
        _ => "rbw".to_string(),
    }
}
