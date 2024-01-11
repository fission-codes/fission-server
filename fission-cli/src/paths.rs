use directories::ProjectDirs;
use std::path::PathBuf;

pub(crate) fn project_dirs() -> ProjectDirs {
    ProjectDirs::from("", "", "fission-cli")
        .expect("Couldn't find operating-system-specific configuration paths")
}

pub(crate) fn config_file() -> PathBuf {
    project_dirs().config_dir().join("config.toml")
}

pub(crate) fn default_key_file() -> PathBuf {
    project_dirs().config_dir().join("main-private-key.pem")
}

pub(crate) fn http_cache_dir() -> PathBuf {
    project_dirs().cache_dir().join("http-cache")
}
