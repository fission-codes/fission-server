use directories::ProjectDirs;
use std::path::PathBuf;

pub fn project_dirs() -> ProjectDirs {
    ProjectDirs::from("", "", "fission-cli")
        .expect("Couldn't find operating-system-specific configuration paths")
}

pub fn config_file() -> PathBuf {
    project_dirs().config_dir().join("config.toml")
}

pub fn default_key_file() -> PathBuf {
    project_dirs().config_dir().join("main-private-key.pem")
}

pub fn ucans_dir() -> PathBuf {
    project_dirs().config_dir().join("ucans")
}
