#![forbid(unsafe_code)]

//! Reimplements `ssk-cli`'s config-loading sequence
//! (`crates/ssk-cli/src/main.rs`'s private `load_config`/`config_format_from_path`)
//! against `ssk-config`'s public API. This duplication is intentional:
//! `load_config` is a private function in the `ssk-cli` *binary* crate, not
//! exported by `ssk-config`, so the daemon cannot literally call it.

use std::path::Path;

use ssk_config::{AppConfig, LoadedConfig};

#[derive(Debug, thiserror::Error)]
pub enum DaemonConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unrecognized config file extension for {0} (expected .yaml, .yml, or .toml)")]
    UnknownFormat(String),
    #[error("config error: {0}")]
    Config(#[from] ssk_config::ConfigError),
}

/// Load and validate the daemon's config. `path: None` yields
/// `AppConfig::default()` (fail-closed defaults), matching `ssk-cli`'s
/// behavior when no `--config` flag is given.
pub fn load_daemon_config(path: Option<&Path>) -> Result<LoadedConfig, DaemonConfigError> {
    let Some(path) = path else {
        return Ok(LoadedConfig {
            config: AppConfig::default(),
            migrated_from: None,
        });
    };

    let content = std::fs::read_to_string(path).map_err(|source| DaemonConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml" | "yml") => Ok(AppConfig::parse_with_migration_yaml(&content)?),
        Some("toml") => Ok(AppConfig::parse_with_migration_toml(&content)?),
        _ => Err(DaemonConfigError::UnknownFormat(path.display().to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_path_yields_valid_defaults() {
        let loaded = load_daemon_config(None).expect("default config must load");
        assert_eq!(loaded.config.version, ssk_config::CURRENT_CONFIG_VERSION);
        assert!(loaded.migrated_from.is_none());
        loaded.config.validate().expect("defaults must validate");
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = load_daemon_config(Some(Path::new("/nonexistent/kaleidoscorp.yaml")))
            .expect_err("missing file must error");
        assert!(matches!(err, DaemonConfigError::Io { .. }));
    }

    #[test]
    fn unknown_extension_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.ini");
        std::fs::write(&path, "version: 2").expect("write");
        let err = load_daemon_config(Some(&path)).expect_err("unknown extension must error");
        assert!(matches!(err, DaemonConfigError::UnknownFormat(_)));
    }

    #[test]
    fn valid_yaml_config_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        let yaml = serde_yaml::to_string(&AppConfig::default()).expect("serialize default");
        std::fs::write(&path, yaml).expect("write");
        let loaded = load_daemon_config(Some(&path)).expect("valid config must load");
        assert_eq!(loaded.config.version, ssk_config::CURRENT_CONFIG_VERSION);
    }
}
