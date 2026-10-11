use ssh_guard::config::Config;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn examples_root() -> PathBuf {
    repo_root().join("examples")
}

fn example_dirs() -> Vec<PathBuf> {
    let mut dirs = fs::read_dir(examples_root())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    dirs.sort();
    dirs
}

fn root_relative(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap()
        .display()
        .to_string()
}

#[test]
fn all_example_configs_parse_and_semantically_validate() {
    let dirs = example_dirs();
    let mut config_paths = Vec::new();
    for dir in &dirs {
        let readme = dir.join("README.md");
        assert!(
            readme.is_file(),
            "missing README.md in {}",
            root_relative(dir)
        );
        let readme_raw = fs::read_to_string(&readme).unwrap();
        assert!(
            readme_raw.contains("## What it covers"),
            "{} missing '## What it covers' section",
            root_relative(&readme)
        );
        assert!(
            readme_raw.contains("## Account expectations"),
            "{} missing '## Account expectations' section",
            root_relative(&readme)
        );
        config_paths.push(dir.join("config.toml"));
    }

    for config_path in config_paths {
        assert!(
            config_path.is_file(),
            "missing {}",
            root_relative(&config_path)
        );
        let raw = fs::read_to_string(&config_path).unwrap();
        let config: Config = toml::from_str(&raw).unwrap_or_else(|error| {
            panic!("{} failed to parse: {error}", root_relative(&config_path))
        });
        config.validate_semantics().unwrap_or_else(|error| {
            panic!(
                "{} failed semantic validation: {error}",
                root_relative(&config_path)
            )
        });
    }
}
