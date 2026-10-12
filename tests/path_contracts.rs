use ssh_guard::config::Config;
use ssh_guard::engine::match_command;
use ssh_guard::errors::{GuardError, MatchFailure};
use std::fs::{create_dir_all, write};
use std::path::Path;

fn argv(tokens: &[String]) -> Vec<String> {
    tokens.to_vec()
}

fn token(s: &str) -> String {
    s.to_string()
}

fn toml_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn no_match_failures(err: GuardError) -> Vec<MatchFailure> {
    match err {
        GuardError::NoMatch { failures, .. } => failures,
        other => panic!("expected NoMatch, got {other:?}"),
    }
}

#[test]
fn test_inline_flag_in_flags_matches_inline_value() {
    let cfg: Config = toml::from_str(
        r#"
[contracts.lines]
type = "int_range"
min = 1
max = 10

[[rules]]
command = "tail"
action = { type = "show_help" }
arg_style = "gnu_long"
flags = ["--lines={lines}"]
"#,
    )
    .unwrap();

    let result = match_command(&cfg, &argv(&[token("tail"), token("--lines=3")]));
    assert!(result.is_ok(), "expected --lines=3 to match: {result:?}");
    let matched = result.unwrap();
    assert_eq!(matched.captures.get("lines").map(String::as_str), Some("3"));
}

#[test]
fn test_inline_flag_in_flags_matches_separate_value() {
    let cfg: Config = toml::from_str(
        r#"
[contracts.lines]
type = "int_range"
min = 1
max = 10

[[rules]]
command = "tail"
action = { type = "show_help" }
arg_style = "gnu_long"
flags = ["--lines={lines}"]
"#,
    )
    .unwrap();

    let result = match_command(&cfg, &argv(&[token("tail"), token("--lines"), token("3")]));
    assert!(result.is_ok(), "expected --lines 3 to match: {result:?}");
    let matched = result.unwrap();
    assert_eq!(matched.captures.get("lines").map(String::as_str), Some("3"));
}

#[test]
fn test_path_contract_matches_existing_path_with_spaces_in_roots() {
    let root = tempfile::tempdir().unwrap();
    let file_path = root.path().join("hello world.txt");
    write(&file_path, "ok").unwrap();

    let cfg: Config = toml::from_str(&format!(
        r#"
roots = ["{}"]

[contracts.allowed_path]
type = "path"
root_set = "roots"

[[rules]]
command = "cat"
action = {{ type = "show_help" }}
args = ["{{allowed_path}}"]
"#,
        toml_path(root.path())
    ))
    .unwrap();

    let result = match_command(
        &cfg,
        &argv(&[token("cat"), file_path.to_string_lossy().to_string()]),
    );
    assert!(result.is_ok(), "expected rooted path to match: {result:?}");
    let matched = result.unwrap();
    assert_eq!(
        matched.captures.get("allowed_path").map(String::as_str),
        Some(file_path.to_string_lossy().as_ref())
    );
}

#[test]
fn test_path_contract_rejects_nonexistent_path_by_default() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing.txt");

    let cfg: Config = toml::from_str(&format!(
        r#"
roots = ["{}"]

[contracts.allowed_path]
type = "path"
root_set = "roots"

[[rules]]
command = "cat"
action = {{ type = "show_help" }}
args = ["{{allowed_path}}"]
"#,
        toml_path(root.path())
    ))
    .unwrap();

    let failures = no_match_failures(
        match_command(
            &cfg,
            &argv(&[token("cat"), missing.to_string_lossy().to_string()]),
        )
        .unwrap_err(),
    );
    assert!(
        failures
            .iter()
            .any(|f| f.reason.contains("cannot resolve path")),
        "expected canonicalize failure, got {failures:?}"
    );
}

#[test]
fn test_path_contract_allows_nonexistent_path_when_must_exist_false() {
    let root = tempfile::tempdir().unwrap();
    let target_dir = root.path().join("uploads");
    create_dir_all(&target_dir).unwrap();
    let missing = target_dir.join("new file.txt");

    let cfg: Config = toml::from_str(&format!(
        r#"
roots = ["{}"]

[contracts.output_path]
type = "path"
root_set = "roots"
must_exist = false

[[rules]]
command = "write"
action = {{ type = "show_help" }}
args = ["{{output_path}}"]
"#,
        toml_path(root.path())
    ))
    .unwrap();

    let result = match_command(
        &cfg,
        &argv(&[token("write"), missing.to_string_lossy().to_string()]),
    );
    assert!(
        result.is_ok(),
        "expected missing path under allowed root to match: {result:?}"
    );
    let matched = result.unwrap();
    assert_eq!(
        matched.captures.get("output_path").map(String::as_str),
        Some(missing.to_string_lossy().as_ref())
    );
}

#[test]
fn test_path_contract_rejects_escape_when_must_exist_false() {
    let root = tempfile::tempdir().unwrap();
    let subdir = root.path().join("uploads");
    create_dir_all(&subdir).unwrap();
    let escaped = subdir.join("..").join("..").join("escape.txt");

    let cfg: Config = toml::from_str(&format!(
        r#"
roots = ["{}"]

[contracts.output_path]
type = "path"
root_set = "roots"
must_exist = false

[[rules]]
command = "write"
action = {{ type = "show_help" }}
args = ["{{output_path}}"]
"#,
        toml_path(root.path())
    ))
    .unwrap();

    let failures = no_match_failures(
        match_command(
            &cfg,
            &argv(&[token("write"), escaped.to_string_lossy().to_string()]),
        )
        .unwrap_err(),
    );
    assert!(
        failures
            .iter()
            .any(|f| f.reason.contains("not within any allowed root")),
        "expected root escape rejection, got {failures:?}"
    );
}

#[test]
fn test_path_contract_rejects_broken_symlink_prefix_when_must_exist_false() {
    let root = tempfile::tempdir().unwrap();
    let broken_target = root
        .path()
        .join("..")
        .join("outside")
        .join("missing-target");
    let link_path = root.path().join("broken-link");
    std::os::unix::fs::symlink(&broken_target, &link_path).unwrap();
    let escaped = link_path.join("..").join("evil.txt");

    let cfg: Config = toml::from_str(&format!(
        r#"
roots = ["{}"]

[contracts.output_path]
type = "path"
root_set = "roots"
must_exist = false

[[rules]]
command = "write"
action = {{ type = "show_help" }}
args = ["{{output_path}}"]
"#,
        toml_path(root.path())
    ))
    .unwrap();

    let failures = no_match_failures(
        match_command(
            &cfg,
            &argv(&[token("write"), escaped.to_string_lossy().to_string()]),
        )
        .unwrap_err(),
    );
    assert!(
        failures
            .iter()
            .any(|f| f.reason.contains("cannot resolve path")),
        "expected broken symlink rejection, got {failures:?}"
    );
}

#[test]
fn test_path_contract_unknown_root_set_fails_semantic_validation() {
    let cfg: Config = toml::from_str(
        r#"
[contracts.allowed_path]
type = "path"
root_set = "missing"

[[rules]]
command = "cat"
action = { type = "show_help" }
args = ["{allowed_path}"]
"#,
    )
    .unwrap();

    let err = cfg.validate_semantics().unwrap_err().to_string();
    assert!(err.contains("unknown root set 'missing'"), "got: {err}");
}

#[test]
fn test_profile_path_contract_with_profile_root_set_passes_validation() {
    let cfg: Config = toml::from_str(
        r#"
[[rules]]
command = "help"
action = { type = "show_help" }

[profiles.deploy]
users = ["deploy"]

[profiles.deploy.root_sets]
release = ["/srv/app/releases"]

[profiles.deploy.contracts.release_path]
type = "path"
root_set = "release"

[[profiles.deploy.rules]]
command = "show-release"
action = { type = "show_help" }
args = ["{release_path}"]
"#,
    )
    .unwrap();

    let result = cfg.validate_semantics();
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}
