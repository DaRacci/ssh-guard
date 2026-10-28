use ssh_guard::config::{self, action::Action, arg::ArgStyle, duration::Duration, rule::Rule};
use std::collections::HashMap;

#[test]
fn test_execute_argv_for_test_accepts_standard_captures() {
    let rule = Rule {
        action: Action::Run {
            binary: "/opt/test/bin/du".into(),
            args: vec!["-d{depth:-1}".into()],
            timeout: Duration::default(),
        },
        command: Some("du".into()),
        implicit_symlinks: true,
        arg_style: ArgStyle::GnuLong,
        flag_groups: vec![],
        flags: vec![],
        args: vec![],
        pre_args: vec![],
        subcommands: vec![],
    };
    let user_argv = vec!["du".to_string(), "/var".to_string()];
    let mut captures = HashMap::new();
    captures.insert("depth".into(), "2".into());

    let built =
        ssh_guard::actions::execute_argv_for_test(&rule, &[], &captures, &user_argv).unwrap();

    assert_eq!(built, vec!["-d2".to_string(), "/var".to_string()]);
}

#[test]
fn test_execute_accepts_standard_captures() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("data.txt");
    std::fs::write(&file_path, "content").unwrap();

    let config = config::Config {
        roots: vec![dir.path().to_string_lossy().to_string()],
        ..Default::default()
    };
    let rule = Rule {
        action: Action::ReadFile {
            path_capture: "path".into(),
            root_set: "roots".into(),
        },
        command: Some("cat".into()),
        implicit_symlinks: true,
        arg_style: ArgStyle::GnuLong,
        flag_groups: vec![],
        flags: vec![],
        args: vec![],
        pre_args: vec![],
        subcommands: vec![],
    };
    let mut captures = HashMap::new();
    captures.insert("path".into(), file_path.to_string_lossy().to_string());

    let result = ssh_guard::actions::execute(&config, &rule, &[], &captures, &[]);

    assert_eq!(result.unwrap(), 0);
}
