use ssh_guard::config::{
    self, action::Action, arg::ArgStyle, contract::Contract, rule::Rule, subcommand::Subcommand,
};
use ssh_guard::engine::match_command;
use std::collections::HashMap;

/// journalctl-like rule: value flags (-n), standalone flags from a flag group
/// (--no-pager), inline flag (-u {unit}), subcommand-style units.
fn journalctl_config() -> config::Config {
    config::Config {
        global: config::global::Global::default(),
        contracts: {
            let mut c = HashMap::new();
            c.insert(
                "unit".into(),
                Contract::Enum {
                    values: vec!["ssh".into(), "nginx".into()],
                },
            );
            c
        },
        flag_groups: {
            let mut f = HashMap::new();
            f.insert(
                "pager".into(),
                vec!["--no-pager".into(), "--full".into(), "-q".into()],
            );
            f
        },
        rules: vec![
            Rule {
                action: Action::ShowHelp,
                command: Some("journalctl".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec!["pager".into()],
                flags: vec!["-n".into(), "-f".into()],
                args: vec!["{int}".into()],
                pre_args: vec![],
                subcommands: vec![Subcommand {
                    name: "-u".into(),
                    arg_style: None,
                    flag_groups: vec!["pager".into()],
                    flags: vec!["-n".into()],
                    args: vec!["{unit}".into()],
                    pre_args: vec![],
                    subcommands: vec![],
                }],
            },
            Rule {
                action: Action::ShowHelp,
                command: Some("systemctl".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec!["pager".into()],
                flags: vec!["-l".into()],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![Subcommand {
                    name: "status".into(),
                    arg_style: None,
                    flag_groups: vec!["pager".into()],
                    flags: vec!["-l".into()],
                    args: vec!["{string}".into()],
                    pre_args: vec![],
                    subcommands: vec![],
                }],
            },
            // df-like: mixed flags + positional args on one rule
            Rule {
                action: Action::ShowHelp,
                command: Some("df".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec![],
                flags: vec!["-h".into(), "-i".into()],
                args: vec!["{string}".into()],
                pre_args: vec![],
                subcommands: vec![],
            },
        ],
        roots: vec![],
        units: vec![],
        ..Default::default()
    }
}

fn argv(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|s| s.to_string()).collect()
}

#[test]
fn test_journalctl_flag_after_positional() {
    let cfg = journalctl_config();
    // journalctl -n 3 --no-pager
    let result = match_command(&cfg, &argv(&["journalctl", "-n", "3", "--no-pager"]));
    assert!(
        result.is_ok(),
        "journalctl -n 3 --no-pager must match: {result:?}"
    );
}

#[test]
fn test_journalctl_flag_before_value() {
    let cfg = journalctl_config();
    // journalctl --no-pager -n 3
    let result = match_command(&cfg, &argv(&["journalctl", "--no-pager", "-n", "3"]));
    assert!(
        result.is_ok(),
        "journalctl --no-pager -n 3 must match: {result:?}"
    );
}

#[test]
fn test_journalctl_subcommand_then_flags_any_order() {
    let cfg = journalctl_config();
    // journalctl -u ssh -n 5 -q : subcommand, unit arg, then flags after
    let result = match_command(&cfg, &argv(&["journalctl", "-u", "ssh", "-n", "5", "-q"]));
    assert!(
        result.is_ok(),
        "journalctl -u ssh -n 5 -q must match: {result:?}"
    );
    // reversed: flags interleaved before the unit
    let result2 = match_command(&cfg, &argv(&["journalctl", "-u", "-n", "5", "-q", "ssh"]));
    assert!(
        result2.is_ok(),
        "journalctl -u -n 5 -q ssh must match: {result2:?}"
    );
    // captures the unit by contract name regardless of position
    let r = match_command(&cfg, &argv(&["journalctl", "-u", "ssh", "-n", "5", "-q"])).unwrap();
    assert_eq!(r.captures.get("unit").map(String::as_str), Some("ssh"));
    assert_eq!(r.subcommand_path, vec!["-u"]);
}

#[test]
fn test_journalctl_disallowed_flag_denied_in_any_position() {
    let cfg = journalctl_config();
    // -f IS allowlisted; use something that is not: --follow
    let result = match_command(&cfg, &argv(&["journalctl", "-n", "3", "--follow"]));
    assert!(result.is_err(), "--follow must be denied");
    let result2 = match_command(&cfg, &argv(&["journalctl", "--follow", "-n", "3"]));
    assert!(result2.is_err(), "--follow must be denied in any position");
}

#[test]
fn test_systemctl_status_flag_after_unit() {
    let cfg = journalctl_config();
    // systemctl status ssh -l
    let result = match_command(&cfg, &argv(&["systemctl", "status", "ssh", "-l"]));
    assert!(
        result.is_ok(),
        "systemctl status ssh -l must match: {result:?}"
    );
    // and the flag-first order
    let result2 = match_command(&cfg, &argv(&["systemctl", "status", "-l", "ssh"]));
    assert!(
        result2.is_ok(),
        "systemctl status -l ssh must match: {result2:?}"
    );
}

#[test]
fn test_df_flag_then_path_and_path_then_flag() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["df", "-h", "/var"]));
    assert!(result.is_ok(), "df -h /var must match: {result:?}");
    let result2 = match_command(&cfg, &argv(&["df", "/var", "-h"]));
    assert!(result2.is_ok(), "df /var -h must match: {result2:?}");
    // both flags, both orders
    let result3 = match_command(&cfg, &argv(&["df", "-h", "/var", "-i"]));
    assert!(result3.is_ok(), "df -h /var -i must match: {result3:?}");
    let result4 = match_command(&cfg, &argv(&["df", "-i", "/var", "-h"]));
    assert!(result4.is_ok(), "df -i /var -h must match: {result4:?}");
}

#[test]
fn test_df_disallowed_flag_denied() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["df", "/var", "--inodes"]));
    assert!(result.is_err(), "df /var --inodes must be denied");
}
