use ssh_guard::config;
use ssh_guard::engine::match_command;

/// journalctl-like rule: value flags (-n), standalone flags from a flag group
/// (--no-pager), inline flag (-u {unit}), subcommand-style units.
fn journalctl_config() -> config::Config {
    let value = toml::toml! {
        [[rules]]
        action = { type = "show_help" }
        command = "journalctl"
        implicit_symlinks = true
        arg_style = "gnu_long"
        flag_groups = ["pager"]
        flags = ["-n", "-f"]
        args = ["{int}"]

        [[rules.subcommands]]
        name = "-u"
        arg_style = "gnu_long"
        flag_groups = ["pager"]
        flags = ["-n"]
        args = ["{unit}"]

        [[rules]]
        action = { type = "show_help" }
        command = "systemctl"
        implicit_symlinks = true
        arg_style = "gnu_long"
        flag_groups = ["pager"]
        flags = ["-l"]

        [[rules.subcommands]]
        name = "status"
        arg_style = "gnu_long"
        flag_groups = ["pager"]
        flags = ["-l"]
        args = ["{string}"]

        [[rules]]
        action = { type = "show_help" }
        command = "df"
        implicit_symlinks = true
        arg_style = "gnu_long"
        flags = ["-h", "-i"]
        args = ["{string}"]

        [contracts.unit]
        type = "enum"
        values = ["ssh", "nginx"]

        [flag_groups]
        pager = ["--no-pager", "--full", "-q"]
    };
    let cfg: config::Config = value.try_into().unwrap();
    cfg
}

fn argv(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|s| s.to_string()).collect()
}

#[test]
fn test_journalctl_flag_after_positional() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["journalctl", "-n", "3", "--no-pager"]));
    assert!(
        result.is_ok(),
        "journalctl -n 3 --no-pager must match: {result:?}"
    );
}

#[test]
fn test_journalctl_flag_before_value() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["journalctl", "--no-pager", "-n", "3"]));
    assert!(
        result.is_ok(),
        "journalctl --no-pager -n 3 must match: {result:?}"
    );
}

#[test]
fn test_journalctl_subcommand_then_flags_any_order() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["journalctl", "-u", "ssh", "-n", "5", "-q"]));
    assert!(
        result.is_ok(),
        "journalctl -u ssh -n 5 -q must match: {result:?}"
    );
    let result2 = match_command(&cfg, &argv(&["journalctl", "-u", "-n", "5", "-q", "ssh"]));
    assert!(
        result2.is_ok(),
        "journalctl -u -n 5 -q ssh must match: {result2:?}"
    );
    let r = match_command(&cfg, &argv(&["journalctl", "-u", "ssh", "-n", "5", "-q"])).unwrap();
    assert_eq!(r.captures.get("unit").map(String::as_str), Some("ssh"));
    assert_eq!(r.subcommand_path, vec!["-u"]);
}

#[test]
fn test_journalctl_disallowed_flag_denied_in_any_position() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["journalctl", "-n", "3", "--follow"]));
    assert!(result.is_err(), "--follow must be denied");
    let result2 = match_command(&cfg, &argv(&["journalctl", "--follow", "-n", "3"]));
    assert!(result2.is_err(), "--follow must be denied in any position");
}

#[test]
fn test_systemctl_status_flag_after_unit() {
    let cfg = journalctl_config();
    let result = match_command(&cfg, &argv(&["systemctl", "status", "ssh", "-l"]));
    assert!(
        result.is_ok(),
        "systemctl status ssh -l must match: {result:?}"
    );
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
