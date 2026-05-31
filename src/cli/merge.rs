use crate::config::{
    Config, action::Action, arg::ArgStyle, duration::Duration, rule::Rule, subcommand::Subcommand,
};
use crate::errors::GuardError;

/// Merge a new command into the config via the add-rule subcommand.
///
/// Walks the argv to distinguish flags (--since, -n) from real subcommands
/// (status, log, remote). Flags and their values are merged into the rule or
/// subcommand level where they appear. Subcommand names are matched against
/// existing subcommand entries and created if missing.
pub fn add_rule(config_path: &str, cmd_input: &str) -> Result<(), GuardError> {
    let argv = shlex::split(cmd_input)
        .ok_or_else(|| GuardError::Config("failed to parse command".into()))?;

    if argv.is_empty() {
        return Err(GuardError::Config("empty command".into()));
    }

    let binary_name = &argv[0];
    let mut config = Config::from_file(config_path)?;

    // Find or create the rule for this binary
    let rule = find_or_create_rule(&mut config.rules, binary_name);

    // Walk remaining tokens: flags → rule, first non-flag → subcommand
    walk_and_merge(rule, &argv[1..]);

    // Auto-create flag groups if applicable
    auto_create_flag_groups(&mut config, binary_name);

    config.write_to_file(config_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::action::Action;

    fn create_config(toml_content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test.toml");
        std::fs::write(&config_path, toml_content).unwrap();
        let path_str = config_path.to_str().unwrap().to_string();
        (dir, path_str)
    }

    fn minimal_config() -> (tempfile::TempDir, String) {
        create_config(
            r#"
[[rules]]
action = { type = "show_help" }
"#,
        )
    }

    fn find_rule<'a>(rules: &'a [Rule], name: &str) -> Option<&'a Rule> {
        rules.iter().find(|r| {
            matches!(&r.action, Action::Run { binary, .. } if binary.ends_with(&format!("/{name}")) || binary == name)
        })
    }

    /// Basic: add first rule to empty config.
    #[test]
    fn test_add_first_rule() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "journalctl --no-pager -n 10").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "journalctl").unwrap();

        assert_eq!(rule.flags, vec!["--no-pager", "-n"]);
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    /// Basic: rule with subcommand and positional arg.
    #[test]
    fn test_add_rule_with_subcommand() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "systemctl status angrr").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert_eq!(rule.subcommands[0].args, vec!["angrr"]);
        assert!(rule.subcommands[0].flags.is_empty());
    }

    /// Dedup: existing flag not duplicated; new flag added; subcommand + arg created.
    /// Use `-n 10` as last flag so "status" isn't consumed as flag value.
    #[test]
    fn test_add_to_existing_rule_dedup_flags() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/systemctl" }
flags = ["--no-pager"]
"#,
        );
        add_rule(&path, "systemctl --no-pager --full -n 10 status sshd").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        // --no-pager appears once; --full and -n are new
        assert_eq!(rule.flags, vec!["--no-pager", "--full", "-n"]);
        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert_eq!(rule.subcommands[0].args, vec!["sshd"]);
    }

    /// New subcommand added alongside existing one.
    #[test]
    fn test_add_new_subcommand_to_existing_rule() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/systemctl" }

[[rules.subcommands]]
name = "status"
args = ["sshd"]
"#,
        );
        add_rule(&path, "systemctl show sshd").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 2);
        // status untouched
        assert_eq!(rule.subcommands[0].name, "status");
        assert_eq!(rule.subcommands[0].args, vec!["sshd"]);
        // show added
        assert_eq!(rule.subcommands[1].name, "show");
        assert_eq!(rule.subcommands[1].args, vec!["sshd"]);
    }

    /// Flags only, no subcommand — value consumed as flag value.
    #[test]
    fn test_add_rule_no_subcommands_only_flags() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "journalctl --since yesterday --no-pager").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "journalctl").unwrap();

        assert!(rule.flags.contains(&"--since".to_string()));
        assert!(rule.flags.contains(&"--no-pager".to_string()));
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    /// Same flag passed twice → deduplicated in rule.
    #[test]
    fn test_merge_flags_dedup_same_flag_twice() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "cmd --verbose --verbose").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "cmd").unwrap();

        assert_eq!(rule.flags, vec!["--verbose"]);
    }

    /// Existing arg not duplicated when same subcommand + arg added again.
    #[test]
    fn test_merge_args_dedup() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/systemctl" }

[[rules.subcommands]]
name = "status"
args = ["sshd.service"]
"#,
        );
        add_rule(&path, "systemctl status sshd.service").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].args, vec!["sshd.service"]);
    }

    /// Flag value consumed, not stored as positional arg.
    #[test]
    fn test_flag_with_value_consumed() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "journalctl -n 10").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "journalctl").unwrap();

        assert_eq!(rule.flags, vec!["-n"]);
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    /// Flag value consumed; next token after value is subcommand.
    #[test]
    fn test_flag_value_followed_by_subcommand() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "cmd --flag value status").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "cmd").unwrap();

        assert_eq!(rule.flags, vec!["--flag"]);
        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert!(rule.subcommands[0].flags.is_empty());
        assert!(rule.subcommands[0].args.is_empty());
    }

    /// 2 rules for same binary → no auto group (need 3+).
    #[test]
    fn test_auto_create_flag_groups_two_rules_no_group() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "-n"]
"#,
        );
        // Add a rule for a DIFFERENT binary so journalctl remains at 2 rules
        add_rule(&path, "systemctl status sshd").unwrap();

        let config = Config::from_file(&path).unwrap();
        assert!(config.flag_groups.is_empty());
    }

    /// 3 rules for same binary with >= 2 common flags → auto group created.
    /// Need 3+ existing rules (find_or_create_rule reuses, doesn't create new).
    #[test]
    fn test_auto_create_flag_groups_three_rules() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since", "-n"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since", "--full"]
"#,
        );
        // Call add_rule with journalctl — finds existing rule and triggers auto group
        add_rule(&path, "journalctl --since yesterday --no-pager").unwrap();

        let config = Config::from_file(&path).unwrap();

        // Group "journalctl-common-flags" should exist with common flags
        let group = config.flag_groups.get("journalctl-common-flags");
        assert!(group.is_some(), "expected flag group to be created");
        let group = group.unwrap();
        assert!(group.contains(&"--no-pager".to_string()));
        assert!(group.contains(&"--since".to_string()));
    }

    /// 3+ rules but only 1 common flag (< 2) → no auto group.
    #[test]
    fn test_auto_create_flag_groups_single_common_flag_no_group() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--since", "--no-pager"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--since", "-n"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--since", "--full"]
"#,
        );
        // Add 4th rule; all have "--since" but only that one is common (need 2+)
        add_rule(&path, "journalctl --since yesterday --no-pager").unwrap();

        let config = Config::from_file(&path).unwrap();
        assert!(
            config.flag_groups.is_empty(),
            "no group expected with only 1 common flag"
        );
    }

    /// Empty command string → error.
    #[test]
    fn test_add_rule_empty_command() {
        let (_dir, path) = minimal_config();
        let err = add_rule(&path, "").unwrap_err();
        assert!(
            matches!(err, GuardError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    /// Invalid shlex (unclosed quote) → error.
    #[test]
    fn test_add_rule_invalid_shlex() {
        let (_dir, path) = minimal_config();
        let err = add_rule(&path, "echo \"hello").unwrap_err();
        assert!(
            matches!(err, GuardError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    /// Command with no flags or args → rule created with empty fields.
    #[test]
    fn test_add_rule_command_only_no_params() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "git").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "git").unwrap();

        assert!(rule.flags.is_empty());
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    /// Flags after subcommand name → consumed at subcommand level.
    /// Covers walk_and_merge "another flag at subcommand level" branch (L369-371).
    #[test]
    fn test_walk_and_merge_flag_after_subcommand() {
        let (_dir, path) = minimal_config();
        // "sshd" gets consumed as --full's value, then --another-flag starts a new flag
        add_rule(&path, "systemctl status --full sshd --another-flag").unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert!(rule.subcommands[0].flags.contains(&"--full".to_string()));
        assert!(
            rule.subcommands[0]
                .flags
                .contains(&"--another-flag".to_string())
        );
        // "sshd" consumed as value for --full, so no positional args
        assert!(rule.subcommands[0].args.is_empty());
    }

    /// 2 existing rules for same binary + add_rule with that binary →
    /// matching_indices.len() == 2 < 3 → early return.
    /// Covers auto_create_flag_groups < 3 check (L479-483).
    #[test]
    fn test_auto_create_flag_groups_less_than_3_rules() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["-n"]
"#,
        );
        add_rule(&path, "journalctl --since yesterday").unwrap();

        let config = Config::from_file(&path).unwrap();
        assert!(config.flag_groups.is_empty());
    }

    /// 3+ rules for same binary but 0 common flags →
    /// common.len() == 0 < 2 → early return.
    /// Covers auto_create_flag_groups common.len() < 2 check (L501).
    #[test]
    fn test_auto_create_flag_groups_zero_common_flags() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["-n"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--full"]
"#,
        );
        add_rule(&path, "journalctl --since yesterday").unwrap();

        let config = Config::from_file(&path).unwrap();
        assert!(config.flag_groups.is_empty());
    }

    /// 3+ rules with subcommands that share >= 2 common flags →
    /// flag_groups assigned to subcommands too.
    /// Covers the sub.flag_groups.push branch in auto_create_flag_groups (L514-517).
    #[test]
    fn test_auto_create_flag_groups_with_subcommands() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since"]

[[rules.subcommands]]
name = "list"
flags = ["--no-pager"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since", "-n"]

[[rules.subcommands]]
name = "show"
flags = ["--no-pager"]

[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since", "--full"]

[[rules.subcommands]]
name = "verify"
flags = ["--no-pager"]
"#,
        );
        add_rule(&path, "journalctl --since yesterday --no-pager").unwrap();

        let config = Config::from_file(&path).unwrap();

        let group = config.flag_groups.get("journalctl-common-flags");
        assert!(group.is_some(), "expected flag group to be created");
        let group = group.unwrap();
        assert!(group.contains(&"--no-pager".to_string()));
        assert!(group.contains(&"--since".to_string()));

        for rule in &config.rules {
            if let Action::Run { binary, .. } = &rule.action {
                if binary.ends_with("/journalctl") {
                    for sub in &rule.subcommands {
                        assert!(
                            sub.flag_groups
                                .contains(&"journalctl-common-flags".to_string()),
                            "subcommand '{}' should have the common flag group",
                            sub.name
                        );
                    }
                    // Common flags removed from rule-level flags
                    assert!(!rule.flags.contains(&"--no-pager".to_string()));
                }
            }
        }
    }
}

/// Walk argv tokens and merge them into the rule tree.
///
/// - Flag-like tokens (starting with `-` or `/`) and their values go into
///   the current level's `flags` list (deduplicated).
/// - The first non-flag token is treated as a subcommand name. Subsequent
///   non-flag tokens at this level become positional args.
fn walk_and_merge(rule: &mut Rule, argv: &[String]) {
    let mut i = 0;

    // Consume top-level flags
    i = merge_flags(&mut rule.flags, argv, i);

    if i >= argv.len() {
        return;
    }

    // First non-flag token is a subcommand
    let subcmd_name = &argv[i];
    i += 1;

    let sub = find_or_create_subcommand(&mut rule.subcommands, subcmd_name);

    // Consume that subcommand's flags
    i = merge_flags(&mut sub.flags, argv, i);

    // Remaining non-flag tokens after flags → positional args for this subcommand
    while i < argv.len() {
        let token = &argv[i];
        if token.starts_with('-') || token.starts_with('/') {
            // Another flag at subcommand level
            i = merge_flags(&mut sub.flags, argv, i);
        } else {
            // Positional arg at subcommand level
            if !sub.args.contains(token) {
                sub.args.push(token.clone());
            }
            i += 1;
        }
    }
}

/// Merge flags starting at position `start` into `flags` list, returning new position.
/// Each flag consumes itself. If the next token is a non-flag value, it's consumed
/// as the flag's value (e.g. `-n 10` → `-n` stored, `10` consumed but not stored).
fn merge_flags(flags: &mut Vec<String>, argv: &[String], mut start: usize) -> usize {
    while start < argv.len() {
        let token = &argv[start];
        if !token.starts_with('-') && !token.starts_with('/') {
            break;
        }
        // Add flag if not already present
        if !flags.contains(token) {
            flags.push(token.clone());
        }
        start += 1;
        // Consume value if next token is non-flag
        if start < argv.len() {
            let next = &argv[start];
            if !next.starts_with('-') && !next.starts_with('/') {
                start += 1; // consume value (not stored separately)
            }
        }
    }
    start
}

fn find_or_create_rule<'a>(rules: &'a mut Vec<Rule>, binary_name: &str) -> &'a mut Rule {
    if let Some(pos) = rules.iter().position(|r| {
        if let Action::Run { binary, .. } = &r.action {
            binary.ends_with(&format!("/{binary_name}")) || binary == binary_name
        } else {
            false
        }
    }) {
        return &mut rules[pos];
    }

    rules.push(Rule {
        action: Action::Run {
            binary: format!("/run/current-system/sw/bin/{binary_name}"),
            args: vec![],
            timeout: Duration::default(),
        },
        command: None,
        implicit_symlinks: true,
        arg_style: ArgStyle::default(),
        flag_groups: vec![],
        flags: vec![],
        args: vec![],
        pre_args: vec![],
        subcommands: vec![],
    });
    rules.last_mut().unwrap()
}

fn find_or_create_subcommand<'a>(subs: &'a mut Vec<Subcommand>, name: &str) -> &'a mut Subcommand {
    if let Some(pos) = subs.iter().position(|s| s.name == name) {
        return &mut subs[pos];
    }

    subs.push(Subcommand {
        name: name.to_string(),
        arg_style: None,
        flag_groups: vec![],
        flags: vec![],
        args: vec![],
        pre_args: vec![],
        subcommands: vec![],
    });
    subs.last_mut().unwrap()
}

fn auto_create_flag_groups(config: &mut Config, binary_name: &str) {
    // Find all rules for this binary
    let matching_indices: Vec<usize> = config
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            if let Action::Run { binary, .. } = &r.action {
                binary.ends_with(&format!("/{binary_name}")) || binary == binary_name
            } else {
                false
            }
        })
        .map(|(i, _)| i)
        .collect();

    if matching_indices.len() < 3 {
        return;
    }

    // Collect all flags from rules + their subcommands
    let all_flag_sets: Vec<std::collections::HashSet<String>> = matching_indices
        .iter()
        .map(|&idx| {
            let rule = &config.rules[idx];
            let mut flags: std::collections::HashSet<String> = rule.flags.iter().cloned().collect();
            for sub in &rule.subcommands {
                flags.extend(sub.flags.iter().cloned());
                for group_name in &sub.flag_groups {
                    if let Some(gf) = config.flag_groups.get(group_name) {
                        flags.extend(gf.iter().cloned());
                    }
                }
            }
            flags
        })
        .collect();

    let mut common: std::collections::HashSet<String> = all_flag_sets[0].clone();
    for fs in &all_flag_sets[1..] {
        common = common.intersection(fs).cloned().collect();
    }

    if common.len() < 2 {
        return;
    }

    let group_name = format!("{}-common-flags", binary_name);
    if config.flag_groups.contains_key(&group_name) {
        return;
    }

    let mut common_vec: Vec<String> = common.into_iter().collect();
    common_vec.sort();
    config.flag_groups.insert(group_name.clone(), common_vec);

    for &idx in &matching_indices {
        let rule = &mut config.rules[idx];
        let common_set: std::collections::HashSet<&String> =
            config.flag_groups[&group_name].iter().collect();
        rule.flags.retain(|f| !common_set.contains(f));
        for sub in &mut rule.subcommands {
            sub.flags.retain(|f| !common_set.contains(f));
            if !sub.flag_groups.contains(&group_name) {
                sub.flag_groups.push(group_name.clone());
            }
        }
    }
}
