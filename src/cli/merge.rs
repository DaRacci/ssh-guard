use crate::config::{
    Config, action::Action, arg::ArgStyle, duration::Duration, rule::Rule, subcommand::Subcommand,
};
use crate::errors::GuardError;

/// Merge a new command into the config via the add-rule subcommand.
///
/// If `profile` is `None`, the rule is added to the base config.
/// If `profile` is `Some(name)`, the rule is added to that profile's rules,
/// and the profile must already exist in the config.
pub fn add_rule(
    config_path: &str,
    cmd_input: &str,
    profile: Option<&str>,
) -> Result<(), GuardError> {
    let argv = shlex::split(cmd_input)
        .ok_or_else(|| GuardError::Config("failed to parse command".into()))?;

    if argv.is_empty() {
        return Err(GuardError::Config("empty command".into()));
    }

    let binary_name = &argv[0];
    let mut config = Config::from_file(config_path)?;

    match profile {
        Some(profile_name) => {
            let profile_entry = config.profiles.get_mut(profile_name).ok_or_else(|| {
                GuardError::Config(format!("profile '{profile_name}' does not exist"))
            })?;

            let rules = profile_entry.rules.get_or_insert_with(Vec::new);
            let profile_fg = profile_entry
                .flag_groups
                .get_or_insert_with(|| std::collections::HashMap::new());

            let rule = find_or_create_rule(rules, binary_name);
            walk_and_merge(rule, &argv[1..]);
            auto_create_flag_groups_in_rules(profile_fg, rules, binary_name);
        }
        None => {
            let rule = find_or_create_rule(&mut config.rules, binary_name);
            walk_and_merge(rule, &argv[1..]);
            auto_create_flag_groups(&mut config, binary_name);
        }
    }

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

    #[test]
    fn test_add_first_rule() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "journalctl --no-pager -n 10", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "journalctl").unwrap();

        assert_eq!(rule.flags, vec!["--no-pager", "-n"]);
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    #[test]
    fn test_add_rule_with_subcommand() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "systemctl status angrr", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert_eq!(rule.subcommands[0].args, vec!["angrr"]);
        assert!(rule.subcommands[0].flags.is_empty());
    }

    #[test]
    fn test_add_to_existing_rule_dedup_flags() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/systemctl" }
flags = ["--no-pager"]
"#,
        );
        add_rule(&path, "systemctl --no-pager --full -n 10 status sshd", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.flags, vec!["--no-pager", "--full", "-n"]);
        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert_eq!(rule.subcommands[0].args, vec!["sshd"]);
    }

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
        add_rule(&path, "systemctl show sshd", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 2);
        assert_eq!(rule.subcommands[0].name, "status");
        assert_eq!(rule.subcommands[0].args, vec!["sshd"]);
        assert_eq!(rule.subcommands[1].name, "show");
        assert_eq!(rule.subcommands[1].args, vec!["sshd"]);
    }

    #[test]
    fn test_add_rule_no_subcommands_only_flags() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "journalctl --since yesterday --no-pager", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "journalctl").unwrap();

        assert!(rule.flags.contains(&"--since".to_string()));
        assert!(rule.flags.contains(&"--no-pager".to_string()));
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    #[test]
    fn test_merge_flags_dedup_same_flag_twice() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "cmd --verbose --verbose", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "cmd").unwrap();

        assert_eq!(rule.flags, vec!["--verbose"]);
    }

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
        add_rule(&path, "systemctl status sshd.service", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "systemctl").unwrap();

        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].args, vec!["sshd.service"]);
    }

    #[test]
    fn test_flag_with_value_consumed() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "journalctl -n 10", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "journalctl").unwrap();

        assert_eq!(rule.flags, vec!["-n"]);
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    #[test]
    fn test_flag_value_followed_by_subcommand() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "cmd --flag value status", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "cmd").unwrap();

        assert_eq!(rule.flags, vec!["--flag"]);
        assert_eq!(rule.subcommands.len(), 1);
        assert_eq!(rule.subcommands[0].name, "status");
        assert!(rule.subcommands[0].flags.is_empty());
        assert!(rule.subcommands[0].args.is_empty());
    }

    #[test]
    fn test_add_rule_empty_command() {
        let (_dir, path) = minimal_config();
        let err = add_rule(&path, "", None).unwrap_err();
        assert!(
            matches!(err, GuardError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[test]
    fn test_add_rule_invalid_shlex() {
        let (_dir, path) = minimal_config();
        let err = add_rule(&path, "echo \"hello", None).unwrap_err();
        assert!(
            matches!(err, GuardError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[test]
    fn test_add_rule_command_only_no_params() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "git", None).unwrap();

        let config = Config::from_file(&path).unwrap();
        let rule = find_rule(&config.rules, "git").unwrap();

        assert!(rule.flags.is_empty());
        assert!(rule.subcommands.is_empty());
        assert!(rule.args.is_empty());
    }

    #[test]
    fn test_walk_and_merge_flag_after_subcommand() {
        let (_dir, path) = minimal_config();
        add_rule(&path, "systemctl status --full sshd --another-flag", None).unwrap();

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
        assert!(rule.subcommands[0].args.is_empty());
    }

    #[test]
    fn test_add_rule_to_profile() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["admin_user"]
"#,
        );
        add_rule(&path, "journalctl -n 10", Some("admin")).unwrap();

        let config = Config::from_file(&path).unwrap();
        let profile = config.profiles.get("admin").unwrap();
        let rules = profile.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        let rule = find_rule(rules, "journalctl").unwrap();
        assert_eq!(rule.flags, vec!["-n"]);
        // base unchanged
        assert_eq!(config.rules.len(), 1);
    }

    #[test]
    fn test_add_rule_to_nonexistent_profile() {
        let (_dir, path) = minimal_config();
        let err = add_rule(&path, "journalctl -n 10", Some("nonexistent")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "expected 'does not exist', got: {err:?}"
        );
    }

    #[test]
    fn test_add_rule_to_profile_auto_flag_group() {
        let (_dir, path) = create_config(
            r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["admin_user"]

[[profiles.admin.rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since"]

[[profiles.admin.rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since", "-n"]

[[profiles.admin.rules]]
action = { type = "run", binary = "/run/current-system/sw/bin/journalctl" }
flags = ["--no-pager", "--since", "--full"]
"#,
        );
        add_rule(
            &path,
            "journalctl --since yesterday --no-pager",
            Some("admin"),
        )
        .unwrap();

        let config = Config::from_file(&path).unwrap();
        // Group should be in profile-local flag_groups, NOT top-level
        let profile = config.profiles.get("admin").unwrap();
        let profile_fg = profile.flag_groups.as_ref().unwrap();
        let group = profile_fg.get("journalctl-common-flags");
        assert!(
            group.is_some(),
            "expected flag group in profile-local flag_groups"
        );
        // Top-level flag_groups stays empty
        assert!(
            config.flag_groups.is_empty(),
            "top-level flag_groups should be empty"
        );
        // Base rules unchanged
        assert_eq!(config.rules.len(), 1);
    }
}

/// Walk argv tokens and merge them into the rule tree.
fn walk_and_merge(rule: &mut Rule, argv: &[String]) {
    let mut i = 0;
    i = merge_flags(&mut rule.flags, argv, i);

    if i >= argv.len() {
        return;
    }

    let subcmd_name = &argv[i];
    i += 1;

    let sub = find_or_create_subcommand(&mut rule.subcommands, subcmd_name);
    i = merge_flags(&mut sub.flags, argv, i);

    while i < argv.len() {
        let token = &argv[i];
        if token.starts_with('-') || token.starts_with('/') {
            i = merge_flags(&mut sub.flags, argv, i);
        } else {
            if !sub.args.contains(token) {
                sub.args.push(token.clone());
            }
            i += 1;
        }
    }
}

/// Merge flags starting at position `start` into `flags` list, returning new position.
fn merge_flags(flags: &mut Vec<String>, argv: &[String], mut start: usize) -> usize {
    while start < argv.len() {
        let token = &argv[start];
        if !token.starts_with('-') && !token.starts_with('/') {
            break;
        }
        if !flags.contains(token) {
            flags.push(token.clone());
        }
        start += 1;
        if start < argv.len() {
            let next = &argv[start];
            if !next.starts_with('-') && !next.starts_with('/') {
                start += 1;
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
    auto_create_flag_groups_in_rules(&mut config.flag_groups, &mut config.rules, binary_name);
}

fn auto_create_flag_groups_in_rules(
    flag_groups: &mut crate::config::FlagGroups,
    rules: &mut Vec<Rule>,
    binary_name: &str,
) {
    let matching_indices: Vec<usize> = rules
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

    let all_flag_sets: Vec<std::collections::HashSet<String>> = matching_indices
        .iter()
        .map(|&idx| {
            let rule = &rules[idx];
            let mut flags: std::collections::HashSet<String> = rule.flags.iter().cloned().collect();
            for sub in &rule.subcommands {
                flags.extend(sub.flags.iter().cloned());
                for group_name in &sub.flag_groups {
                    if let Some(gf) = flag_groups.get(group_name) {
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
    if flag_groups.contains_key(&group_name) {
        return;
    }

    let mut common_vec: Vec<String> = common.into_iter().collect();
    common_vec.sort();
    flag_groups.insert(group_name.clone(), common_vec);

    for &idx in &matching_indices {
        let rule = &mut rules[idx];
        let common_set: std::collections::HashSet<&String> =
            flag_groups[&group_name].iter().collect();
        rule.flags.retain(|f| !common_set.contains(f));
        for sub in &mut rule.subcommands {
            sub.flags.retain(|f| !common_set.contains(f));
            if !sub.flag_groups.contains(&group_name) {
                sub.flag_groups.push(group_name.clone());
            }
        }
    }
}
