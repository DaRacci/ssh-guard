pub mod action;
pub mod arg;
pub mod audit;
pub mod contract;
pub mod duration;
pub mod global;
pub mod profile;
pub mod rule;
pub mod subcommand;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::{
    action::Action, contract::Contract, global::Global, profile::Profile, rule::Rule,
};

pub type FlagGroups = HashMap<String, Vec<String>>;
pub type Contracts = HashMap<String, Contract>;
pub type Profiles = HashMap<String, Profile>;
pub type RootSets = HashMap<String, Vec<String>>;

pub(crate) const DEFAULT_ROOT_SET: &str = "roots";

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub global: Global,

    #[serde(default)]
    pub contracts: Contracts,

    #[serde(default)]
    pub flag_groups: FlagGroups,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,

    /// Allowed filesystem roots for default `roots` set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,

    /// Additional named filesystem root sets.
    #[serde(default, skip_serializing_if = "RootSets::is_empty")]
    pub root_sets: RootSets,

    /// Allowed systemd units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,

    /// Named profiles that extend the base config for specific SSH users.
    /// Key is profile name (any unique string).
    #[serde(default, skip_serializing_if = "Profiles::is_empty")]
    pub profiles: Profiles,
}

impl Config {
    /// Load config from TOML file on disk.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` if file read fails or TOML parsing fails.
    pub fn from_file(path: &str) -> Result<Self, crate::errors::GuardError> {
        let data = std::fs::read_to_string(path).map_err(|e| {
            crate::errors::GuardError::Config(format!("cannot read config file: {e}"))
        })?;
        toml::from_str(&data).map_err(|e| crate::errors::GuardError::Toml(e.to_string()))
    }

    #[must_use]
    pub fn root_set_paths(&self, name: &str) -> Option<&[String]> {
        if name == DEFAULT_ROOT_SET {
            Some(self.roots.as_slice())
        } else {
            self.root_sets.get(name).map(Vec::as_slice)
        }
    }

    /// SHA-256 hex digest of raw config file contents.
    ///
    /// Hashes file bytes exactly as read, so it can be tested against
    /// `sha256sum <path>`.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` if file read fails or digest formatting fails.
    pub fn sha256(path: &str) -> Result<String, crate::errors::GuardError> {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;

        let data = std::fs::read(path).map_err(|e| {
            crate::errors::GuardError::Config(format!("cannot read config file: {e}"))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut hex, "{byte:02x}").map_err(|e| {
                crate::errors::GuardError::Config(format!("cannot format digest: {e}"))
            })?;
        }
        Ok(hex)
    }

    /// Serialize config to pretty TOML.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` if TOML serialization fails.
    pub fn to_toml_string(&self) -> Result<String, crate::errors::GuardError> {
        toml::to_string_pretty(self).map_err(|e| crate::errors::GuardError::Toml(e.to_string()))
    }

    /// Write config to TOML file.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` if serialization or file write fails.
    pub fn write_to_file(&self, path: &str) -> Result<(), crate::errors::GuardError> {
        let toml_str = self.to_toml_string()?;
        std::fs::write(path, toml_str)?;
        Ok(())
    }

    /// Resolve effective config for a given SSH username.
    ///
    /// - If no profile matches -> base config unchanged.
    /// - If exactly one profile matches -> merge base + profile.
    /// - If multiple profiles match -> returns error.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` if more than one profile matches `user`.
    pub fn resolve_for_user(&self, user: &str) -> Result<Config, crate::errors::GuardError> {
        let matching: Vec<(&String, &Profile)> = self
            .profiles
            .iter()
            .filter(|(_, p)| p.users.iter().any(|u| u == user))
            .collect();

        if matching.len() > 1 {
            let names: Vec<&str> = matching.iter().map(|(n, _)| n.as_str()).collect();
            return Err(crate::errors::GuardError::Config(format!(
                "user '{user}' matches multiple profiles: {}",
                names.join(", ")
            )));
        }

        let Some((_, profile)) = matching.into_iter().next() else {
            let mut base = self.clone();
            base.profiles = Profiles::new();
            return Ok(base);
        };

        Ok(self.merge_profile(profile))
    }

    /// Merge a single profile into this base config, returning a new `Config`.
    ///
    /// Merge rules:
    /// - `global`: field-wise override, profile fills unspecified fields from base.
    /// - `contracts`: map merge, profile keys override same-name base keys.
    /// - `flag_groups`: map merge, profile keys override same-name base keys.
    /// - `rules`: append profile rules after base rules.
    /// - `roots`: append unique values preserving base-first order.
    /// - `root_sets`: same-name sets append unique values preserving base-first order.
    /// - `units`: append unique values preserving base-first order.
    /// - Unset profile sections leave base values intact.
    #[must_use]
    pub fn merge_profile(&self, profile: &Profile) -> Config {
        let mut merged = self.clone();

        if let Some(ref ov) = profile.global {
            merged.global = ov.apply_to(&self.global);
        }

        if let Some(ref pc) = profile.contracts {
            for (k, v) in pc {
                merged.contracts.insert(k.clone(), v.clone());
            }
        }

        if let Some(ref pf) = profile.flag_groups {
            for (k, v) in pf {
                merged.flag_groups.insert(k.clone(), v.clone());
            }
        }

        if let Some(ref pr) = profile.rules {
            merged.rules.extend(pr.clone());
        }

        if let Some(ref pr) = profile.roots {
            append_unique(&mut merged.roots, pr);
        }

        if let Some(ref profile_root_sets) = profile.root_sets {
            merge_root_sets(&mut merged.root_sets, profile_root_sets);
        }

        if let Some(ref pu) = profile.units {
            append_unique(&mut merged.units, pu);
        }

        merged.profiles = Profiles::new();
        merged
    }

    /// Collect semantic validation errors that do not depend on host-specific binaries existing on disk.
    #[must_use]
    pub fn validation_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();

        validate_root_set_definitions(&self.root_sets, "base", &mut errors);
        validate_contract_definitions(&self.contracts, &self.root_sets, "base", &mut errors);
        validate_rules(
            &self.flag_groups,
            &self.contracts,
            &self.root_sets,
            &self.rules,
            "base",
            &mut errors,
        );

        for (pname, profile) in &self.profiles {
            if let Some(profile_root_sets) = &profile.root_sets {
                validate_root_set_definitions(
                    profile_root_sets,
                    &format!("profile '{pname}'"),
                    &mut errors,
                );
            }

            let merged = self.merge_profile(profile);

            if let Some(profile_contracts) = &profile.contracts {
                validate_contract_definitions(
                    profile_contracts,
                    &merged.root_sets,
                    &format!("profile '{pname}'"),
                    &mut errors,
                );
            }

            if let Some(ref rules) = profile.rules {
                validate_rules(
                    &merged.flag_groups,
                    &merged.contracts,
                    &merged.root_sets,
                    rules,
                    &format!("profile '{pname}'"),
                    &mut errors,
                );
            }
        }

        if let Err(error) = self.check_duplicate_users() {
            errors.push(error.to_string());
        }

        errors
    }

    /// Validate semantic config shape without requiring host binaries to exist.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` when rules, captures, root sets, or profile user assignments are invalid.
    pub fn validate_semantics(&self) -> Result<(), crate::errors::GuardError> {
        let errors = self.validation_errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::errors::GuardError::Validation(format!(
                "{} validation error(s): {}",
                errors.len(),
                errors.join("; ")
            )))
        }
    }

    /// Check for duplicate SSH usernames across all profiles.
    ///
    /// # Errors
    ///
    /// Returns `GuardError` with duplicate user details if same username appears in more than one profile.
    pub fn check_duplicate_users(&self) -> Result<(), crate::errors::GuardError> {
        let mut seen: HashMap<&str, &str> = HashMap::new(); // user -> first_profile_name
        for (pname, profile) in &self.profiles {
            for u in &profile.users {
                if let Some(&first) = seen.get(u.as_str()) {
                    return Err(crate::errors::GuardError::Config(format!(
                        "duplicate user '{u}' in profiles '{first}' and '{pname}'"
                    )));
                }
                seen.insert(u, pname);
            }
        }
        Ok(())
    }
}

fn append_unique(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.contains(value) {
            target.push(value.clone());
        }
    }
}

fn merge_root_sets(target: &mut RootSets, incoming: &RootSets) {
    for (name, paths) in incoming {
        append_unique(target.entry(name.clone()).or_default(), paths);
    }
}

fn validate_root_set_definitions(root_sets: &RootSets, scope: &str, errors: &mut Vec<String>) {
    if root_sets.contains_key(DEFAULT_ROOT_SET) {
        errors.push(format!(
            "{scope}: reserved root set name '{DEFAULT_ROOT_SET}' must use the `roots` field"
        ));
    }
}

fn validate_contract_definitions(
    contracts: &Contracts,
    available_root_sets: &RootSets,
    scope: &str,
    errors: &mut Vec<String>,
) {
    for (name, contract) in contracts {
        if let Contract::Path { root_set, .. } = contract
            && root_set != DEFAULT_ROOT_SET
            && !available_root_sets.contains_key(root_set)
        {
            errors.push(format!(
                "{scope} contract '{name}': unknown root set '{root_set}'"
            ));
        }
    }
}

fn collect_capture_keys(patterns: &[String], out: &mut Vec<String>) {
    use crate::engine::parse::parse_arg_pattern;
    use crate::engine::types::ArgPattern;

    for raw in patterns {
        let pattern = parse_arg_pattern(raw);
        let key = match &pattern {
            ArgPattern::Template(template)
            | ArgPattern::InlineFlag { template, .. }
            | ArgPattern::TemplateContext { template, .. } => template.capture_key(),
            ArgPattern::Literal(_) => None,
        };
        if let Some(name) = key {
            out.push(name.to_string());
        }
    }
}

#[derive(Clone)]
struct CapturePath {
    subcommand_path: Vec<String>,
    capture_keys: Vec<String>,
}

fn expanded_flags(
    available_flag_groups: &FlagGroups,
    referenced_groups: &[String],
    inline_flags: &[String],
) -> Vec<String> {
    crate::engine::flags::expand_flags(available_flag_groups, referenced_groups, inline_flags)
}

fn collect_rule_capture_paths(available_flag_groups: &FlagGroups, rule: &Rule) -> Vec<CapturePath> {
    let mut base_capture_keys = Vec::new();
    collect_capture_keys(
        &expanded_flags(available_flag_groups, &rule.flag_groups, &rule.flags),
        &mut base_capture_keys,
    );
    collect_capture_keys(&rule.args, &mut base_capture_keys);

    let mut paths = Vec::new();
    if rule.subcommands.is_empty() || !rule.args.is_empty() {
        paths.push(CapturePath {
            subcommand_path: Vec::new(),
            capture_keys: base_capture_keys.clone(),
        });
    }

    collect_subcommand_capture_paths(
        &rule.subcommands,
        available_flag_groups,
        &Vec::new(),
        &base_capture_keys,
        &mut paths,
    );
    paths
}

fn collect_subcommand_capture_paths(
    subcommands: &[crate::config::subcommand::Subcommand],
    available_flag_groups: &FlagGroups,
    current_path: &[String],
    current_capture_keys: &[String],
    out: &mut Vec<CapturePath>,
) {
    for subcommand in subcommands {
        let mut next_path = current_path.to_vec();
        next_path.push(subcommand.name.clone());

        let mut next_capture_keys = current_capture_keys.to_vec();
        collect_capture_keys(
            &expanded_flags(
                available_flag_groups,
                &subcommand.flag_groups,
                &subcommand.flags,
            ),
            &mut next_capture_keys,
        );
        collect_capture_keys(&subcommand.args, &mut next_capture_keys);

        out.push(CapturePath {
            subcommand_path: next_path.clone(),
            capture_keys: next_capture_keys.clone(),
        });

        collect_subcommand_capture_paths(
            &subcommand.subcommands,
            available_flag_groups,
            &next_path,
            &next_capture_keys,
            out,
        );
    }
}

fn capture_paths_for_prefix<'a>(
    capture_paths: &'a [CapturePath],
    prefix: &[String],
) -> Vec<&'a CapturePath> {
    capture_paths
        .iter()
        .filter(|path| path.subcommand_path.starts_with(prefix))
        .collect()
}

fn format_capture_path(path: &[String]) -> String {
    if path.is_empty() {
        "<top-level>".to_string()
    } else {
        path.join(" ")
    }
}

fn validate_action_captures(
    rule: &Rule,
    available_root_sets: &RootSets,
    index: usize,
    scope: &str,
    capture_paths: &[CapturePath],
    errors: &mut Vec<String>,
) {
    let kind = crate::kinds::kind_for(&rule.action);
    for root_set in kind.root_sets() {
        validate_root_set(root_set, available_root_sets, index, scope, errors);
    }
    let references = kind.capture_refs();

    for (field, reference) in references {
        let name = reference
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}');
        if name.is_empty() {
            continue;
        }
        for capture_path in capture_paths {
            if capture_path.capture_keys.iter().any(|key| key == name) {
                continue;
            }
            let available = if capture_path.capture_keys.is_empty() {
                "none".to_string()
            } else {
                capture_path.capture_keys.join(", ")
            };
            let path_label = format_capture_path(&capture_path.subcommand_path);
            errors.push(format!(
                "{scope} rule[{index}]: {field} '{reference}' is missing capture '{name}' on path {path_label} (available: {available}). Use a named capture like {{{name}:string}} in args, or a contract arg named '{name}'."
            ));
        }
    }
}

fn validate_root_set(
    root_set: &str,
    available_root_sets: &RootSets,
    index: usize,
    scope: &str,
    errors: &mut Vec<String>,
) {
    if root_set != DEFAULT_ROOT_SET && !available_root_sets.contains_key(root_set) {
        errors.push(format!(
            "{scope} rule[{index}]: unknown root set '{root_set}'"
        ));
    }
}

fn validate_flag_group_refs(
    referenced_groups: &[String],
    available_groups: &FlagGroups,
    context: &str,
    errors: &mut Vec<String>,
) {
    for group in referenced_groups {
        if !available_groups.contains_key(group) {
            errors.push(format!("{context}: unknown flag group '{group}'"));
        }
    }
}

fn validate_template_contracts(
    template: &crate::engine::types::TemplateType,
    available_contracts: &Contracts,
    context: &str,
    raw: &str,
    errors: &mut Vec<String>,
) {
    match template {
        crate::engine::types::TemplateType::Named { inner, .. } => {
            validate_template_contracts(inner, available_contracts, context, raw, errors);
        }
        crate::engine::types::TemplateType::ContractRef(name) => {
            if !available_contracts.contains_key(name) {
                errors.push(format!(
                    "{context}: unknown contract '{name}' referenced in '{raw}'"
                ));
            }
        }
        crate::engine::types::TemplateType::Union(parts) => {
            for part in parts {
                validate_template_contracts(part, available_contracts, context, raw, errors);
            }
        }
        crate::engine::types::TemplateType::String
        | crate::engine::types::TemplateType::Int
        | crate::engine::types::TemplateType::Any => {}
    }
}

fn validate_pattern_contracts(
    patterns: &[String],
    available_contracts: &Contracts,
    context: &str,
    errors: &mut Vec<String>,
) {
    use crate::engine::parse::parse_arg_pattern;
    use crate::engine::types::ArgPattern;

    for raw in patterns {
        match parse_arg_pattern(raw) {
            ArgPattern::Template(template)
            | ArgPattern::InlineFlag { template, .. }
            | ArgPattern::TemplateContext { template, .. } => {
                validate_template_contracts(&template, available_contracts, context, raw, errors);
            }
            ArgPattern::Literal(_) => {}
        }
    }
}

fn validate_placeholder_refs(
    tokens: &[String],
    capture_paths: &[&CapturePath],
    context: &str,
    field: &str,
    errors: &mut Vec<String>,
) {
    for token in tokens {
        for (name, has_default) in placeholder_references(token) {
            if has_default {
                continue;
            }
            for capture_path in capture_paths {
                if capture_path.capture_keys.iter().any(|key| key == &name) {
                    continue;
                }
                let available = if capture_path.capture_keys.is_empty() {
                    "none".to_string()
                } else {
                    capture_path.capture_keys.join(", ")
                };
                let path_label = format_capture_path(&capture_path.subcommand_path);
                errors.push(format!(
                    "{context}: {field} token '{token}' references missing capture '{name}' on path {path_label} (available: {available})"
                ));
            }
        }
    }
}

fn placeholder_references(token: &str) -> Vec<(String, bool)> {
    let mut refs = Vec::new();
    let mut chars = token.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if chars
                .peek()
                .is_some_and(|next| matches!(next, '{' | '}' | '\\'))
            {
                chars.next();
            }
            continue;
        }

        if ch != '{' {
            continue;
        }

        let mut inner = String::new();
        let mut closed = false;
        for next in chars.by_ref() {
            if next == '}' {
                closed = true;
                break;
            }
            inner.push(next);
        }
        if !closed {
            continue;
        }

        let (name, has_default) = match inner.split_once(":-") {
            Some((name, _default)) => (name, true),
            None => (inner.as_str(), false),
        };

        if !name.is_empty() {
            refs.push((name.to_string(), has_default));
        }
    }

    refs
}

fn validate_subcommands(
    subcommands: &[crate::config::subcommand::Subcommand],
    available_flag_groups: &FlagGroups,
    available_contracts: &Contracts,
    capture_paths: &[CapturePath],
    current_prefix: &[String],
    context: &str,
    errors: &mut Vec<String>,
) {
    for subcommand in subcommands {
        let mut sub_prefix = current_prefix.to_vec();
        sub_prefix.push(subcommand.name.clone());

        let sub_context = format!("{context} subcommand '{}'", subcommand.name);
        let applicable_paths = capture_paths_for_prefix(capture_paths, &sub_prefix);

        validate_flag_group_refs(
            &subcommand.flag_groups,
            available_flag_groups,
            &sub_context,
            errors,
        );
        let sub_flags = expanded_flags(
            available_flag_groups,
            &subcommand.flag_groups,
            &subcommand.flags,
        );
        validate_pattern_contracts(
            &sub_flags,
            available_contracts,
            &format!("{sub_context} flags"),
            errors,
        );
        validate_pattern_contracts(
            &subcommand.args,
            available_contracts,
            &format!("{sub_context} args"),
            errors,
        );
        validate_placeholder_refs(
            &subcommand.pre_args,
            &applicable_paths,
            &sub_context,
            "pre_args",
            errors,
        );
        validate_subcommands(
            &subcommand.subcommands,
            available_flag_groups,
            available_contracts,
            capture_paths,
            &sub_prefix,
            &sub_context,
            errors,
        );
    }
}

fn validate_rules(
    available_flag_groups: &FlagGroups,
    available_contracts: &Contracts,
    available_root_sets: &RootSets,
    rules: &[Rule],
    scope: &str,
    errors: &mut Vec<String>,
) {
    for (index, rule) in rules.iter().enumerate() {
        let capture_paths = collect_rule_capture_paths(available_flag_groups, rule);
        let context = format!("{scope} rule[{index}]");
        let all_capture_paths = capture_paths.iter().collect::<Vec<_>>();
        let rule_flags = expanded_flags(available_flag_groups, &rule.flag_groups, &rule.flags);

        validate_action_captures(
            rule,
            available_root_sets,
            index,
            scope,
            &capture_paths,
            errors,
        );
        validate_flag_group_refs(&rule.flag_groups, available_flag_groups, &context, errors);
        validate_pattern_contracts(
            &rule_flags,
            available_contracts,
            &format!("{context} flags"),
            errors,
        );
        validate_pattern_contracts(
            &rule.args,
            available_contracts,
            &format!("{context} args"),
            errors,
        );
        validate_placeholder_refs(
            &rule.pre_args,
            &all_capture_paths,
            &context,
            "pre_args",
            errors,
        );
        validate_subcommands(
            &rule.subcommands,
            available_flag_groups,
            available_contracts,
            &capture_paths,
            &[],
            &context,
            errors,
        );

        if rule.command_name().is_none() {
            errors.push(format!(
                "{scope} rule[{index}]: command name could not be resolved"
            ));
        }

        if let Action::Run { binary, args, .. } = &rule.action {
            let path = std::path::Path::new(binary);
            if !path.is_absolute() {
                errors.push(format!(
                    "{scope} rule[{index}]: binary '{binary}' must be an absolute path"
                ));
            }
            validate_placeholder_refs(args, &all_capture_paths, &context, "action.args", errors);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::action::Action;
    use crate::config::arg::ArgStyle;
    use crate::config::audit::AuditFormat;
    use crate::config::duration::Duration;
    use crate::config::duration::parse_duration;

    use super::*;

    fn run_timeout(action: &Action) -> Option<u64> {
        if let Action::Run { timeout, .. } = action {
            Some(timeout.millis)
        } else {
            None
        }
    }

    fn run_parts(action: &Action) -> Option<(String, Vec<String>, u64)> {
        if let Action::Run {
            binary,
            args,
            timeout,
        } = action
        {
            Some((binary.clone(), args.clone(), timeout.millis))
        } else {
            None
        }
    }

    fn tail_default_lines(action: &Action) -> Option<usize> {
        if let Action::TailFile { default_lines, .. } = action {
            Some(*default_lines)
        } else {
            None
        }
    }

    fn int_range(contract: &Contract) -> Option<(i64, i64)> {
        if let Contract::IntRange { min, max } = contract {
            Some((*min, *max))
        } else {
            None
        }
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.global.audit_format, AuditFormat::Json);
        assert_eq!(cfg.global.audit_log, "/var/log/ssh-guard-audit.log");
    }

    #[test]
    fn test_parse_subcommands() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/git", timeout = "10s" }
implicit_symlinks = false

[[rules.subcommands]]
name = "status"
args = ["--porcelain", "--short", "{string}"]

[[rules.subcommands]]
name = "log"
flags = ["--oneline"]
flag_groups = ["git-common"]

[[rules.subcommands]]
name = "remote"

[[rules.subcommands.subcommands]]
name = "add"
args = ["{gh_remote}"]

[flag_groups]
git-common = ["--no-pager"]

[global]
audit_log = "/tmp/audit.log"
help_text = "allowed: git status, git log, git remote add"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(cfg.rules.len(), 1);
        let rule = &cfg.rules[0];
        assert!(!rule.implicit_symlinks);
        assert_eq!(rule.subcommands.len(), 3);

        let status = &rule.subcommands[0];
        assert_eq!(status.name, "status");
        assert_eq!(status.args, vec!["--porcelain", "--short", "{string}"]);

        let log = &rule.subcommands[1];
        assert_eq!(log.name, "log");
        assert_eq!(log.flags, vec!["--oneline"]);
        assert_eq!(log.flag_groups, vec!["git-common"]);

        let remote = &rule.subcommands[2];
        assert_eq!(remote.name, "remote");
        assert_eq!(remote.subcommands.len(), 1);
        assert_eq!(remote.subcommands[0].name, "add");
        assert_eq!(remote.subcommands[0].args, vec!["{gh_remote}"]);

        assert_eq!(cfg.flag_groups["git-common"], vec!["--no-pager"]);

        assert_eq!(cfg.contracts.len(), 0);

        assert_eq!(cfg.global.audit_log, "/tmp/audit.log");
        assert_eq!(
            cfg.global.help_text,
            "allowed: git status, git log, git remote add"
        );
    }

    #[test]
    fn test_duration_parsing() {
        assert_eq!(parse_duration("5000").unwrap().millis, 5000);
        assert_eq!(parse_duration("5000ms").unwrap().millis, 5000);
        assert_eq!(parse_duration("5s").unwrap().millis, 5000);
        assert_eq!(parse_duration("1m").unwrap().millis, 60000);
        assert_eq!(parse_duration("1h").unwrap().millis, 3_600_000);
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn test_duration_deser_inline() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/echo", args = [], timeout = "30s" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(run_timeout(&cfg.rules[0].action), Some(30_000));
    }

    #[test]
    fn test_duration_deser_integer() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/echo", args = [], timeout = 10000 }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(run_timeout(&cfg.rules[0].action), Some(10_000));
    }

    #[test]
    fn test_parse_global_all_fields() {
        let toml_str = r#"
[global]
audit_log = "/custom/audit.log"
audit_format = "logfmt"
help_text = "Available: help"
log_tag = "my-guard"
max_read_bytes = 512_000
max_tail_lines = 1000
default_tail_lines = 50

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.global.audit_log, "/custom/audit.log");
        assert_eq!(cfg.global.audit_format, AuditFormat::Logfmt);
        assert_eq!(cfg.global.help_text, "Available: help");
        assert_eq!(cfg.global.log_tag, "my-guard");
        assert_eq!(cfg.global.max_read_bytes, 512_000);
        assert_eq!(cfg.global.max_tail_lines, 1000);
        assert_eq!(cfg.global.default_tail_lines, 50);
    }

    #[test]
    fn test_parse_contracts() {
        let toml_str = r#"
[contracts.port]
type = "int_range"
min = 1024
max = 65535

[contracts.svc]
type = "enum"
values = ["ssh", "nginx"]

[contracts.username]
type = "string_len"
min = 3
max = 32

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.contracts.len(), 3);
        assert_eq!(int_range(&cfg.contracts["port"]), Some((1024, 65_535)));
    }

    #[test]
    fn test_parse_run_action_with_timeout() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/rsync", args = ["-a", "{string}"], timeout = "2m" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(
            run_parts(&cfg.rules[0].action),
            Some((
                "/opt/test/bin/rsync".into(),
                vec!["-a".into(), "{string}".into()],
                120_000,
            ))
        );
    }

    #[test]
    fn test_parse_all_action_types() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/echo", args = ["hello"] }

[[rules]]
action = { type = "read_file", path_capture = "{log}", root_set = "logs" }

[[rules]]
action = { type = "tail_file", path_capture = "{log}", default_lines = 50, root_set = "logs" }

[[rules]]
action = { type = "stat_path", path_capture = "{path}", root_set = "files" }

[[rules]]
action = { type = "list_dir", path_capture = "{dir}", root_set = "files" }

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 6);
        assert_eq!(tail_default_lines(&cfg.rules[2].action), Some(50));
    }

    #[test]
    fn test_parse_flag_groups_in_config() {
        let toml_str = r#"
[flag_groups]
net = ["--host", "-p"]
fmt = ["--format", "-f"]

[[rules]]
action = { type = "run", binary = "/opt/test/bin/curl" }
flags = ["--verbose"]
flag_groups = ["net"]

[[rules.subcommands]]
name = "get"
flag_groups = ["fmt"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(cfg.flag_groups["net"], vec!["--host", "-p"]);
        assert_eq!(cfg.flag_groups["fmt"], vec!["--format", "-f"]);

        let rule = &cfg.rules[0];
        assert_eq!(rule.flag_groups, vec!["net"]);
        assert_eq!(rule.flags, vec!["--verbose"]);

        assert_eq!(rule.subcommands[0].flag_groups, vec!["fmt"]);
    }

    #[test]
    fn test_parse_implicit_symlinks() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/realcmd" }
implicit_symlinks = false

[[rules]]
action = { type = "read_file", path_capture = "{file}", root_set = "data" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 2);

        assert!(!cfg.rules[0].implicit_symlinks);
        assert!(cfg.rules[1].implicit_symlinks);
    }

    #[test]
    fn test_parse_template_suffix_in_config() {
        let toml_str = r#"
[contracts.unit]
type = "enum"
values = ["nginx", "sshd"]

[[rules]]
action = { type = "run", binary = "/opt/test/bin/systemctl" }

[[rules.subcommands]]
name = "status"
args = ["{unit}.service"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();

        assert!(cfg.contracts.contains_key("unit"));

        let rule = &cfg.rules[0];
        assert_eq!(rule.subcommands[0].args, vec!["{unit}.service"]);
    }

    #[test]
    fn test_parse_subcommand_arg_style_override() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/some-tool" }
arg_style = "gnu_long"

[[rules.subcommands]]
name = "legacy"
arg_style = "dos"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let rule = &cfg.rules[0];
        assert_eq!(rule.arg_style, ArgStyle::GnuLong);
        assert_eq!(rule.subcommands[0].arg_style, Some(ArgStyle::Dos));
    }

    #[test]
    fn test_config_round_trip() {
        use crate::config::contract::Contract;

        let original = Config {
            global: Global {
                audit_log: "/tmp/roundtrip.log".into(),
                audit_format: AuditFormat::Logfmt,
                help_text: "round trip test".into(),
                log_tag: "test".into(),
                max_read_bytes: 999,
                max_tail_lines: 111,
                default_tail_lines: 50,
            },
            contracts: {
                let mut c = Contracts::new();
                c.insert("port".into(), Contract::IntRange { min: 1, max: 9999 });
                c
            },
            flag_groups: {
                let mut f = FlagGroups::new();
                f.insert(
                    "verbose".into(),
                    vec!["-v".to_string(), "--verbose".to_string()],
                );
                f
            },
            rules: vec![Rule {
                action: Action::Run {
                    binary: "/opt/test/bin/test".into(),
                    args: vec!["{arg}".into()],
                    timeout: Duration { millis: 10000 },
                },
                command: Some("test".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec!["verbose".into()],
                flags: vec!["--debug".into()],
                args: vec!["{string}".into()],
                pre_args: vec!["--config".to_string(), "/etc/test.conf".to_string()],
                subcommands: vec![],
            }],
            roots: vec!["/data".into()],
            units: vec!["nginx".into(), "sshd".into()],
            ..Default::default()
        };

        let toml_str = original.to_toml_string().unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(deserialized.global.audit_log, "/tmp/roundtrip.log");
        assert_eq!(deserialized.global.audit_format, AuditFormat::Logfmt);
        assert_eq!(deserialized.global.help_text, "round trip test");
        assert_eq!(deserialized.global.max_read_bytes, 999);

        assert!(deserialized.contracts.contains_key("port"));
        assert_eq!(deserialized.flag_groups["verbose"], vec!["-v", "--verbose"]);

        assert_eq!(deserialized.rules.len(), 1);
        let r = &deserialized.rules[0];
        assert_eq!(r.command, Some("test".into()));
        assert_eq!(
            run_parts(&r.action),
            Some(("/opt/test/bin/test".into(), vec!["{arg}".into()], 10_000))
        );
        assert_eq!(r.flag_groups, vec!["verbose"]);
        assert_eq!(r.flags, vec!["--debug"]);
        assert_eq!(r.args, vec!["{string}"]);
        assert_eq!(r.pre_args, vec!["--config", "/etc/test.conf"]);

        assert_eq!(deserialized.roots, vec!["/data"]);
        assert_eq!(deserialized.units, vec!["nginx", "sshd"]);
    }

    #[test]
    fn test_parse_roots_and_units() {
        let toml_str = r#"
roots = ["/var/log", "/home"]
units = ["nginx", "postgresql", "sshd"]

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.roots, vec!["/var/log", "/home"]);
        assert_eq!(cfg.units, vec!["nginx", "postgresql", "sshd"]);
    }

    #[test]
    fn test_parse_named_root_sets() {
        let toml_str = r#"
roots = ["/var/log"]

[root_sets]
data = ["/srv/data", "/srv/shared"]
logs = ["/srv/log/app"]

[[rules]]
action = { type = "show_help" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let value: toml::Value = toml::from_str(&cfg.to_toml_string().unwrap()).unwrap();

        assert_eq!(
            value["roots"].as_array().unwrap(),
            &vec![toml::Value::String("/var/log".into())]
        );
        assert_eq!(
            value["root_sets"]["data"].as_array().unwrap(),
            &vec![
                toml::Value::String("/srv/data".into()),
                toml::Value::String("/srv/shared".into())
            ]
        );
        assert_eq!(
            value["root_sets"]["logs"].as_array().unwrap(),
            &vec![toml::Value::String("/srv/log/app".into())]
        );
    }

    #[test]
    fn test_from_file_nonexistent() {
        let path = "/tmp/__ssh_guard_test_nonexistent_should_not_exist.toml";
        let result = Config::from_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_to_file_round_trip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let cfg = Config {
            global: Global {
                audit_log: "/tmp/write_test.log".into(),
                audit_format: AuditFormat::Json,
                help_text: "write test".into(),
                log_tag: "test".into(),
                max_read_bytes: 1024,
                max_tail_lines: 100,
                default_tail_lines: 20,
            },
            rules: vec![Rule {
                action: Action::Run {
                    binary: "/opt/test/bin/ls".into(),
                    args: vec!["-la".into()],
                    timeout: Duration { millis: 5000 },
                },
                command: None,
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            }],
            ..Default::default()
        };

        cfg.write_to_file(&path).unwrap();
        let read_back = Config::from_file(&path).unwrap();

        assert_eq!(read_back.global.audit_log, "/tmp/write_test.log");
        assert_eq!(read_back.global.help_text, "write test");
        assert_eq!(read_back.rules.len(), 1);
        assert_eq!(
            run_parts(&read_back.rules[0].action).map(|(binary, _, _)| binary),
            Some("/opt/test/bin/ls".into())
        );

        drop(tmp);
    }

    #[test]
    fn test_config_empty_rules() {
        // rules has #[serde(default)], no [[rules]] entries is ok, becomes empty vec
        let toml_str = r#"
[global]
audit_log = "/dev/null"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(
            result.is_ok(),
            "empty rules should parse with #[serde(default)]"
        );
        let cfg = result.unwrap();
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn test_to_toml_string_empty_config() {
        let cfg = Config {
            global: Global {
                audit_log: "/dev/null".into(),
                audit_format: AuditFormat::Json,
                help_text: String::new(),
                log_tag: "test".into(),
                max_read_bytes: 100,
                max_tail_lines: 10,
                default_tail_lines: 5,
            },
            ..Default::default()
        };
        let s = cfg.to_toml_string().unwrap();
        assert!(s.contains("audit_log"));
        assert!(s.contains("/dev/null"));
    }

    #[test]
    fn test_from_file_success_via_inline() {
        use std::io::Write;
        let toml_content = r#"
[global]
audit_log = "/tmp/test_inline.log"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/true" }
"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{toml_content}").unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let cfg = Config::from_file(&path).unwrap();
        assert_eq!(cfg.global.audit_log, "/tmp/test_inline.log");
        assert_eq!(cfg.rules.len(), 1);
        drop(tmp);
    }

    #[test]
    fn test_sha256_matches_sha256sum() {
        use std::io::Write;
        let content = b"[global]\naudit_log = \"/dev/null\"\n";
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(content).unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let got = Config::sha256(&path).unwrap();
        assert_eq!(got.len(), 64);
        assert_eq!(got, Config::sha256(&path).unwrap());
        let mut tmp2 = tempfile::NamedTempFile::new().unwrap();
        tmp2.write_all(b"other").unwrap();
        let path2 = tmp2.path().to_str().unwrap().to_string();
        assert_ne!(got, Config::sha256(&path2).unwrap());
        drop(tmp);
        drop(tmp2);
    }

    #[test]
    fn test_sha256_nonexistent() {
        let path = "/tmp/__ssh_guard_test_nonexistent_sha256.toml";
        assert!(Config::sha256(path).is_err());
    }

    #[test]
    fn test_parse_rule_with_flags_and_pre_args() {
        let toml_str = r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/deploy", args = ["--env", "{string}"] }
flags = ["--dry-run", "--verbose"]
pre_args = ["--config", "/etc/deploy.conf"]
args = ["{string}"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.rules.len(), 1);
        let rule = &cfg.rules[0];
        assert_eq!(rule.flags, vec!["--dry-run", "--verbose"]);
        assert_eq!(rule.pre_args, vec!["--config", "/etc/deploy.conf"]);
        assert_eq!(rule.args, vec!["{string}"]);
        assert!(rule.subcommands.is_empty());
    }

    use crate::config::profile::Profile;

    #[test]
    fn test_parse_config_with_profiles() {
        let toml_str = r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["alice", "bob"]

[profiles.admin.global]
audit_log = "/admin/log"
help_text = "admin help"

[[profiles.admin.rules]]
action = { type = "run", binary = "/opt/test/bin/extra", args = [] }

[profiles.dev]
users = ["charlie"]
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.profiles.len(), 2);

        let admin = &cfg.profiles["admin"];
        assert_eq!(admin.users, vec!["alice", "bob"]);
        assert_eq!(
            admin.global.as_ref().unwrap().audit_log.as_deref(),
            Some("/admin/log")
        );
        assert!(admin.rules.is_some());
        assert_eq!(admin.rules.as_ref().unwrap().len(), 1);

        let dev = &cfg.profiles["dev"];
        assert_eq!(dev.users, vec!["charlie"]);
        assert!(dev.global.is_none());
        assert!(dev.rules.is_none());
    }

    #[test]
    fn test_validate_semantics_rejects_unknown_flag_group() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "journalctl"
action = { type = "run", binary = "/opt/test/bin/journalctl", args = [] }
flag_groups = ["missing"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("unknown flag group 'missing'"), "got: {err}");
    }

    #[test]
    fn test_validate_semantics_rejects_missing_action_arg_capture() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "du"
action = { type = "run", binary = "/opt/test/bin/du", args = ["-d{depth}"] }
args = ["{path:string}"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("action.args token '-d{depth}'"), "got: {err}");
        assert!(err.contains("missing capture 'depth'"), "got: {err}");
    }

    #[test]
    fn test_validate_semantics_accepts_action_arg_capture_from_flag_group() {
        let cfg: Config = toml::from_str(
            r#"
[flag_groups]
paging = ["--lines={lines:int}"]

[[rules]]
command = "tail"
action = { type = "run", binary = "/opt/test/bin/tail", args = ["{lines}"] }
flag_groups = ["paging"]
"#,
        )
        .unwrap();
        let result = cfg.validate_semantics();
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_semantics_rejects_unknown_contract_in_flag_group() {
        let cfg: Config = toml::from_str(
            r#"
[flag_groups]
captured = ["--path={missing_contract}"]

[[rules]]
command = "inspect"
action = { type = "show_help" }
flag_groups = ["captured"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(
            err.contains("unknown contract 'missing_contract'"),
            "got: {err}"
        );
    }

    #[test]
    fn test_validate_semantics_rejects_unknown_contract() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "systemctl"
action = { type = "run", binary = "/opt/test/bin/systemctl", args = [] }
args = ["{unit_name}"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("unknown contract 'unit_name'"), "got: {err}");
    }

    #[test]
    fn test_validate_semantics_rejects_sibling_only_placeholder_capture() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "cmd"
action = { type = "run", binary = "/opt/test/bin/cmd", args = [] }

[[rules.subcommands]]
name = "alpha"
pre_args = ["--user", "{user}"]

[[rules.subcommands]]
name = "beta"
args = ["{user:string}"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("subcommand 'alpha'"), "got: {err}");
        assert!(err.contains("path alpha"), "got: {err}");
        assert!(err.contains("missing capture 'user'"), "got: {err}");
    }

    #[test]
    fn test_validate_tail_file_lines_capture_ref_checked() {
        let toml_str = r#"
[[rules]]
command = "logs"
args = ["{path:string}"]
action = { type = "tail_file", path_capture = "path", lines_capture = "n", root_set = "roots" }
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let errors = cfg.validation_errors();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("lines_capture") && e.contains("'n'")),
            "{errors:?}"
        );
    }

    #[test]
    fn test_validate_semantics_allows_subcommand_only_capture_for_action_args() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "cmd"
action = { type = "run", binary = "/opt/test/bin/cmd", args = ["{user}"] }

[[rules.subcommands]]
name = "beta"
args = ["{user:string}"]
"#,
        )
        .unwrap();
        let result = cfg.validate_semantics();
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    // Regression: a non-`Run` rule with no explicit `command` has no resolvable
    // command name. Old `cli::validate` never checked this, so such a config
    // validated cleanly yet matched any argv[0] at runtime and rendered empty
    // in help output.
    #[test]
    fn test_validate_semantics_rejects_unresolvable_command_name() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(
            err.contains("command name could not be resolved"),
            "got: {err}"
        );
    }

    // Regression: `validate_root_set` must mirror runtime root-set lookup in
    // `actions.rs`. An undefined root set previously passed `cli::validate`
    // and only failed when the action actually ran.
    #[test]
    fn test_validate_semantics_rejects_unknown_root_set() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "cat"
action = { type = "read_file", path_capture = "{file}", root_set = "data" }
args = ["{file:string}"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("unknown root set 'data'"), "got: {err}");
    }

    #[test]
    fn test_validate_semantics_accepts_roots_root_set() {
        let cfg: Config = toml::from_str(
            r#"
roots = ["/var/log"]

[[rules]]
command = "cat"
action = { type = "read_file", path_capture = "{file}", root_set = "roots" }
args = ["{file:string}"]
"#,
        )
        .unwrap();
        let result = cfg.validate_semantics();
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_semantics_accepts_named_root_set() {
        let cfg: Config = toml::from_str(
            r#"
[root_sets]
data = ["/srv/data"]

[[rules]]
command = "cat-data"
action = { type = "read_file", path_capture = "{file}", root_set = "data" }
args = ["{file:string}"]
"#,
        )
        .unwrap();
        let result = cfg.validate_semantics();
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_semantics_rejects_reserved_root_set_name() {
        let cfg: Config = toml::from_str(
            r#"
[root_sets]
roots = ["/srv/data"]

[[rules]]
command = "help"
action = { type = "show_help" }
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("reserved root set name 'roots'"), "got: {err}");
    }

    #[test]
    fn test_validate_semantics_accepts_profile_named_root_set() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "help"
action = { type = "show_help" }

[profiles.admin]
users = ["alice"]

[profiles.admin.root_sets]
data = ["/srv/data"]

[[profiles.admin.rules]]
command = "cat-data"
action = { type = "read_file", path_capture = "{file}", root_set = "data" }
args = ["{file:string}"]
"#,
        )
        .unwrap();
        let result = cfg.validate_semantics();
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_validate_semantics_rejects_profile_reserved_root_set_name() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "help"
action = { type = "show_help" }

[profiles.admin]
users = ["alice"]

[profiles.admin.root_sets]
roots = ["/srv/data"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("reserved root set name 'roots'"), "got: {err}");
    }

    #[test]
    fn test_validate_semantics_rejects_base_rule_using_profile_only_root_set() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
command = "cat-data"
action = { type = "read_file", path_capture = "{file}", root_set = "data" }
args = ["{file:string}"]

[profiles.admin]
users = ["alice"]

[profiles.admin.root_sets]
data = ["/srv/data"]
"#,
        )
        .unwrap();
        let err = cfg.validate_semantics().unwrap_err().to_string();
        assert!(err.contains("unknown root set 'data'"), "got: {err}");
    }

    // A `Run` rule derives its command name from the binary filename, so no
    // explicit `command` is required.
    #[test]
    fn test_validate_semantics_derives_command_name_from_binary() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "run", binary = "/opt/test/bin/systemctl", args = [] }
"#,
        )
        .unwrap();
        let result = cfg.validate_semantics();
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_resolve_for_user_no_match() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["alice"]
"#,
        )
        .unwrap();
        let resolved = cfg.resolve_for_user("bob").unwrap();
        assert_eq!(resolved.rules.len(), 1);
        assert!(resolved.profiles.is_empty());
    }

    #[test]
    fn test_resolve_for_user_single_match() {
        let cfg: Config = toml::from_str(
            r#"
[global]
audit_log = "/base/log"
help_text = "base help"

[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["alice"]

[profiles.admin.global]
audit_log = "/admin/log"

[[profiles.admin.rules]]
action = { type = "run", binary = "/opt/test/bin/admintool", args = [] }
"#,
        )
        .unwrap();
        let resolved = cfg.resolve_for_user("alice").unwrap();
        assert_eq!(resolved.global.audit_log, "/admin/log");
        assert_eq!(resolved.global.help_text, "base help");
        assert_eq!(resolved.rules.len(), 2);
        assert!(matches!(resolved.rules[0].action, Action::ShowHelp));
        assert!(matches!(resolved.rules[1].action, Action::Run { .. }));
        assert!(resolved.profiles.is_empty());
    }

    #[test]
    fn test_resolve_for_user_multiple_match_error() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["alice"]

[profiles.dev]
users = ["alice"]
"#,
        )
        .unwrap();
        let err = cfg.resolve_for_user("alice").unwrap_err();
        assert!(
            err.to_string().contains("matches multiple profiles"),
            "expected multiple profile error, got: {err}"
        );
    }

    #[test]
    fn test_merge_profile_global_override() {
        let base: Config = toml::from_str(
            r#"
[global]
audit_log = "/base/log"
help_text = "base help"
[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();

        let profile: Profile = toml::from_str(
            r#"
users = ["alice"]
[global]
audit_log = "/admin/log"
"#,
        )
        .unwrap();

        let merged = base.merge_profile(&profile);
        assert_eq!(merged.global.audit_log, "/admin/log");
        assert_eq!(merged.global.help_text, "base help");
        assert_eq!(merged.rules.len(), 1);
    }

    #[test]
    fn test_merge_profile_rule_append() {
        let base: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();

        let profile = Profile {
            users: vec!["bob".into()],
            rules: Some(vec![Rule {
                action: Action::Run {
                    binary: "/opt/test/bin/tool".into(),
                    args: vec![],
                    timeout: Duration { millis: 5000 },
                },
                command: Some("tool".into()),
                implicit_symlinks: true,
                arg_style: ArgStyle::GnuLong,
                flag_groups: vec![],
                flags: vec![],
                args: vec![],
                pre_args: vec![],
                subcommands: vec![],
            }]),
            ..Default::default()
        };

        let merged = base.merge_profile(&profile);
        assert_eq!(merged.rules.len(), 2);
        assert!(matches!(merged.rules[0].action, Action::ShowHelp));
        assert_eq!(merged.rules[1].command_name(), Some("tool"));
    }

    #[test]
    fn test_merge_profile_contracts_map_merge() {
        let base: Config = toml::from_str(
            r#"
[contracts.port]
type = "int_range"
min = 1024
max = 65535

[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();

        let profile: Profile = toml::from_str(
            r#"
users = ["bob"]
[contracts.port]
type = "int_range"
min = 1
max = 9999
"#,
        )
        .unwrap();

        let merged = base.merge_profile(&profile);
        assert_eq!(merged.contracts.len(), 1);
        assert_eq!(int_range(&merged.contracts["port"]), Some((1, 9_999)));
    }

    #[test]
    fn test_merge_profile_roots_append_unique() {
        let base: Config = toml::from_str(
            r#"
roots = ["/base", "/common"]
[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();

        let profile: Profile = toml::from_str(
            r#"
users = ["bob"]
roots = ["/common", "/profile"]
"#,
        )
        .unwrap();

        let merged = base.merge_profile(&profile);
        assert_eq!(merged.roots, vec!["/base", "/common", "/profile"]);
    }

    #[test]
    fn test_merge_profile_named_root_sets_append_unique() {
        let base: Config = toml::from_str(
            r#"
[root_sets]
logs = ["/base/log", "/shared"]

[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();

        let profile: Profile = toml::from_str(
            r#"
users = ["bob"]

[root_sets]
logs = ["/shared", "/profile/log"]
data = ["/srv/data"]
"#,
        )
        .unwrap();

        let merged = base.merge_profile(&profile);
        let value: toml::Value = toml::from_str(&merged.to_toml_string().unwrap()).unwrap();
        assert_eq!(
            value["root_sets"]["logs"].as_array().unwrap(),
            &vec![
                toml::Value::String("/base/log".into()),
                toml::Value::String("/shared".into()),
                toml::Value::String("/profile/log".into())
            ]
        );
        assert_eq!(
            value["root_sets"]["data"].as_array().unwrap(),
            &vec![toml::Value::String("/srv/data".into())]
        );
    }

    #[test]
    fn test_merge_profile_units_append_unique() {
        let base: Config = toml::from_str(
            r#"
units = ["nginx", "sshd"]
[[rules]]
action = { type = "show_help" }
"#,
        )
        .unwrap();

        let profile: Profile = toml::from_str(
            r#"
users = ["bob"]
units = ["sshd", "httpd"]
"#,
        )
        .unwrap();

        let merged = base.merge_profile(&profile);
        assert_eq!(merged.units, vec!["nginx", "sshd", "httpd"]);
    }

    #[test]
    fn test_check_duplicate_users_no_dups() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["alice", "bob"]

[profiles.dev]
users = ["charlie"]
"#,
        )
        .unwrap();
        assert!(cfg.check_duplicate_users().is_ok());
    }

    #[test]
    fn test_check_duplicate_users_finds_dups() {
        let cfg: Config = toml::from_str(
            r#"
[[rules]]
action = { type = "show_help" }

[profiles.admin]
users = ["alice", "bob"]

[profiles.dev]
users = ["bob", "charlie"]
"#,
        )
        .unwrap();
        let err = cfg.check_duplicate_users().unwrap_err();
        assert!(
            err.to_string().contains("duplicate user"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn test_config_round_trip_with_profiles() {
        let original = Config {
            global: Global {
                audit_log: "/tmp/profile_test.log".into(),
                ..Global::default()
            },
            profiles: {
                let mut p = Profiles::new();
                p.insert(
                    "admin".into(),
                    Profile {
                        users: vec!["admin".into()],
                        global: None,
                        contracts: None,
                        flag_groups: None,
                        rules: None,
                        roots: None,
                        root_sets: None,
                        units: None,
                    },
                );
                p
            },
            ..Default::default()
        };

        let toml_str = original.to_toml_string().unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(deserialized.profiles.len(), 1);
        assert_eq!(
            deserialized.profiles["admin"].users,
            vec!["admin".to_string()]
        );
    }
}
