use std::collections::HashMap;
use std::fmt::Write as _;

use ssh_guard::config::{
    Config,
    action::Action,
    arg::ArgStyle,
    contract::Contract,
    duration::{Duration, parse_duration},
    global::Global,
    profile::{GlobalOverride, Profile},
    rule::Rule,
    subcommand::Subcommand,
};
use ssh_guard::engine::match_command;
use tempfile::NamedTempFile;

fn main() {
    divan::main();
}

fn run_action(binary: &str) -> Action {
    Action::Run {
        binary: binary.to_string(),
        args: vec![],
        timeout: Duration::default(),
    }
}

fn base_rule(command: &str) -> Rule {
    Rule {
        action: run_action(&format!("/usr/bin/{command}")),
        command: Some(command.to_string()),
        implicit_symlinks: true,
        arg_style: ArgStyle::GnuLong,
        flag_groups: vec![],
        flags: vec![],
        args: vec![],
        pre_args: vec![],
        subcommands: vec![],
    }
}

fn make_rule_with_args(command: &str, flags: Vec<String>, args: Vec<String>) -> Rule {
    Rule {
        flags,
        args,
        ..base_rule(command)
    }
}

fn nested_subcommand(level: usize, depth: usize) -> Subcommand {
    let name = format!("sub-{level}");
    let subcommands = if level + 1 == depth {
        vec![]
    } else {
        vec![nested_subcommand(level + 1, depth)]
    };
    let args = if level + 1 == depth {
        vec!["{string}".to_string()]
    } else {
        vec![]
    };

    Subcommand {
        name,
        arg_style: None,
        flag_groups: vec![],
        flags: vec![],
        args,
        pre_args: vec![],
        subcommands,
    }
}

fn config_with_rules(rule_count: usize) -> Config {
    let mut rules = Vec::with_capacity(rule_count);
    for idx in 0..rule_count.saturating_sub(1) {
        rules.push(base_rule(&format!("cmd-{idx}")));
    }
    rules.push(base_rule("target"));

    Config {
        global: Global::default(),
        contracts: HashMap::new(),
        flag_groups: HashMap::new(),
        rules,
        roots: vec![],
        units: vec![],
        profiles: HashMap::new(),
    }
}

fn ambiguous_backtracking_argv(pair_count: usize) -> Vec<String> {
    let mut argv = vec!["bench".to_string()];
    for idx in 0..pair_count {
        argv.push("--opt".to_string());
        argv.push(format!("value-{idx}"));
    }
    argv.push("--deny".to_string());
    argv
}

fn enum_contract_config(enum_size: usize) -> (Config, Vec<String>) {
    let values: Vec<String> = (0..enum_size).map(|idx| format!("unit-{idx}")).collect();
    let target = values
        .last()
        .cloned()
        .unwrap_or_else(|| "unit-0".to_string());

    let mut contracts = HashMap::new();
    contracts.insert("unit".to_string(), Contract::Enum { values });

    let config = Config {
        global: Global::default(),
        contracts,
        flag_groups: HashMap::new(),
        rules: vec![make_rule_with_args(
            "systemctl",
            vec![],
            vec!["{unit}".to_string()],
        )],
        roots: vec![],
        units: vec![],
        profiles: HashMap::new(),
    };

    (config, vec!["systemctl".to_string(), target])
}

fn complex_pattern_rule(pattern_count: usize) -> Rule {
    let mut args = Vec::with_capacity(pattern_count + 1);
    for idx in 0..pattern_count {
        args.push(format!("--opt-{idx}={{capture_{idx}:string|int|any}}"));
    }
    args.push("--match={payload:int|string|any}".to_string());
    make_rule_with_args("bench", vec![], args)
}

fn nested_config(depth: usize) -> (Config, Vec<String>) {
    let subcommands = if depth == 0 {
        vec![]
    } else {
        vec![nested_subcommand(0, depth)]
    };
    let rule = Rule {
        subcommands,
        args: if depth == 0 {
            vec!["{string}".to_string()]
        } else {
            vec![]
        },
        ..base_rule("systemctl")
    };

    let mut argv = vec!["systemctl".to_string()];
    for level in 0..depth {
        argv.push(format!("sub-{level}"));
    }
    argv.push("payload".to_string());

    (
        Config {
            global: Global::default(),
            contracts: HashMap::new(),
            flag_groups: HashMap::new(),
            rules: vec![rule],
            roots: vec![],
            units: vec![],
            profiles: HashMap::new(),
        },
        argv,
    )
}

fn config_parse_fixture(rule_count: usize) -> String {
    let mut toml =
        String::from("[global]\nhelp_text = \"bench\"\nlog_tag = \"ssh-guard-bench\"\n\n");

    for idx in 0..rule_count {
        let _ = writeln!(
            toml,
            "[[rules]]\ncommand = \"cmd-{idx}\"\naction = {{ type = \"run\", binary = \"/usr/bin/cmd-{idx}\", timeout = \"2.5s\" }}\nflags = [\"--verbose\"]\nargs = [\"--depth={{int}}\", \"{{unit}}.service\"]\n"
        );
    }

    toml.push_str("[profiles.admin]\nusers = [\"bench-user\"]\nroots = [\"/srv/admin\"]\nunits = [\"sshd.service\"]\n\n");
    toml.push_str("[profiles.admin.global]\nhelp_text = \"admin\"\n\n");
    toml.push_str("[profiles.admin.contracts.unit]\ntype = \"enum\"\nvalues = [\"sshd\", \"nginx\", \"postgres\"]\n\n");

    toml
}

struct ConfigFileFixture {
    _file: NamedTempFile,
    path: String,
}

fn config_file_fixture(rule_count: usize) -> ConfigFileFixture {
    let toml = config_parse_fixture(rule_count);
    let mut file = NamedTempFile::new().expect("temp file");
    std::io::Write::write_all(&mut file, toml.as_bytes()).expect("write config");
    ConfigFileFixture {
        path: file.path().display().to_string(),
        _file: file,
    }
}

fn resolve_profile_config(rule_count: usize) -> Config {
    let mut rules = Vec::with_capacity(rule_count);
    for idx in 0..rule_count {
        rules.push(base_rule(&format!("base-{idx}")));
    }

    let mut contracts = HashMap::new();
    contracts.insert(
        "port".to_string(),
        Contract::IntRange {
            min: 1024,
            max: 65535,
        },
    );

    let profile = Profile {
        users: vec!["bench-user".to_string()],
        global: Some(GlobalOverride {
            help_text: Some("profile-help".to_string()),
            ..GlobalOverride::default()
        }),
        contracts: Some({
            let mut overrides = HashMap::new();
            overrides.insert(
                "unit".to_string(),
                Contract::Enum {
                    values: vec!["sshd".to_string(), "nginx".to_string()],
                },
            );
            overrides
        }),
        flag_groups: Some({
            let mut groups = HashMap::new();
            groups.insert(
                "common".to_string(),
                vec!["--all".to_string(), "--verbose".to_string()],
            );
            groups
        }),
        rules: Some(vec![make_rule_with_args(
            "profile-cmd",
            vec!["--json".to_string()],
            vec!["{port}".to_string()],
        )]),
        roots: Some(vec!["/srv/profile".to_string(), "/srv/shared".to_string()]),
        units: Some(vec![
            "sshd.service".to_string(),
            "nginx.service".to_string(),
        ]),
    };

    let mut profiles = HashMap::new();
    profiles.insert("admin".to_string(), profile);

    Config {
        global: Global::default(),
        contracts,
        flag_groups: HashMap::new(),
        rules,
        roots: vec!["/srv/base".to_string(), "/srv/shared".to_string()],
        units: vec!["base.service".to_string()],
        profiles,
    }
}

mod matcher {
    use super::*;

    #[divan::bench(args = [1usize, 8, 64, 256])]
    fn many_rules_hit_last(bencher: divan::Bencher, rule_count: usize) {
        let config = config_with_rules(rule_count);
        let argv = vec!["target".to_string()];

        bencher.bench(|| {
            let result = match_command(divan::black_box(&config), divan::black_box(&argv)).unwrap();
            divan::black_box(result.rule_index)
        });
    }

    #[divan::bench(args = [0usize, 1, 4, 8, 16])]
    fn nested_subcommands_success(bencher: divan::Bencher, depth: usize) {
        let (config, argv) = nested_config(depth);

        bencher.bench(|| {
            let result = match_command(divan::black_box(&config), divan::black_box(&argv)).unwrap();
            divan::black_box(result.subcommand_path.len())
        });
    }

    #[divan::bench(args = [1usize, 8, 32, 128])]
    fn complex_pattern_parsing_success(bencher: divan::Bencher, pattern_count: usize) {
        let config = Config {
            global: Global::default(),
            contracts: HashMap::new(),
            flag_groups: HashMap::new(),
            rules: vec![complex_pattern_rule(pattern_count)],
            roots: vec![],
            units: vec![],
            profiles: HashMap::new(),
        };
        let argv = vec!["bench".to_string(), "--match=42".to_string()];

        bencher.bench(|| {
            let result = match_command(divan::black_box(&config), divan::black_box(&argv)).unwrap();
            divan::black_box(result.captures.len())
        });
    }

    #[divan::bench(args = [4usize, 32, 256, 1024])]
    fn enum_contract_validation_success(bencher: divan::Bencher, enum_size: usize) {
        let (config, argv) = enum_contract_config(enum_size);

        bencher.bench(|| {
            let result = match_command(divan::black_box(&config), divan::black_box(&argv)).unwrap();
            divan::black_box(result.captures.len())
        });
    }

    #[divan::bench(args = [2usize, 4, 6])]
    fn adversarial_flag_value_backtracking_reject(bencher: divan::Bencher, pair_count: usize) {
        let config = Config {
            global: Global::default(),
            contracts: HashMap::new(),
            flag_groups: HashMap::new(),
            rules: vec![make_rule_with_args(
                "bench",
                vec!["--opt".to_string()],
                vec!["{string}".to_string()],
            )],
            roots: vec![],
            units: vec![],
            profiles: HashMap::new(),
        };
        let argv = ambiguous_backtracking_argv(pair_count);

        bencher.bench(|| {
            let result = match_command(divan::black_box(&config), divan::black_box(&argv));
            divan::black_box(result.is_err())
        });
    }
}

mod config {
    use super::*;

    #[divan::bench(args = [8usize, 64, 256])]
    fn from_file_rule_count(bencher: divan::Bencher, rule_count: usize) {
        let fixture = config_file_fixture(rule_count);

        bencher.bench(|| {
            let config = Config::from_file(divan::black_box(fixture.path.as_str())).unwrap();
            divan::black_box(config.rules.len())
        });
    }

    #[divan::bench(args = [8usize, 64, 256])]
    fn resolve_for_user_large_merge(bencher: divan::Bencher, rule_count: usize) {
        let config = resolve_profile_config(rule_count);

        bencher.bench(|| {
            let resolved = config
                .resolve_for_user(divan::black_box("bench-user"))
                .unwrap();
            divan::black_box((
                resolved.rules.len(),
                resolved.roots.len(),
                resolved.units.len(),
            ))
        });
    }
}

mod duration {
    use super::*;

    #[divan::bench(args = ["5000ms", "2.5s", "1.5h", "999999999ms", "0.125m"]) ]
    fn parse_common_shapes(input: &str) {
        let duration = parse_duration(divan::black_box(input)).unwrap();
        divan::black_box(duration.millis);
    }
}
