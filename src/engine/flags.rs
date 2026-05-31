use std::collections::HashMap;

use crate::config::arg::ArgStyle;
use crate::config::rule::Rule;
use crate::config::subcommand::Subcommand;

pub(crate) fn is_flag_like(token: &str, style: &ArgStyle) -> bool {
    match style {
        ArgStyle::GnuLong => token.starts_with("--"),
        ArgStyle::PosixShort => token.starts_with('-') && !token.starts_with("--"),
        ArgStyle::Dos => token.starts_with('/'),
    }
}

pub(crate) fn expand_flags(
    flag_groups_map: &HashMap<String, Vec<String>>,
    groups: &[String],
    inline: &[String],
) -> Vec<String> {
    let mut all = inline.to_vec();
    for g in groups {
        if let Some(fs) = flag_groups_map.get(g) {
            all.extend(fs.clone());
        }
    }
    all
}

pub(crate) fn effective_style<'a>(rule: &'a Rule, sub: Option<&'a Subcommand>) -> &'a ArgStyle {
    sub.and_then(|s| s.arg_style.as_ref())
        .unwrap_or(&rule.arg_style)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::arg::ArgStyle;
    use std::collections::HashMap;

    #[test]
    fn test_is_flag_like_gnu() {
        assert!(is_flag_like("--porcelain", &ArgStyle::GnuLong));
        assert!(!is_flag_like("status", &ArgStyle::GnuLong));
        assert!(!is_flag_like("-p", &ArgStyle::GnuLong));
        assert!(!is_flag_like("/v", &ArgStyle::GnuLong));
        assert!(!is_flag_like("-x", &ArgStyle::GnuLong));
        assert!(is_flag_like("--", &ArgStyle::GnuLong));
    }

    #[test]
    fn test_is_flag_like_posix() {
        assert!(is_flag_like("-p", &ArgStyle::PosixShort));
        assert!(!is_flag_like("--porcelain", &ArgStyle::PosixShort));
        assert!(!is_flag_like("status", &ArgStyle::PosixShort));
        assert!(!is_flag_like("/v", &ArgStyle::PosixShort));
        assert!(is_flag_like("-abc", &ArgStyle::PosixShort));
        assert!(!is_flag_like("--long", &ArgStyle::PosixShort));
    }

    #[test]
    fn test_is_flag_like_dos() {
        assert!(is_flag_like("/v", &ArgStyle::Dos));
        assert!(!is_flag_like("--verbose", &ArgStyle::Dos));
        assert!(!is_flag_like("status", &ArgStyle::Dos));
        assert!(!is_flag_like("-p", &ArgStyle::Dos));
        assert!(is_flag_like("/", &ArgStyle::Dos));
    }

    #[test]
    fn test_expand_flags() {
        let mut groups = HashMap::new();
        groups.insert("g1".into(), vec!["-a".into(), "-b".into()]);
        groups.insert("g2".into(), vec!["-c".into()]);
        let result = expand_flags(&groups, &["g1".into(), "g2".into()], &["-x".into()]);
        assert_eq!(result, vec!["-x", "-a", "-b", "-c"]);
    }

    #[test]
    fn test_expand_flags_empty_groups() {
        let groups = HashMap::new();
        let result = expand_flags(&groups, &[], &["-x".into()]);
        assert_eq!(result, vec!["-x"]);
    }
}
