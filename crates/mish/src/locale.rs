//! Locale resolution for the child shell.
//!
//! The terminal emulator (vte/alacritty) decodes child output as **UTF-8**. If
//! the child runs under a non-UTF-8 locale it will emit text in some other
//! encoding (Latin-1, GBK, …) and the rendered screen — and therefore everything
//! synchronized to the client — is corrupted. Real mosh refuses to start without
//! a UTF-8 locale for exactly this reason.
//!
//! We're more lenient: resolve the effective locale from the standard POSIX
//! precedence, and if it isn't UTF-8, fall back to a UTF-8 locale for the child
//! and warn, rather than aborting the session. The decision logic is pure so it
//! can be unit-tested without touching the process environment.

/// The locale environment variables, in POSIX precedence order: `LC_ALL`
/// overrides everything, then the category (`LC_CTYPE` governs character
/// encoding), then `LANG`.
pub const LOCALE_VARS: [&str; 3] = ["LC_ALL", "LC_CTYPE", "LANG"];

/// The UTF-8 locale to impose when none is configured. `C.UTF-8` is the most
/// portable choice (always present on glibc/musl systems); it may be absent on
/// some BSDs, where the warning still alerts the operator.
pub const FALLBACK_LOCALE: &str = "C.UTF-8";

/// What to do about the child's locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalePlan {
    /// An existing variable already selects a UTF-8 locale; leave the
    /// environment untouched. Carries `"VAR=value"` for logging.
    AlreadyUtf8(String),
    /// No UTF-8 locale was found. Impose [`FALLBACK_LOCALE`] via `LC_ALL` (so it
    /// overrides any non-UTF-8 `LANG`/`LC_*` already present) and warn.
    Fallback,
}

/// Whether a locale value selects the UTF-8 codeset (e.g. `en_US.UTF-8`,
/// `C.utf8`). Case- and hyphen-insensitive, matching how libc compares codesets.
pub fn is_utf8(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace('-', "");
    normalized.contains("utf8")
}

/// Decide the locale plan given a lookup into the environment (so callers can
/// pass `|k| std::env::var(k).ok()` and tests can pass a fixture).
pub fn plan_locale<F: Fn(&str) -> Option<String>>(get: F) -> LocalePlan {
    for var in LOCALE_VARS {
        match get(var) {
            // An empty value is "unset" for locale purposes; keep looking.
            Some(val) if !val.is_empty() => {
                if is_utf8(&val) {
                    return LocalePlan::AlreadyUtf8(format!("{var}={val}"));
                }
                // A non-UTF-8 LC_ALL/LC_CTYPE shadows everything below it, so a
                // lower-precedence UTF-8 LANG wouldn't actually take effect —
                // stop and fall back.
                return LocalePlan::Fallback;
            }
            _ => {}
        }
    }
    LocalePlan::Fallback
}

/// Resolve and apply the locale to the current process's environment (which the
/// child inherits). Returns a human-readable note for logging. Call after any
/// explicit `-l KEY=VAL` overrides have been exported.
pub fn ensure_utf8_locale() -> String {
    match plan_locale(|k| std::env::var(k).ok()) {
        LocalePlan::AlreadyUtf8(found) => format!("locale ok ({found})"),
        LocalePlan::Fallback => {
            std::env::set_var("LC_ALL", FALLBACK_LOCALE);
            format!(
                "no UTF-8 locale in LC_ALL/LC_CTYPE/LANG; forcing LC_ALL={FALLBACK_LOCALE} \
                 (non-UTF-8 output would otherwise render corrupted)"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn detects_utf8_variants() {
        assert!(is_utf8("en_US.UTF-8"));
        assert!(is_utf8("C.utf8"));
        assert!(is_utf8("de_DE.utf-8"));
        assert!(!is_utf8("C"));
        assert!(!is_utf8("en_US"));
        assert!(!is_utf8("ru_RU.KOI8-R"));
        assert!(!is_utf8("POSIX"));
    }

    #[test]
    fn lc_all_utf8_wins() {
        assert_eq!(
            plan_locale(env(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "C")])),
            LocalePlan::AlreadyUtf8("LC_ALL=en_US.UTF-8".into())
        );
    }

    #[test]
    fn lang_utf8_used_when_no_lc() {
        assert_eq!(
            plan_locale(env(&[("LANG", "fr_FR.UTF-8")])),
            LocalePlan::AlreadyUtf8("LANG=fr_FR.UTF-8".into())
        );
    }

    #[test]
    fn non_utf8_lc_all_shadows_utf8_lang() {
        // LC_ALL is highest precedence; a non-UTF-8 LC_ALL means LANG can't help.
        assert_eq!(
            plan_locale(env(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")])),
            LocalePlan::Fallback
        );
    }

    #[test]
    fn empty_values_are_skipped() {
        assert_eq!(
            plan_locale(env(&[("LC_ALL", ""), ("LANG", "en_US.UTF-8")])),
            LocalePlan::AlreadyUtf8("LANG=en_US.UTF-8".into())
        );
    }

    #[test]
    fn nothing_set_falls_back() {
        assert_eq!(plan_locale(env(&[])), LocalePlan::Fallback);
    }
}
