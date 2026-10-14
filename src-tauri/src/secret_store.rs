use serde::Serialize;

/// Where a stored credential actually lives. Serialized camelCase
/// (`"keychain"` / `"plaintextFile"`) so the settings UI can surface the
/// headless plaintext fallback the operator accepted in option (a).
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum StorageMode {
    Keychain,
    PlaintextFile,
}

/// The decision for one credential read, derived only from the keychain result
/// and the plaintext file, so it can be unit-tested with no OS keychain present.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretPlan {
    /// The keychain held the value.
    Keychain(String),
    /// The keychain is empty but a plaintext file holds the value; the caller
    /// should try to move it into the keychain.
    Migrate(String),
    /// The keychain errored (locked/absent) but a plaintext file still holds a
    /// usable value; the credential must not be hidden by the keychain error.
    Legacy(String),
    /// Nothing is stored.
    Empty,
    /// The keychain errored and there is no plaintext fallback.
    Unavailable(String),
}

pub fn plan_secret(keychain: Result<Option<String>, String>, legacy: Option<String>) -> SecretPlan {
    match keychain {
        Ok(Some(value)) => SecretPlan::Keychain(value),
        Ok(None) => match legacy {
            Some(value) => SecretPlan::Migrate(value),
            None => SecretPlan::Empty,
        },
        Err(error) => match legacy {
            Some(value) => SecretPlan::Legacy(value),
            None => SecretPlan::Unavailable(error),
        },
    }
}

/// Execute a plan. This is the whole read/migrate behaviour, expressed with
/// injected effects so the migration ordering and the failure path are testable
/// without a Secret Service:
///
/// - `legacy_file_present` — whether a plaintext file exists right now. The
///   `Keychain` arm uses it to **retry a removal that failed in an earlier
///   launch**, so a transient unlink failure (permissions, a Windows file
///   lock, a read-only volume) self-heals on the next read instead of leaving
///   a plaintext copy beside the keychain entry forever (round-3 verdict,
///   Issue 1);
/// - `write_keychain` attempts the migration write;
/// - `remove_plaintext` drops the file and is **fallible** — a failed unlink is
///   surfaced through `on_failure`, never swallowed;
/// - `on_failure` surfaces migration and removal failures. None of them is
///   silent: the operator accepted the plaintext fallback (option (a)) on the
///   condition that it stay user-visible.
pub fn apply_secret_plan(
    plan: SecretPlan,
    legacy_file_present: bool,
    write_keychain: impl FnOnce(&str) -> Result<(), String>,
    remove_plaintext: impl FnOnce() -> Result<(), String>,
    on_failure: impl FnOnce(&str),
) -> Result<Option<String>, String> {
    match plan {
        SecretPlan::Keychain(value) => {
            // The value is already safe in the keychain. If a plaintext copy
            // survived — a previous launch migrated the value but its unlink
            // failed — retry the removal now. The credential is never at risk
            // on this arm: the keychain already holds it.
            if legacy_file_present {
                if let Err(error) = remove_plaintext() {
                    on_failure(&format!(
                        "a plaintext copy survives next to the keychain entry; removal failed: {error}"
                    ));
                }
            }
            Ok(Some(value))
        }
        SecretPlan::Legacy(value) => Ok(Some(value)),
        SecretPlan::Empty => Ok(None),
        SecretPlan::Unavailable(error) => Err(error),
        SecretPlan::Migrate(value) => match write_keychain(&value) {
            Ok(()) => match remove_plaintext() {
                Ok(()) => Ok(Some(value)),
                Err(error) => {
                    on_failure(&format!(
                        "keychain write succeeded but the plaintext file could not be removed: {error}"
                    ));
                    Ok(Some(value))
                }
            },
            Err(error) => {
                on_failure(&format!(
                    "keychain write failed; keeping the plaintext file: {error}"
                ));
                Ok(Some(value))
            }
        },
    }
}

/// Which backing store currently holds the credential, for a status payload.
/// A plaintext file on disk **wins whenever it exists**, even if the keychain
/// also holds the value: the operator accepted the fallback on the condition
/// that it be user-visible, and a copy that survived a failed or partial
/// migration is exactly the residual case that must stay visible (round-3
/// verdict, Issue 1 — previously `storage_from` reported `Keychain` and kept
/// the warning silent while a plaintext token sat on disk).
pub fn storage_from(
    keychain: &Result<Option<String>, String>,
    file_present: bool,
) -> Option<StorageMode> {
    if file_present {
        Some(StorageMode::PlaintextFile)
    } else {
        match keychain {
            Ok(Some(_)) => Some(StorageMode::Keychain),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keychain(value: Option<&str>) -> Result<Option<String>, String> {
        Ok(value.map(str::to_string))
    }

    #[test]
    fn plan_prefers_the_keychain_value() {
        assert_eq!(
            plan_secret(keychain(Some("k")), Some("file".into())),
            SecretPlan::Keychain("k".into())
        );
    }

    #[test]
    fn plan_migrates_a_legacy_file_when_the_keychain_is_empty() {
        assert_eq!(
            plan_secret(keychain(None), Some("file".into())),
            SecretPlan::Migrate("file".into())
        );
    }

    #[test]
    fn plan_returns_empty_when_nothing_is_stored() {
        assert_eq!(plan_secret(keychain(None), None), SecretPlan::Empty);
    }

    #[test]
    fn plan_keeps_the_legacy_value_when_the_keychain_errors() {
        assert_eq!(
            plan_secret(Err("locked".into()), Some("file".into())),
            SecretPlan::Legacy("file".into())
        );
    }

    #[test]
    fn plan_surfaces_the_keychain_error_when_there_is_no_fallback() {
        assert_eq!(
            plan_secret(Err("locked".into()), None),
            SecretPlan::Unavailable("locked".into())
        );
    }

    #[test]
    fn migration_is_idempotent_once_the_keychain_holds_the_value() {
        // Second pass: the value the first pass migrated is read back from the
        // keychain, so no further write or file removal happens.
        let mut writes = 0;
        let mut removals = 0;
        let result = apply_secret_plan(
            plan_secret(keychain(Some("migrated")), None),
            false,
            |_| {
                writes += 1;
                Ok(())
            },
            || {
                removals += 1;
                Ok(())
            },
            |_| {},
        );
        assert_eq!(result, Ok(Some("migrated".into())));
        assert_eq!(writes, 0, "a keychain hit must not rewrite");
        assert_eq!(
            removals, 0,
            "a keychain hit with no surviving file must not attempt removal"
        );
    }

    #[test]
    fn a_successful_migration_writes_once_then_removes_the_file() {
        let mut writes = 0;
        let mut removals = 0;
        let result = apply_secret_plan(
            SecretPlan::Migrate("file".into()),
            true,
            |_| {
                writes += 1;
                Ok(())
            },
            || {
                removals += 1;
                Ok(())
            },
            |_| {},
        );
        assert_eq!(result, Ok(Some("file".into())));
        assert_eq!(writes, 1);
        assert_eq!(removals, 1);
    }

    #[test]
    fn a_failed_migration_keeps_the_file_and_surfaces_the_error() {
        let mut removals = 0;
        let mut surfaced: Option<String> = None;
        let result = apply_secret_plan(
            SecretPlan::Migrate("file".into()),
            true,
            |_| Err("no secret service".into()),
            || {
                removals += 1;
                Ok(())
            },
            |error| surfaced = Some(error.to_string()),
        );
        assert_eq!(result, Ok(Some("file".into())));
        assert_eq!(removals, 0, "the plaintext file must be kept on failure");
        let surfaced = surfaced.expect("a failed migration must not be silent");
        assert!(
            surfaced.contains("keychain write failed"),
            "got: {surfaced}"
        );
        assert!(surfaced.contains("no secret service"), "got: {surfaced}");
    }

    #[test]
    fn a_removal_that_fails_after_a_successful_migration_is_surfaced() {
        // Round-3 verdict Issue 1, first half: the keychain write succeeded but
        // the unlink failed. The value is safe; the failure must be surfaced,
        // not swallowed as `let _ = fs::remove_file(..)` was.
        let mut removals = 0;
        let mut surfaced: Option<String> = None;
        let result = apply_secret_plan(
            SecretPlan::Migrate("file".into()),
            true,
            |_| Ok(()),
            || {
                removals += 1;
                Err("read-only file system".into())
            },
            |error| surfaced = Some(error.to_string()),
        );
        assert_eq!(
            result,
            Ok(Some("file".into())),
            "the value is safe in the keychain"
        );
        assert_eq!(removals, 1, "removal must still be attempted");
        let surfaced = surfaced.expect("a failed removal must not be swallowed");
        assert!(surfaced.contains("could not be removed"), "got: {surfaced}");
        assert!(
            surfaced.contains("read-only file system"),
            "got: {surfaced}"
        );
    }

    #[test]
    fn the_keychain_arm_retries_removal_while_the_plaintext_file_survives() {
        // Round-3 verdict Issue 1, second half (CK-B pass 2): a previous
        // launch migrated the value but its unlink failed, so a plaintext copy
        // survives. This launch takes the Keychain arm and must retry the
        // removal instead of never touching the file again.
        let mut removals = 0;
        let mut surfaced: Option<String> = None;
        let result = apply_secret_plan(
            plan_secret(keychain(Some("migrated")), Some("file".into())),
            true,
            |_| panic!("a keychain hit must not rewrite"),
            || {
                removals += 1;
                Err("read-only file system".into())
            },
            |error| surfaced = Some(error.to_string()),
        );
        assert_eq!(result, Ok(Some("migrated".into())));
        assert_eq!(
            removals, 1,
            "the Keychain arm must retry removal while a file survives"
        );
        let surfaced = surfaced.expect("the failed retry must not be silent");
        assert!(
            surfaced.contains("survives next to the keychain entry"),
            "got: {surfaced}"
        );
        assert!(
            surfaced.contains("read-only file system"),
            "got: {surfaced}"
        );
    }

    #[test]
    fn the_keychain_arm_removes_a_surviving_file_without_surfacing_a_failure() {
        // The self-heal success path: the retry succeeds, nothing is surfaced.
        let mut removals = 0;
        let mut surfaced = 0;
        let result = apply_secret_plan(
            plan_secret(keychain(Some("migrated")), Some("file".into())),
            true,
            |_| panic!("a keychain hit must not rewrite"),
            || {
                removals += 1;
                Ok(())
            },
            |_| surfaced += 1,
        );
        assert_eq!(result, Ok(Some("migrated".into())));
        assert_eq!(removals, 1);
        assert_eq!(surfaced, 0, "a successful self-heal is not a failure");
    }

    #[test]
    fn a_keychain_hit_without_a_plaintext_file_attempts_no_removal() {
        // Guard against over-removal: no file, no removal attempt.
        let mut removals = 0;
        let result = apply_secret_plan(
            plan_secret(keychain(Some("k")), None),
            false,
            |_| panic!("a keychain hit must not rewrite"),
            || {
                removals += 1;
                Ok(())
            },
            |_| {},
        );
        assert_eq!(result, Ok(Some("k".into())));
        assert_eq!(removals, 0);
    }

    #[test]
    fn empty_and_unavailable_are_distinct() {
        assert_eq!(
            apply_secret_plan(SecretPlan::Empty, false, |_| Ok(()), || Ok(()), |_| {}),
            Ok(None)
        );
        assert_eq!(
            apply_secret_plan(
                SecretPlan::Unavailable("locked".into()),
                false,
                |_| Ok(()),
                || Ok(()),
                |_| {}
            ),
            Err("locked".into())
        );
    }

    #[test]
    fn storage_from_reports_where_the_credential_lives() {
        assert_eq!(
            storage_from(&keychain(Some("k")), false),
            Some(StorageMode::Keychain)
        );
        // A surviving plaintext copy is reported even when the keychain also
        // holds the value — the UI warning must cover the residual case.
        assert_eq!(
            storage_from(&keychain(Some("k")), true),
            Some(StorageMode::PlaintextFile)
        );
        assert_eq!(
            storage_from(&keychain(None), true),
            Some(StorageMode::PlaintextFile)
        );
        assert_eq!(
            storage_from(&Err("locked".into()), true),
            Some(StorageMode::PlaintextFile)
        );
        assert_eq!(storage_from(&keychain(None), false), None);
    }
}
