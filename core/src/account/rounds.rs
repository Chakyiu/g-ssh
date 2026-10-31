//! The steps of signing in and syncing that do not depend on a UI: what a round does on a worker
//! thread and how its answer goes into the vault. The apps own the timers and the threads.

use std::collections::BTreeMap;
use std::path::Path;

use secrecy::SecretString;
use uuid::Uuid;

use super::api::JoinRequest;
use super::team::{self, TeamError};
use super::{AccountError, Api, ApiError, GitHubStep};
use crate::vault::sync::{RecoveryJob, SyncJob, SyncResult, SyncState, TeamContext, TeamsUpdate};
use crate::vault::{NewVaultKeys, RecoveryPhrase, VaultError, VaultManager};

pub struct TeamsChecked {
    pub update: TeamsUpdate,
    /// People waiting to be let into a team, by team. Each was checked against the secret of an
    /// invite link made on this device.
    pub join_requests: BTreeMap<Uuid, Vec<(Uuid, JoinRequest)>>,
}

/// The answer of one round, for `take_in`.
pub enum Round {
    /// With the session token the round used.
    Synced(String, Vec<Result<SyncResult, ApiError>>),
    RecoveryTold(Result<Option<String>, ApiError>),
    /// With the session token the round used. `None` when the account has no team keys, so it
    /// is in no team.
    Teams(String, Result<Option<TeamsChecked>, TeamError>),
}

/// What one round sends. Made on the vault's thread, run on a worker.
pub enum RoundWork {
    TellRecovery(RecoveryJob),
    CheckTeams(TeamContext),
    Sync(Vec<SyncJob>),
}

impl RoundWork {
    /// `None` when there is nothing to do. `is_teams_due` is the app's timer; a vault behind on
    /// its teams checks them anyway.
    pub fn plan(
        vault: &VaultManager,
        is_teams_due: bool,
        has_synced_this_session: bool,
    ) -> Option<Self> {
        // The account must hear about a recovery first: until then it still checks the old
        // password.
        let recovery = vault.recovery_job();
        let jobs = vault.begin_sync();
        if let Some(recovery) = recovery {
            return Some(Self::TellRecovery(recovery));
        }
        if jobs.is_empty() {
            return None;
        }
        // Teams before items: a vault whose key changed cannot be read until the new key is
        // here. The first pull of a session is the exception.
        let is_teams_due = is_teams_due || vault.is_behind_on_teams();
        if is_teams_due && !is_first_pull(has_synced_this_session, &jobs) {
            if let Some(context) = vault.team_context() {
                return Some(Self::CheckTeams(context));
            }
        }
        Some(Self::Sync(jobs))
    }

    pub fn is_team_check(&self) -> bool {
        matches!(self, Self::CheckTeams(_))
    }

    /// Blocks on the network.
    pub fn run(self, api: &Api) -> Round {
        match self {
            Self::TellRecovery(recovery) => {
                Round::RecoveryTold(super::tell_recovery(api, &recovery))
            }
            Self::CheckTeams(context) => {
                let token = context.session_token.clone();
                Round::Teams(token, check_teams(api, &context))
            }
            Self::Sync(jobs) => {
                let token = jobs[0].session_token.clone();
                let results = jobs
                    .into_iter()
                    .map(|job| super::run_sync(api, job))
                    .collect();
                Round::Synced(token, results)
            }
        }
    }
}

/// Personal vault first: it holds the team pins a teams check needs. Only once per session, as
/// an empty vault never moves its cursor.
pub fn is_first_pull(has_synced_this_session: bool, jobs: &[SyncJob]) -> bool {
    !has_synced_this_session && jobs.first().is_some_and(|job| job.cursor == 0)
}

/// Fetch and check the account's teams, and who waits to join them.
pub fn check_teams(api: &Api, context: &TeamContext) -> Result<Option<TeamsChecked>, TeamError> {
    let keys = match team::ensure_keys(api, context, None) {
        Ok(keys) => keys,
        Err(TeamError::PasswordNeeded) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut update = team::refresh(api, context, &keys)?;
    let mut join_requests = BTreeMap::new();
    for (invite_id, invite) in &context.invites {
        let team_id = invite.team_id;
        // An invite of a team that failed its check is kept as it is.
        if !update.checked.contains(&team_id) {
            continue;
        }
        let (requests, open) = team::requests(api, context, team_id)?;
        if !open.contains(invite_id) {
            update.closed_invites.push(*invite_id);
        }
        join_requests.insert(team_id, requests);
    }
    Ok(Some(TeamsChecked {
        update,
        join_requests,
    }))
}

/// Apply a finished round to the vault. Returns whether another round should follow at once,
/// and whether any record changed.
pub fn take_in(vault: &mut VaultManager, round: Round) -> Result<(bool, bool), String> {
    let saved = |result: Result<(), VaultError>| {
        result.map_err(|e| format!("Could not save the vault: {e}"))
    };
    match round {
        Round::Synced(token, results) => {
            // The personal vault comes first. When it failed, the team vaults wait too: a host
            // moving into a team must leave here before it arrives there.
            let is_personal_ok = results.first().is_some_and(Result::is_ok);
            let mut answers = Vec::new();
            let mut problem = None;
            for (index, result) in results.into_iter().enumerate() {
                match result {
                    Ok(result) if is_personal_ok => answers.push(result),
                    Ok(_) => {}
                    Err(e) if e.is_session_ended() => {
                        saved(vault.end_session(&token))?;
                        return Ok((false, false));
                    }
                    // A team vault got a new key, or it was deleted, or this account no longer
                    // sees it. The team check sorts that out.
                    Err(e) if index > 0 && is_team_news(&e) => vault.note_behind_on_teams(),
                    // One full or broken team vault must not stop the others.
                    Err(e) => problem = problem.or(Some(e.to_string())),
                }
            }
            let changed = vault
                .finish_round(answers)
                .map_err(|e| format!("Could not save the vault: {e}"))?;
            match problem {
                Some(problem) if changed == 0 => Err(problem),
                problem => {
                    // Not shown: the round did bring changes in.
                    if let Some(problem) = problem {
                        tracing::warn!(error = %problem, "a vault failed to sync in a round that changed others");
                    }
                    Ok((
                        vault.has_unsynced_changes() || vault.is_behind_on_teams(),
                        changed > 0,
                    ))
                }
            }
        }
        Round::RecoveryTold(Ok(session_token)) => {
            let is_signed_in = session_token.is_some();
            saved(vault.finish_recovery(session_token))?;
            Ok((is_signed_in, false))
        }
        Round::Teams(token, Err(TeamError::Api(e))) if e.is_session_ended() => {
            saved(vault.end_session(&token))?;
            Ok((false, false))
        }
        Round::Teams(_, Ok(Some(checked))) => {
            saved(vault.apply_teams(checked.update))?;
            // The items come next, in a round of their own.
            Ok((true, true))
        }
        Round::Teams(_, Ok(None)) => {
            vault.forget_behind_on_teams();
            Ok((true, false))
        }
        Round::Teams(_, Err(e)) => {
            // Otherwise every round retries the team check and items never sync.
            vault.forget_behind_on_teams();
            Err(e.to_string())
        }
        Round::RecoveryTold(Err(e)) => Err(e.to_string()),
    }
}

fn is_team_news(error: &ApiError) -> bool {
    matches!(error.code(), Some("key_rotated" | "vault_not_found"))
}

/// Best effort: a session left open holds nothing this device still uses.
pub fn log_out_quietly(token: Option<String>) {
    let Some(token) = token else { return };
    std::thread::spawn(move || {
        if let Err(e) = Api::shared().logout(&token) {
            tracing::warn!(error = %e, "could not close the sync session on the server");
        }
    });
}

/// A vault made on this device from a g-ssh account.
pub enum Created {
    Opened(VaultManager),
    /// A new account. The user has not seen this phrase yet.
    WithPhrase(VaultManager, RecoveryPhrase),
}

pub enum PreVaultError {
    /// Nothing was written.
    Account(AccountError),
    /// Nothing was sent to the server.
    VaultExists,
    /// Signed in, but the vault file was not written.
    NotSaved(VaultError),
    /// Registered, but not written. The keys come back for a retry.
    RegisteredNotSaved(VaultError, Box<UnsavedVault>),
}

/// Accepted by the server, not yet written to disk.
pub struct UnsavedVault {
    pub keys: NewVaultKeys,
    pub state: SyncState,
    pub phrase: RecoveryPhrase,
}

impl From<AccountError> for PreVaultError {
    fn from(error: AccountError) -> Self {
        Self::Account(error)
    }
}

/// Blocks on Argon2id and the network.
pub fn create_vault_for(
    path: &Path,
    step: &GitHubStep,
    password: &SecretString,
) -> Result<Created, PreVaultError> {
    // Before any request, so an existing vault is never replaced.
    if crate::vault::vault_path_occupied(path) {
        return Err(PreVaultError::VaultExists);
    }
    let api = Api::shared();
    if step.is_new {
        let (keys, phrase) = NewVaultKeys::generate(password).map_err(AccountError::Vault)?;
        let state = super::register_new_vault(&api, step, &keys)?;
        return save_registered(
            path,
            UnsavedVault {
                keys,
                state,
                phrase,
            },
        );
    }
    // A wrong password fails here, before anything is written.
    let account = super::sign_in(&api, step, password)?;
    let token = account.state.session_token.clone();
    VaultManager::create_from_account(path, account)
        .map(Created::Opened)
        .map_err(|e| {
            log_out_quietly(token);
            PreVaultError::NotSaved(e)
        })
}

/// On failure the keys come back and the session stays open for a retry.
pub fn save_registered(path: &Path, unsaved: UnsavedVault) -> Result<Created, PreVaultError> {
    match VaultManager::create_registered(path, &unsaved.keys, &unsaved.state) {
        Ok(manager) => Ok(Created::WithPhrase(manager, unsaved.phrase)),
        Err(e) => Err(PreVaultError::RegisteredNotSaved(e, Box::new(unsaved))),
    }
}

pub fn retry_registered(unsaved: UnsavedVault) -> Result<Created, PreVaultError> {
    let path = match crate::vault::default_vault_path() {
        Ok(path) => path,
        Err(e) => return Err(PreVaultError::RegisteredNotSaved(e, Box::new(unsaved))),
    };
    retry_registered_at(&path, unsaved)
}

pub fn retry_registered_at(path: &Path, unsaved: UnsavedVault) -> Result<Created, PreVaultError> {
    // Checked again: a vault made since then is never replaced.
    if crate::vault::vault_path_occupied(path) {
        log_out_quietly(unsaved.state.session_token.clone());
        return Err(PreVaultError::VaultExists);
    }
    save_registered(path, unsaved)
}

/// A sign-in error as a line for the user.
pub fn sign_in_problem(error: &AccountError, is_new: bool) -> String {
    match error {
        AccountError::Vault(VaultError::InvalidPassword) => "Wrong master password.".into(),
        AccountError::Api(api) => match api.code() {
            Some("wrong_password") if is_new => "Wrong master password.".into(),
            Some("wrong_password") => "Wrong password for this account.".into(),
            Some("too_many_attempts") => "Too many wrong passwords. Try again in an hour.".into(),
            Some("ticket_invalid") => "The sign-in expired. Sign in with GitHub again.".into(),
            Some("account_exists") => {
                "This GitHub account already has a g-ssh account. Sign in with GitHub again.".into()
            }
            _ => api.to_string(),
        },
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::KdfParams;
    use crate::vault::sync::{Registration, TeamState, TeamUpdate, VaultKey};

    fn refused(status: u16, code: &str) -> ApiError {
        ApiError::Refused {
            status,
            code: code.into(),
            message: format!("refused: {code}"),
        }
    }

    /// A signed-in vault in a team with one vault. Returns the team vault's id.
    fn vault_in_a_team(dir: &tempfile::TempDir) -> (VaultManager, Uuid) {
        let password = SecretString::from("pw");
        let kdf = KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };
        let (mut vault, _) =
            VaultManager::create_with_params(&dir.path().join("vault.json"), &password, kdf)
                .unwrap();
        let slot = vault.password_slot().enc_dek_by_password().clone();
        vault
            .install_registration(Registration {
                replaces: slot.clone(),
                enc_dek_by_recovery: slot,
                state: SyncState::new(Uuid::nil(), "alice".into(), "token".into(), Uuid::nil()),
            })
            .unwrap();
        let (team_id, vault_id) = (Uuid::new_v4(), Uuid::new_v4());
        let state = TeamState {
            name: "ops".into(),
            roster: Vec::new(),
            logins: BTreeMap::new(),
            left: Vec::new(),
            vault_names: vec![(vault_id, None)],
        };
        let vaults = vec![VaultKey {
            vault_id,
            key: [7; 32],
            key_version: 1,
        }];
        vault
            .add_team(TeamUpdate {
                team_id,
                state,
                vaults,
                pin: None,
            })
            .unwrap();
        (vault, vault_id)
    }

    fn nothing_new(vault_id: Uuid) -> Result<SyncResult, ApiError> {
        Ok(SyncResult {
            vault_id,
            started_at: 0,
            pulled: Vec::new(),
            cursor: 0,
            pushed: Vec::new(),
        })
    }

    #[test]
    fn a_team_vault_that_is_gone_asks_for_a_team_check_and_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = vault_in_a_team(&dir);
        let answers = vec![
            nothing_new(Uuid::nil()),
            Err(refused(404, "vault_not_found")),
        ];

        let outcome = take_in(&mut vault, Round::Synced("token".into(), answers));

        assert_eq!(outcome, Ok((true, false)));
        assert!(vault.is_behind_on_teams());
    }

    #[test]
    fn a_full_team_vault_is_still_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = vault_in_a_team(&dir);
        let answers = vec![nothing_new(Uuid::nil()), Err(refused(413, "vault_full"))];

        let outcome = take_in(&mut vault, Round::Synced("token".into(), answers));

        assert_eq!(outcome, Err("refused: vault_full".to_string()));
        assert!(!vault.is_behind_on_teams());
    }

    #[test]
    fn a_missing_personal_vault_is_an_error_and_not_team_news() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, vault_id) = vault_in_a_team(&dir);
        let answers = vec![Err(refused(404, "vault_not_found")), nothing_new(vault_id)];

        let outcome = take_in(&mut vault, Round::Synced("token".into(), answers));

        assert_eq!(outcome, Err("refused: vault_not_found".to_string()));
        assert!(!vault.is_behind_on_teams());
    }

    #[test]
    fn signing_in_before_a_vault_stops_when_a_vault_file_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        std::fs::write(&path, b"not a vault").unwrap();
        // A ticket the server would refuse: the test fails if it is sent.
        let step = GitHubStep {
            ticket: "no-such-ticket".into(),
            is_new: false,
            github_login: "alice".into(),
            kdf: None,
        };

        let created = create_vault_for(&path, &step, &SecretString::from("pw"));

        assert!(matches!(created, Err(PreVaultError::VaultExists)));
        assert_eq!(std::fs::read(&path).unwrap(), b"not a vault");
    }

    #[test]
    fn a_new_account_vault_that_failed_to_save_is_written_with_the_same_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let kdf = KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };
        let password = SecretString::from("pw");
        let (keys, phrase) = NewVaultKeys::generate_with_params(&password, kdf.clone()).unwrap();
        let words = phrase.expose_words().to_string();
        let state = SyncState::new(Uuid::new_v4(), "alice".into(), "token".into(), Uuid::nil());
        // A file where the vault's folder should be, so the write fails.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"").unwrap();

        let failed = save_registered(
            &blocker.join("vault.json"),
            UnsavedVault {
                keys,
                state,
                phrase,
            },
        );
        let Err(PreVaultError::RegisteredNotSaved(_, unsaved)) = failed else {
            panic!("the write should fail and hand the keys back");
        };
        let path = dir.path().join("vault.json");
        let Ok(Created::WithPhrase(vault, phrase)) = retry_registered_at(&path, *unsaved) else {
            panic!("the second write should succeed");
        };

        assert_eq!(phrase.expose_words(), words);
        vault.lock();
        VaultManager::unlock_with_recovery_with_params(
            &path,
            &phrase,
            &SecretString::from("new"),
            kdf,
        )
        .unwrap();
    }

    #[test]
    fn a_team_check_refused_for_the_session_ends_it() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = vault_in_a_team(&dir);
        let refusal = Err(TeamError::Api(refused(401, "unauthorized")));

        let outcome = take_in(&mut vault, Round::Teams("token".into(), refusal));

        assert_eq!(outcome, Ok((false, false)));
        let state = vault.sync_state().unwrap();
        assert_eq!(state.session_token, None);
    }

    #[test]
    fn an_account_without_team_keys_stops_asking_for_team_checks() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = vault_in_a_team(&dir);
        vault.note_behind_on_teams();

        let outcome = take_in(&mut vault, Round::Teams("token".into(), Ok(None)));

        assert_eq!(outcome, Ok((true, false)));
        assert!(!vault.is_behind_on_teams());
    }

    #[test]
    fn a_failed_team_check_lets_the_next_round_sync_items() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = vault_in_a_team(&dir);
        vault.note_behind_on_teams();
        let failure = Err(TeamError::Untrusted(
            "the team keys on the server do not open",
        ));

        let outcome = take_in(&mut vault, Round::Teams("token".into(), failure));

        assert!(outcome.is_err());
        assert!(!vault.is_behind_on_teams());
    }

    fn personal_job_at(cursor: u64) -> SyncJob {
        SyncJob {
            session_token: "token".into(),
            vault_id: Uuid::nil(),
            key_version: 1,
            cursor,
            changes: Vec::new(),
        }
    }

    #[test]
    fn a_vault_that_never_pulled_pulls_its_personal_vault_before_the_teams() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = vault_in_a_team(&dir);

        assert!(is_first_pull(false, &vault.begin_sync()));
        let work = RoundWork::plan(&vault, true, false);
        assert!(matches!(work, Some(RoundWork::Sync(_))));
    }

    #[test]
    fn a_vault_that_synced_this_session_checks_its_teams_when_due() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = vault_in_a_team(&dir);

        assert!(RoundWork::plan(&vault, true, true).is_some_and(|work| work.is_team_check()));
        assert!(matches!(
            RoundWork::plan(&vault, false, true),
            Some(RoundWork::Sync(_))
        ));
    }

    #[test]
    fn a_vault_behind_on_its_teams_checks_them_before_the_timer() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, _) = vault_in_a_team(&dir);
        vault.note_behind_on_teams();

        assert!(RoundWork::plan(&vault, false, true).is_some_and(|work| work.is_team_check()));
    }

    #[test]
    fn an_empty_personal_vault_goes_first_only_once_per_session() {
        let jobs = vec![personal_job_at(0)];

        assert!(is_first_pull(false, &jobs));
        assert!(!is_first_pull(true, &jobs));
    }

    #[test]
    fn a_vault_that_pulled_before_checks_the_teams_first() {
        assert!(!is_first_pull(false, &[personal_job_at(66)]));
    }

    #[test]
    fn no_jobs_is_not_a_first_pull() {
        assert!(!is_first_pull(false, &[]));
    }
}
