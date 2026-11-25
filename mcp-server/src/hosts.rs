//! Saved hosts and the route `SshConnection` dials. Credentials stay inside
//! the route; list output never includes them.

use gssh::ssh::route::{self, CredentialIssue};
use gssh::ssh::KeyIssue;
use gssh::vault::{AuthMethod, ServerEntry, VaultManager};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HostView {
    pub id: Uuid,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub kind: String,
    pub uses_ssh: bool,
    pub group: Option<String>,
    pub jump_host: Option<Uuid>,
    pub host_key_fingerprint: Option<String>,
    pub auth: &'static str,
}

pub fn list_json(vault: &VaultManager) -> Result<String, String> {
    let mut views = host_views(vault)?;
    views.sort_by(|a, b| (&a.label, &a.host, a.id).cmp(&(&b.label, &b.host, b.id)));
    serde_json::to_string_pretty(&views).map_err(|e| e.to_string())
}

pub fn host_views(vault: &VaultManager) -> Result<Vec<HostView>, String> {
    let summaries = vault.list_entries().map_err(|e| e.to_string())?;
    let mut views = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let entry = vault.get_entry(summary.id).map_err(|e| e.to_string())?;
        views.push(HostView {
            id: entry.id,
            label: entry.label,
            host: entry.host,
            port: entry.port,
            username: entry.username,
            kind: entry.kind.label().to_string(),
            uses_ssh: entry.kind.uses_ssh(),
            group: summary.group_name,
            jump_host: entry.jump_host,
            host_key_fingerprint: entry.host_key_fingerprint,
            auth: auth_label(&entry.auth),
        });
    }
    Ok(views)
}

pub fn find_host(vault: &VaultManager, host: &str) -> Result<Uuid, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("host is empty".into());
    }
    if let Ok(id) = Uuid::parse_str(host) {
        vault.get_entry(id).map_err(|e| e.to_string())?;
        return Ok(id);
    }
    let entries = vault.list_entries().map_err(|e| e.to_string())?;
    let labels: Vec<_> = entries.iter().filter(|e| e.label == host).collect();
    match labels.as_slice() {
        [one] => Ok(one.id),
        [] => {
            let names: Vec<_> = entries.iter().filter(|e| e.host == host).collect();
            match names.as_slice() {
                [one] => Ok(one.id),
                [] => Err(format!("no saved host matches '{host}'")),
                _ => Err(format!("several hosts use '{host}'; pass the host id")),
            }
        }
        _ => Err(format!(
            "several hosts are labeled '{host}'; pass the host id"
        )),
    }
}

pub fn prepare_route(vault: &VaultManager, id: Uuid) -> Result<gssh::ssh::SshRoute, String> {
    let entry = vault.get_entry(id).map_err(|e| e.to_string())?;
    if !entry.kind.uses_ssh() {
        return Err(format!(
            "'{}' is a {} host; this server only opens SSH and SFTP hosts",
            display_name(&entry),
            entry.kind.label()
        ));
    }
    let credential =
        route::target_credential(vault, &entry).map_err(|issue| credential_error(&entry, issue))?;
    route::route_for(vault, &entry, credential)
}

fn display_name(entry: &ServerEntry) -> &str {
    if entry.label.is_empty() {
        &entry.host
    } else {
        &entry.label
    }
}

fn auth_label(auth: &AuthMethod) -> &'static str {
    match auth {
        AuthMethod::Password(_) => "password",
        AuthMethod::PrivateKey { .. } => "private_key",
        AuthMethod::Agent => "agent",
    }
}

fn credential_error(entry: &ServerEntry, issue: CredentialIssue) -> String {
    let name = display_name(entry);
    match issue {
        CredentialIssue::KeyMissing => {
            format!("SSH key for '{name}' is missing from the vault")
        }
        CredentialIssue::Passphrase {
            key_name, issue, ..
        } => match issue {
            KeyIssue::MissingPassphrase => {
                format!("'{name}' uses encrypted key '{key_name}' with no saved passphrase")
            }
            KeyIssue::WrongPassphrase => {
                format!("the saved passphrase does not decrypt '{name}' key '{key_name}'")
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gssh::vault::{ConnectionKind, ProxyChoice, VaultManager};
    use secrecy::SecretString;
    use std::path::Path;

    const PASSWORD: &str = "s3cr3t-not-in-output";
    const NOTES: &str = "note-secret-token";

    fn open_vault(dir: &Path) -> VaultManager {
        let (vault, phrase) = VaultManager::create_with_params(
            &dir.join("vault.json"),
            &SecretString::from("test-vault-password".to_string()),
            gssh::vault::model::KdfParams {
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        drop(phrase);
        vault
    }

    fn entry(label: &str, host: &str, jump: Option<Uuid>) -> ServerEntry {
        ServerEntry {
            id: Uuid::new_v4(),
            label: label.into(),
            host: host.into(),
            port: 22,
            kind: ConnectionKind::Ssh,
            username: "deploy".into(),
            auth: AuthMethod::Password(PASSWORD.into()),
            notes: Some(NOTES.into()),
            os: None,
            last_opened_at: None,
            host_key_fingerprint: None,
            last_remote_dir: None,
            last_local_dir: None,
            group: None,
            tags: Vec::new(),
            proxy: ProxyChoice::Default,
            jump_host: jump,
            forwards: Vec::new(),
            startup_snippet: None,
            snippets: Vec::new(),
            rdp: Default::default(),
            vnc: Default::default(),
            sort_order: 0,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn list_reads_connection_files_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = open_vault(dir.path());
        vault.add_entry(entry("app", "app.example", None)).unwrap();

        let json = list_json(&vault).unwrap();
        assert!(dir.path().join("connections").is_dir());
        assert!(json.contains("app.example"));
        assert!(json.contains("\"auth\": \"password\""));
        assert!(!json.contains(PASSWORD));
        assert!(!json.contains(NOTES));
        assert!(!json.contains("test-vault-password"));
    }

    #[test]
    fn route_for_includes_the_saved_jump_host() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = open_vault(dir.path());
        let bastion = entry("bastion", "jump.example", None);
        let bastion_id = bastion.id;
        vault.add_entry(bastion).unwrap();
        let target = entry("app", "app.example", Some(bastion_id));
        let target_id = target.id;
        vault.add_entry(target).unwrap();

        let route = prepare_route(&vault, target_id).unwrap();
        let labels: Vec<_> = route
            .hops()
            .map(|hop| hop.display_name().to_string())
            .collect();
        assert_eq!(labels, vec!["bastion".to_string(), "app".to_string()]);
        assert_eq!(find_host(&vault, "app").unwrap(), target_id);
        assert_eq!(
            find_host(&vault, &target_id.to_string()).unwrap(),
            target_id
        );
    }

    #[test]
    fn duplicate_labels_need_an_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = open_vault(dir.path());
        vault.add_entry(entry("same", "a.example", None)).unwrap();
        vault.add_entry(entry("same", "b.example", None)).unwrap();
        let err = find_host(&vault, "same").unwrap_err();
        assert!(err.contains("host id"), "{err}");
    }

    #[test]
    fn remote_desktop_hosts_are_not_routed() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = open_vault(dir.path());
        let mut desktop = entry("desk", "desk.example", None);
        desktop.kind = ConnectionKind::Rdp;
        desktop.port = 3389;
        let id = desktop.id;
        vault.add_entry(desktop).unwrap();
        let err = match prepare_route(&vault, id) {
            Err(err) => err,
            Ok(_) => panic!("an RDP host must not be routed"),
        };
        assert!(err.contains("RDP"), "{err}");
    }
}
