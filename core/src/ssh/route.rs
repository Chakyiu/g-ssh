//! Turns a vault host into the route an `SshConnection` dials: its bastions, proxy and
//! credentials.

use zeroize::Zeroizing;

use crate::ssh::connection::ResolvedProxy;
use crate::ssh::{self, AuthCredential, KeyIssue, SshHop, SshRoute};
use uuid::Uuid;

use crate::vault::{AuthMethod, ProxyKind, ServerEntry, VaultManager};

/// Why the host's own credential needs the user before connecting.
pub enum CredentialIssue {
    /// The host names a key the vault no longer has.
    KeyMissing,
    /// The key is encrypted and its saved passphrase is missing or wrong. Ask for it, check the
    /// answer with `ssh::check_key_passphrase`, then connect with `pem` and the answer.
    Passphrase {
        key_name: String,
        pem: Zeroizing<String>,
        issue: KeyIssue,
    },
}

/// The credential for `entry` itself, from the vault.
pub fn target_credential(
    vault: &VaultManager,
    entry: &ServerEntry,
) -> Result<AuthCredential, CredentialIssue> {
    let key_id = match &entry.auth {
        AuthMethod::Password(p) => return Ok(AuthCredential::Password(Zeroizing::new(p.clone()))),
        AuthMethod::Agent => return Ok(AuthCredential::Agent),
        AuthMethod::PrivateKey { key_id } => *key_id,
    };
    let key = vault
        .get_key(key_id)
        .map_err(|_| CredentialIssue::KeyMissing)?;
    let pem = Zeroizing::new(key.pem.clone());
    // The connection would fail at key decode, so the caller asks first.
    if let Some(issue) = ssh::check_key_passphrase(&pem, key.passphrase.as_deref()) {
        return Err(CredentialIssue::Passphrase {
            key_name: key.name.clone(),
            pem,
            issue,
        });
    }
    Ok(AuthCredential::PrivateKey {
        pem,
        passphrase: key.passphrase.clone().map(Zeroizing::new),
    })
}

/// The proxy this host is dialled through, if it does not connect directly.
pub fn resolved_proxy(vault: &VaultManager, entry_id: Uuid) -> Option<ResolvedProxy> {
    vault.resolve_proxy_for(entry_id).map(|proxy| {
        let addr = format!("{}:{}", proxy.host, proxy.port);
        let auth = proxy
            .auth
            .as_ref()
            .map(|auth| (auth.username.clone(), auth.password.clone()));
        match proxy.kind {
            ProxyKind::Socks5 => ResolvedProxy::Socks5 { addr, auth },
            ProxyKind::Http => ResolvedProxy::Http { addr, auth },
        }
    })
}

/// Every bastion in front of `entry`, then `entry` with `credential`.
pub fn route_for(
    vault: &VaultManager,
    entry: &ServerEntry,
    credential: AuthCredential,
) -> Result<SshRoute, String> {
    let chain = vault
        .resolve_jump_chain_for(entry.id)
        .map_err(|e| e.to_string())?;

    // Only the first hop is dialled over TCP, so its proxy is the one that counts; a jumped
    // target is never reached from this network at all.
    let dialled = chain.first().map(|hop| hop.id).unwrap_or(entry.id);
    let proxy = resolved_proxy(vault, dialled);

    // The chain ends with the target, whose credential the caller already has.
    let mut jumps = Vec::new();
    for bastion in chain.iter().take(chain.len().saturating_sub(1)) {
        jumps.push(hop(bastion, bastion_credential(vault, bastion)?));
    }

    Ok(SshRoute {
        jumps,
        target: hop(entry, credential),
        proxy,
    })
}

/// A bastion cannot ask for a passphrase mid-chain, so an unusable key is an error naming it.
fn bastion_credential(vault: &VaultManager, entry: &ServerEntry) -> Result<AuthCredential, String> {
    let name = if entry.label.is_empty() {
        &entry.host
    } else {
        &entry.label
    };
    match target_credential(vault, entry) {
        Ok(credential) => Ok(credential),
        Err(CredentialIssue::KeyMissing) => Err(format!(
            "SSH key for '{name}' not found. Reassign it in Settings."
        )),
        Err(CredentialIssue::Passphrase {
            issue: KeyIssue::MissingPassphrase,
            ..
        }) => Err(format!(
            "'{name}' uses an encrypted key. Save its passphrase with the key in Settings."
        )),
        Err(CredentialIssue::Passphrase {
            issue: KeyIssue::WrongPassphrase,
            ..
        }) => Err(format!(
            "The saved passphrase no longer decrypts '{name}'s key."
        )),
    }
}

fn hop(entry: &ServerEntry, credential: AuthCredential) -> SshHop {
    SshHop {
        entry_id: entry.id.to_string(),
        label: entry.label.clone(),
        host: entry.host.clone(),
        port: entry.port,
        username: entry.username.clone(),
        credential,
        expected_host_key: entry.host_key_fingerprint.clone(),
    }
}
