pub mod app;
pub mod chrome;
pub mod hints;
pub mod hosts;
pub mod keyboard;
pub mod local;
pub mod menu;
pub mod palette;
pub mod root;
pub mod scale;
pub mod session;
pub mod settings;
pub mod sftp;
pub mod sync;
pub mod terminal;
pub mod updates;
pub mod vault;
pub mod workspace;

/// The chrome every dialog shares.
///
/// gpui-component paints a dialog in `theme.background`, the very colour of
/// the ground behind it, with the faint `border` token and no shadow, so it
/// reads as text floating on the app rather than a surface above it. This
/// swaps in the floating-surface colour, the border meant for surfaces that
/// sit above the chrome, and the four-layer shadow Zed gives its modals.
pub fn dialog_chrome(dialog: gpui_component::dialog::Dialog) -> gpui_component::dialog::Dialog {
    use gpui::prelude::*;

    dialog
        .bg(crate::theme::pop_surface())
        .border_color(crate::theme::float_border())
        .rounded(scale::px(12.))
        .shadow(modal_shadow())
}

/// Corner radius of the working area, the card that holds the host list or
/// a session.
pub const PANEL_RADIUS: f32 = 14.;

pub fn dialog_narrow() -> gpui::Pixels {
    scale::px(400.)
}

pub fn dialog_wide() -> gpui::Pixels {
    scale::px(480.)
}

/// The host form: user, host and port share a row, and so do the folder and
/// the tags.
pub fn dialog_form() -> gpui::Pixels {
    scale::px(620.)
}

/// The four-layer shadow Zed gives its modals, shared by dialogs, the palette
/// and the settings card so they all sit at the same height.
pub fn modal_shadow() -> Vec<gpui::BoxShadow> {
    let is_light = crate::theme::is_light();
    let layer = |y: f32, blur: f32, alpha: f32| gpui::BoxShadow {
        // Warm shadow, same temperature as the ink, so panels sit on the
        // desk instead of on a neutral grey.
        color: gpui::hsla(0.08, 0.28, 0.07, alpha),
        offset: gpui::point(scale::px(0.), scale::px(y)),
        blur_radius: scale::px(blur),
        spread_radius: scale::px(0.),
        inset: false,
    };
    vec![
        layer(2., 3., if is_light { 0.06 } else { 0.12 }),
        layer(3., 6., if is_light { 0.06 } else { 0.08 }),
        layer(6., 12., 0.04),
        // Contact shadow: unblurred, it draws the panel's own edge.
        layer(1., 0., if is_light { 0.04 } else { 0.12 }),
    ]
}

/// How tall a dialog's content may grow before it has to scroll.
///
/// gpui-component pins a dialog's top at a tenth of the window and gives it no
/// height cap of its own, so tall content just runs off the bottom, taking the
/// confirm buttons with it. This leaves room for that top offset, the dialog's
/// own 16px padding on each side and a matching gap at the bottom.
pub fn dialog_max_height(window: &gpui::Window) -> gpui::Pixels {
    let viewport = window.viewport_size().height;
    (viewport * 0.9 - scale::px(48.)).max(scale::px(200.))
}

pub enum VaultState {
    Locked,
    AwaitingPhraseConfirmation {
        manager: gssh::vault::VaultManager,
        phrase: gssh::vault::RecoveryPhrase,
        is_rotation: bool,
    },
    Unlocked {
        manager: gssh::vault::VaultManager,
    },
}

impl VaultState {
    pub fn manager(&self) -> Option<&gssh::vault::VaultManager> {
        match self {
            VaultState::Unlocked { manager } => Some(manager),
            _ => None,
        }
    }

    pub fn manager_mut(&mut self) -> Option<&mut gssh::vault::VaultManager> {
        match self {
            VaultState::Unlocked { manager } => Some(manager),
            _ => None,
        }
    }

    /// Go from `Unlocked` back to `Locked`, wiping the DEK and dropping the
    /// decrypted records. Any other state is left alone: a recovery phrase
    /// still waiting to be confirmed must not be thrown away.
    pub fn lock(&mut self) {
        if !matches!(self, VaultState::Unlocked { .. }) {
            return;
        }
        if let VaultState::Unlocked { manager } = std::mem::replace(self, VaultState::Locked) {
            manager.lock();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gssh::vault::model::KdfParams;
    use gssh::vault::{RecoveryPhrase, VaultManager};
    use secrecy::SecretString;

    fn new_vault(dir: &std::path::Path) -> (VaultManager, RecoveryPhrase) {
        VaultManager::create_with_params(
            &dir.join("vault.json"),
            &SecretString::from("hunter2".to_string()),
            KdfParams {
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn locking_an_unlocked_vault_drops_the_manager() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) = new_vault(dir.path());
        let mut state = VaultState::Unlocked { manager };

        state.lock();

        assert!(matches!(state, VaultState::Locked));
        assert!(state.manager().is_none());
    }

    #[test]
    fn locking_keeps_a_recovery_phrase_that_is_not_confirmed_yet() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, phrase) = new_vault(dir.path());
        let mut state = VaultState::AwaitingPhraseConfirmation {
            manager,
            phrase,
            is_rotation: false,
        };

        state.lock();

        assert!(matches!(
            state,
            VaultState::AwaitingPhraseConfirmation { .. }
        ));
    }

    #[test]
    fn locking_a_locked_vault_changes_nothing() {
        let mut state = VaultState::Locked;
        state.lock();
        assert!(matches!(state, VaultState::Locked));
    }
}
