use gpui::prelude::*;
use gpui::{AnyElement, App, Context, Entity, FocusHandle, Focusable, Window};
use gpui_component::{
    button::{Button, ButtonVariants as _},
    input::{Input, InputEvent, InputState},
};
use secrecy::SecretString;
use zeroize::Zeroizing;

use super::lock;
use crate::ui::VaultState;
use gssh::vault::{RecoveryPhrase, VaultError, VaultManager};

enum Step {
    Form,
    Working,
}

pub struct CreateVaultView {
    focus_handle: FocusHandle,
    vault_state: Entity<VaultState>,
    step: Step,
    password: Entity<InputState>,
    confirm: Entity<InputState>,
    error: Option<String>,
}

impl Focusable for CreateVaultView {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl CreateVaultView {
    pub fn new(
        vault_state: Entity<VaultState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let password = masked_input("Password", window, cx);
        let confirm = masked_input("Confirm password", window, cx);

        cx.subscribe_in(&password, window, Self::on_input).detach();
        cx.subscribe_in(&confirm, window, Self::on_input).detach();

        Self {
            focus_handle: cx.focus_handle(),
            vault_state,
            step: Step::Form,
            password,
            confirm,
            error: None,
        }
    }

    /// Put the cursor in the password field. Called by `RootView` when the create
    /// screen first appears so the user can type straight away.
    pub fn focus_password(&self, window: &mut Window, cx: &mut Context<Self>) {
        self.password
            .update(cx, |state, cx| state.focus(window, cx));
    }

    /// Called once the vault exists, so the master password does not linger.
    pub fn clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.clear_inputs(window, cx);
        self.step = Step::Form;
        self.error = None;
    }

    fn clear_inputs(&self, window: &mut Window, cx: &mut Context<Self>) {
        for input in [&self.password, &self.confirm] {
            input.update(cx, |state, cx| state.set_value("", window, cx));
        }
    }

    fn on_input(
        &mut self,
        _: &Entity<InputState>,
        event: &InputEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !matches!(event, InputEvent::PressEnter { .. }) {
            return;
        }
        if matches!(self.step, Step::Form) {
            self.submit(cx);
        }
    }

    fn checked_new_password(&self, cx: &App) -> Result<String, &'static str> {
        let password = self.password.read(cx).value().to_string();
        let confirm = Zeroizing::new(self.confirm.read(cx).value().to_string());
        if password.is_empty() {
            return Err("Password cannot be empty.");
        }
        if password != *confirm {
            return Err("Passwords do not match.");
        }
        Ok(password)
    }

    fn submit(&mut self, cx: &mut Context<Self>) {
        let pw = match self.checked_new_password(cx) {
            Ok(pw) => pw,
            Err(e) => {
                self.error = Some(e.into());
                cx.notify();
                return;
            }
        };

        self.step = Step::Working;
        self.error = None;
        cx.notify();

        let (tx, rx) =
            async_channel::bounded::<Result<(VaultManager, RecoveryPhrase), VaultError>>(1);

        std::thread::spawn(move || {
            let result = (|| -> Result<_, VaultError> {
                let path = gssh::vault::default_vault_path()?;
                let secret = SecretString::from(pw);
                VaultManager::create(&path, &secret)
            })();
            let _ = tx.try_send(result);
        });

        cx.spawn(async move |this, cx| {
            let Ok(result) = rx.recv().await else { return };
            this.update(cx, |this, cx| match result {
                Ok((manager, phrase)) => {
                    this.vault_state.update(cx, |vs, cx| {
                        *vs = VaultState::AwaitingPhraseConfirmation {
                            manager,
                            phrase,
                            is_rotation: false,
                        };
                        cx.notify();
                    });
                    this.step = Step::Form;
                }
                Err(e) => {
                    tracing::error!(?e, "vault creation failed");
                    this.step = Step::Form;
                    this.error = Some(format!("Failed to create vault: {e}"));
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }
}

fn masked_input(
    placeholder: &'static str,
    window: &mut Window,
    cx: &mut App,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(placeholder)
            .masked(true)
    })
}

impl CreateVaultView {
    fn render_plain(&self, cx: &mut Context<Self>) -> AnyElement {
        if matches!(self.step, Step::Working) {
            return lock::working("Creating vault\u{2026}", cx);
        }
        lock::column()
            .child(lock::header(
                "Create vault",
                Some("Choose a master password to protect your hosts and credentials."),
                cx,
            ))
            .child(Input::new(&self.password).mask_toggle())
            .child(Input::new(&self.confirm).mask_toggle())
            .children(self.error.as_deref().map(|e| lock::error(e, cx)))
            .child(
                Button::new("create-vault")
                    .primary()
                    .child("Create vault")
                    .on_click(cx.listener(|this, _, _, cx| this.submit(cx))),
            )
            .into_any_element()
    }
}

impl Render for CreateVaultView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        lock::screen(self.render_plain(cx), window, cx)
    }
}
