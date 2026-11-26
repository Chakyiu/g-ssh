//! Password dialog for a sealed host export or import.

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{div, Context, Entity, EventEmitter, Window};

use gpui_component::{
    button::{Button, ButtonVariants as _},
    dialog::{DialogHeader, DialogTitle},
    h_flex,
    input::{Input, InputEvent, InputState},
    v_flex, ActiveTheme as _, Disableable as _, Sizable as _,
};
use zeroize::Zeroizing;

pub enum BundlePasswordEvent {
    Submitted(Zeroizing<String>),
    Cancelled,
}

pub struct BundlePasswordView {
    title: String,
    detail: String,
    action: &'static str,
    password: Entity<InputState>,
    confirm: Option<Entity<InputState>>,
    error: Option<String>,
    is_working: bool,
}

impl EventEmitter<BundlePasswordEvent> for BundlePasswordView {}

impl BundlePasswordView {
    pub fn new(
        title: String,
        detail: String,
        action: &'static str,
        needs_confirm: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(true)
                .placeholder("Password")
        });
        password.update(cx, |state, cx| state.focus(window, cx));
        let confirm = needs_confirm.then(|| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .masked(true)
                    .placeholder("Confirm password")
            })
        });
        cx.subscribe(&password, |this: &mut Self, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::PressEnter { .. }) {
                this.submit(cx);
            }
        })
        .detach();
        if let Some(confirm) = &confirm {
            cx.subscribe(confirm, |this: &mut Self, _, event: &InputEvent, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.submit(cx);
                }
            })
            .detach();
        }

        Self {
            title,
            detail,
            action,
            password,
            confirm,
            error: None,
            is_working: false,
        }
    }

    fn submit(&mut self, cx: &mut Context<Self>) {
        if self.is_working {
            return;
        }
        let value = self.password.read(cx).value().to_string();
        if value.is_empty() {
            self.error = Some("Enter a password.".into());
            cx.notify();
            return;
        }
        if let Some(confirm) = &self.confirm {
            if confirm.read(cx).value().as_ref() != value.as_str() {
                self.error = Some("Those passwords don't match.".into());
                cx.notify();
                return;
            }
        }
        self.is_working = true;
        self.error = None;
        cx.notify();
        cx.emit(BundlePasswordEvent::Submitted(Zeroizing::new(value)));
    }

    pub fn set_error(&mut self, message: String, cx: &mut Context<Self>) {
        self.is_working = false;
        self.error = Some(message);
        cx.notify();
    }
}

impl Render for BundlePasswordView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let action = if self.is_working {
            "Working…"
        } else {
            self.action
        };

        v_flex()
            .p(px(12.))
            .gap(px(8.))
            .child(DialogHeader::new().child(DialogTitle::new().child(self.title.clone())))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(theme.muted_foreground)
                    .child(self.detail.clone()),
            )
            .child(Input::new(&self.password).mask_toggle())
            .children(
                self.confirm
                    .as_ref()
                    .map(|confirm| Input::new(confirm).mask_toggle()),
            )
            .children(self.error.as_ref().map(|message| {
                div()
                    .text_size(px(11.5))
                    .text_color(theme.danger)
                    .child(message.clone())
            }))
            .child(
                h_flex()
                    .gap(px(8.))
                    .justify_end()
                    .child(
                        Button::new("bundle-cancel")
                            .small()
                            .ghost()
                            .disabled(self.is_working)
                            .child("Cancel")
                            .on_click(cx.listener(|this, _, _, cx| {
                                if this.is_working {
                                    return;
                                }
                                cx.emit(BundlePasswordEvent::Cancelled);
                            })),
                    )
                    .child(
                        Button::new("bundle-confirm")
                            .small()
                            .primary()
                            .disabled(self.is_working)
                            .child(action)
                            .on_click(cx.listener(|this, _, _, cx| this.submit(cx))),
                    ),
            )
    }
}

/// A file name a save dialog can use. Spaces and slashes become dashes.
pub(crate) fn export_file_name(title: &str) -> String {
    let mut slug = String::new();
    for ch in title.chars() {
        if slug.len() >= 48 {
            break;
        }
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            slug.push(ch.to_ascii_lowercase());
        } else if (ch.is_whitespace() || ch == '/') && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "connections" } else { slug };
    format!("{slug}.json")
}
