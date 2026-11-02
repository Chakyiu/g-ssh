//! Port forwards for a server: the saved list, its live state, and starting
//! one or stopping it.
//!
//! The inspector's Forwards page draws the rows; this module owns the state
//! they read and the request a Start/Stop press makes. Forwards are defined in
//! the server form, so nothing here adds or edits one.

use gpui::Context;

use crate::ui::session::{ForwardMenuEntry, ForwardRuntime, ServerSession};

impl ServerSession {
    /// Start a stopped forward, or stop a running one. The result comes back
    /// as a `ForwardChanged` event, so nothing is assumed here.
    pub(crate) fn toggle_forward(&mut self, id: String, cx: &mut Context<Self>) {
        let Some(forward) = self.forwards.iter().find(|f| f.spec.id == id) else {
            return;
        };
        let Some(conn) = self.connection.clone() else {
            return;
        };
        let spec = forward.spec.clone();
        let is_bound = forward.is_bound();
        cx.spawn(async move |_, _| {
            if is_bound {
                conn.stop_forward(spec.id).await;
            } else {
                conn.start_forward(spec).await;
            }
        })
        .detach();
    }

    /// The inspector strip's forwards row: the count of bound forwards out of
    /// the ones the host defines, and whether one of them died by itself (the
    /// count then reads red, the way the chip it replaced did). `None` when the
    /// host defines no forwards, so the row is left out.
    pub fn forwards_menu_entry(&self) -> Option<ForwardMenuEntry> {
        forwards_menu_entry(&self.forwards)
    }
}

/// The forwards summary the inspector strip shows. Split out from the session
/// so the counting can be tested without a connection.
fn forwards_menu_entry(forwards: &[ForwardRuntime]) -> Option<ForwardMenuEntry> {
    if forwards.is_empty() {
        return None;
    }
    let bound = forwards.iter().filter(|forward| forward.is_bound()).count();
    Some(ForwardMenuEntry {
        count: format!("{bound}/{}", forwards.len()),
        failed: forwards.iter().any(|forward| forward.failure().is_some()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gssh::ssh::connection::{ForwardKind, ForwardSpec};
    use gssh::ssh::ForwardState;

    fn forward(state: ForwardState) -> ForwardRuntime {
        let spec = ForwardSpec {
            id: "f".to_string(),
            kind: ForwardKind::Local,
            bind_address: "127.0.0.1".to_string(),
            bind_port: 8080,
            target_host: "localhost".to_string(),
            target_port: 80,
        };
        ForwardRuntime {
            spec,
            name: "web".to_string(),
            auto_start: false,
            state,
        }
    }

    #[test]
    fn a_host_without_forwards_gets_no_menu_row() {
        assert!(forwards_menu_entry(&[]).is_none());
    }

    #[test]
    fn the_row_counts_what_is_bound() {
        let forwards = [
            forward(ForwardState::Bound {
                bound_port: 8080,
                active: 0,
            }),
            forward(ForwardState::Stopped { reason: None }),
        ];
        let entry = forwards_menu_entry(&forwards).unwrap();
        assert_eq!(entry.count, "1/2");
        assert!(
            !entry.failed,
            "a forward stopped on request is not a failure"
        );
    }

    #[test]
    fn a_forward_that_died_by_itself_marks_the_row() {
        let forwards = [forward(ForwardState::Stopped {
            reason: Some("Address already in use".to_string()),
        })];
        let entry = forwards_menu_entry(&forwards).unwrap();
        assert_eq!(entry.count, "0/1");
        assert!(entry.failed);
    }
}
