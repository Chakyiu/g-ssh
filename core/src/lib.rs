//! The part of g-ssh without UI: SSH, SFTP, Telnet, RDP, VNC, the terminal
//! emulator, the vault and the account with sync. The desktop and mobile apps
//! share it.

pub mod account;
pub mod app;
pub mod desktop;
pub mod rdp;
pub mod ssh;
pub mod telnet;
pub mod vault;
pub mod vnc;

// TELE-47 gate-block verification: deliberately broken on a throwaway branch,
// never intended to merge.
#[cfg(test)]
mod tele47_gate_block {
    #[test]
    fn deliberately_fails_on_every_platform() {
        assert_eq!(2 + 2, 5, "TELE-47 intentional failure");
    }
}

pub fn tele47_fmt_violation(badly: i32, spaced: i32)->i32{badly*3+spaced}
