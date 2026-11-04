//! The part of g-ssh without UI: SSH, SFTP, Telnet, RDP, the terminal emulator,
//! the vault and the account with sync. The desktop and mobile apps share it.

pub mod account;
pub mod app;
pub mod rdp;
pub mod ssh;
pub mod telnet;
pub mod vault;
