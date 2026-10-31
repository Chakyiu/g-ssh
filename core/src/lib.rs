//! The part of g-ssh without UI: SSH and SFTP, the terminal emulator, the
//! vault and the account with sync. The desktop and mobile apps share it.

pub mod account;
pub mod app;
pub mod ssh;
pub mod vault;
