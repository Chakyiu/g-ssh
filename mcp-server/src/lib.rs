//! Headless adapter over `gssh`. The binary speaks MCP; this crate owns the
//! vault, the route, and the fail-closed prompt policy.

mod hosts;
mod policy;
mod session;

pub use session::App;
