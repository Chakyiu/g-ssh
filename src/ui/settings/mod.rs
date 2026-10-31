mod vault;
pub mod screen;

pub(crate) use screen::set_theme_preference;
pub use screen::{SettingsView, SettingsViewEvent};

use gpui::App;
use gpui_component::{Icon, IconName};

pub fn init(cx: &mut App) {
    screen::init(cx);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsSection {
    Vault,
    Appearance,
    Terminal,
    Keys,
    Snippets,
    Network,
    About,
}

impl SettingsSection {
    pub fn label(self) -> &'static str {
        match self {
            SettingsSection::Vault => "Vault",
            SettingsSection::Appearance => "Appearance",
            SettingsSection::Terminal => "Terminal",
            SettingsSection::Keys => "SSH keys",
            SettingsSection::Snippets => "Snippets",
            SettingsSection::Network => "Proxy",
            SettingsSection::About => "About",
        }
    }

    pub fn icon(self) -> Icon {
        let name = match self {
            SettingsSection::Vault => return Icon::empty().path("icons/lock.svg"),
            SettingsSection::Appearance => IconName::Palette,
            SettingsSection::Terminal => IconName::PanelBottom,
            SettingsSection::Keys => return Icon::empty().path("icons/key-round.svg"),
            SettingsSection::Snippets => IconName::SquareTerminal,
            SettingsSection::Network => IconName::Network,
            SettingsSection::About => IconName::Info,
        };
        Icon::new(name)
    }

    pub fn all() -> &'static [SettingsSection] {
        &[
            SettingsSection::Vault,
            SettingsSection::Appearance,
            SettingsSection::Terminal,
            SettingsSection::Keys,
            SettingsSection::Snippets,
            SettingsSection::Network,
            SettingsSection::About,
        ]
    }
}
