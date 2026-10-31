//! App preferences that must be readable before the vault is unlocked.
//!
//! Lives next to `file_associations.json` so the app keeps one config folder.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Terminal font size in pixels, and the bounds zooming clamps to. The
/// default matches the file pane (12px) so both panes read at one size.
pub const DEFAULT_TERMINAL_FONT_SIZE: f32 = 12.0;
pub const MIN_TERMINAL_FONT_SIZE: f32 = 6.0;
pub const MAX_TERMINAL_FONT_SIZE: f32 = 40.0;

/// How long the font size must stay unchanged before it is written to disk.
/// Holding the zoom shortcut repeats many times a second.
const FONT_SIZE_SAVE_DELAY: Duration = Duration::from_millis(400);

/// Most hosts have vim. Minimal images often have only vi, which is a preset
/// in the settings.
pub const DEFAULT_EDITOR_COMMAND: &str = "vim";

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    #[default]
    Dark,
    Light,
    /// Follow the OS appearance and keep following it as it changes.
    System,
}

impl ThemePreference {
    pub fn label(self) -> &'static str {
        match self {
            ThemePreference::Dark => "Dark",
            ThemePreference::Light => "Light",
            ThemePreference::System => "System",
        }
    }
}

macro_rules! terminal_fonts {
    (
        $(#[$default_meta:meta])*
        $default_variant:ident => [$($default_name:literal),+ $(,)?],
        $($variant:ident => [$($name:literal),+ $(,)?]),* $(,)?
    ) => {
        /// The terminal font. A fixed list keeps proportional fonts, which break the
        /// cell grid, out of the terminal.
        ///
        /// Nerd Font entries are the monospace faces from a Nerd Fonts install, so
        /// prompt icons (starship, powerlevel10k, oh-my-posh) have glyphs. `Nerd Font
        /// Mono` draws those icons one cell wide. Proportional `Nerd Font Propo`
        /// faces are left out. Each face is published under a typographic name
        /// (`JetBrainsMono Nerd Font`, what macOS and Linux report) and a short name
        /// (`JetBrainsMono NF`, what Windows reports).
        #[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum TerminalFont {
            /// Bundled with the app, so it is always there.
            $(#[$default_meta])*
            $default_variant,
            $($variant,)*
        }

        impl TerminalFont {
            pub const ALL: &'static [TerminalFont] = &[
                TerminalFont::$default_variant,
                $(TerminalFont::$variant,)*
            ];

            /// Every family name this face is installed under. The first is
            /// the typographic name and the label.
            pub fn families(self) -> &'static [&'static str] {
                match self {
                    TerminalFont::$default_variant => &[$($default_name),+],
                    $(TerminalFont::$variant => &[$($name),+],)*
                }
            }
        }
    };
}

terminal_fonts! {
    #[default]
    CascadiaCode => ["Cascadia Code"],
    CaskaydiaCoveNerd => ["CaskaydiaCove Nerd Font", "CaskaydiaCove NF"],
    CaskaydiaCoveNerdMono => ["CaskaydiaCove Nerd Font Mono", "CaskaydiaCove NFM"],
    CaskaydiaMonoNerd => ["CaskaydiaMono Nerd Font", "CaskaydiaMono NF"],
    CaskaydiaMonoNerdMono => ["CaskaydiaMono Nerd Font Mono", "CaskaydiaMono NFM"],
    Menlo => ["Menlo"],
    Monaco => ["Monaco"],
    JetBrainsMono => ["JetBrains Mono"],
    JetBrainsMonoNerd => ["JetBrainsMono Nerd Font", "JetBrainsMono NF"],
    JetBrainsMonoNerdMono => ["JetBrainsMono Nerd Font Mono", "JetBrainsMono NFM"],
    JetBrainsMonoNlNerd => ["JetBrainsMonoNL Nerd Font", "JetBrainsMonoNL NF"],
    JetBrainsMonoNlNerdMono => ["JetBrainsMonoNL Nerd Font Mono", "JetBrainsMonoNL NFM"],
    FiraCode => ["Fira Code"],
    FiraCodeNerd => ["FiraCode Nerd Font", "FiraCode NF"],
    FiraCodeNerdMono => ["FiraCode Nerd Font Mono", "FiraCode NFM"],
    FiraMonoNerd => ["FiraMono Nerd Font", "FiraMono NF"],
    FiraMonoNerdMono => ["FiraMono Nerd Font Mono", "FiraMono NFM"],
    SourceCodePro => ["Source Code Pro"],
    SauceCodeProNerd => ["SauceCodePro Nerd Font", "SauceCodePro NF"],
    SauceCodeProNerdMono => ["SauceCodePro Nerd Font Mono", "SauceCodePro NFM"],
    Hack => ["Hack"],
    HackNerd => ["Hack Nerd Font", "Hack NF"],
    HackNerdMono => ["Hack Nerd Font Mono", "Hack NFM"],
    Consolas => ["Consolas"],
    DejaVuSansMono => ["DejaVu Sans Mono"],
    DejaVuSansMonoNerd => ["DejaVuSansMono Nerd Font", "DejaVuSansMono NF"],
    DejaVuSansMonoNerdMono => ["DejaVuSansMono Nerd Font Mono", "DejaVuSansMono NFM"],
    UbuntuMono => ["Ubuntu Mono"],
    UbuntuMonoNerd => ["UbuntuMono Nerd Font", "UbuntuMono NF"],
    UbuntuMonoNerdMono => ["UbuntuMono Nerd Font Mono", "UbuntuMono NFM"],
    LiberationMono => ["Liberation Mono"],
    LiterationMonoNerd => ["LiterationMono Nerd Font", "LiterationMono NF"],
    LiterationMonoNerdMono => ["LiterationMono Nerd Font Mono", "LiterationMono NFM"],
    MesloLgsNerd => ["MesloLGS Nerd Font", "MesloLGS NF"],
    MesloLgsNerdMono => ["MesloLGS Nerd Font Mono", "MesloLGS NFM"],
    MesloLgmNerd => ["MesloLGM Nerd Font", "MesloLGM NF"],
    MesloLgmNerdMono => ["MesloLGM Nerd Font Mono", "MesloLGM NFM"],
    MesloLglNerd => ["MesloLGL Nerd Font", "MesloLGL NF"],
    MesloLglNerdMono => ["MesloLGL Nerd Font Mono", "MesloLGL NFM"],
    IosevkaNerd => ["Iosevka Nerd Font", "Iosevka NF"],
    IosevkaNerdMono => ["Iosevka Nerd Font Mono", "Iosevka NFM"],
    IosevkaTermNerd => ["IosevkaTerm Nerd Font", "IosevkaTerm NF"],
    IosevkaTermNerdMono => ["IosevkaTerm Nerd Font Mono", "IosevkaTerm NFM"],
    RobotoMonoNerd => ["RobotoMono Nerd Font", "RobotoMono NF"],
    RobotoMonoNerdMono => ["RobotoMono Nerd Font Mono", "RobotoMono NFM"],
    VictorMonoNerd => ["VictorMono Nerd Font", "VictorMono NF"],
    VictorMonoNerdMono => ["VictorMono Nerd Font Mono", "VictorMono NFM"],
    GeistMonoNerd => ["GeistMono Nerd Font", "GeistMono NF"],
    GeistMonoNerdMono => ["GeistMono Nerd Font Mono", "GeistMono NFM"],
    ZedMonoNerd => ["ZedMono Nerd Font", "ZedMono NF"],
    ZedMonoNerdMono => ["ZedMono Nerd Font Mono", "ZedMono NFM"],
    CommitMonoNerd => ["CommitMono Nerd Font", "CommitMono NF"],
    CommitMonoNerdMono => ["CommitMono Nerd Font Mono", "CommitMono NFM"],
    InconsolataNerd => ["Inconsolata Nerd Font", "Inconsolata NF"],
    InconsolataNerdMono => ["Inconsolata Nerd Font Mono", "Inconsolata NFM"],
    MononokiNerd => ["Mononoki Nerd Font", "Mononoki NF"],
    MononokiNerdMono => ["Mononoki Nerd Font Mono", "Mononoki NFM"],
    IntoneMonoNerd => ["IntoneMono Nerd Font", "IntoneMono NF"],
    IntoneMonoNerdMono => ["IntoneMono Nerd Font Mono", "IntoneMono NFM"],
}

impl TerminalFont {
    /// The family name the system knows the font by. Also the label.
    ///
    /// Nerd Fonts also answer to a short name; `families` lists both.
    pub fn family(self) -> &'static str {
        self.families()[0]
    }

    /// The fonts this machine can draw, out of `ALL`. `installed` is the
    /// system's list of family names. Cascadia Code is bundled, so it stays
    /// even when the system list does not mention it.
    pub fn available(installed: &[String]) -> Vec<TerminalFont> {
        Self::ALL
            .iter()
            .copied()
            .filter(|font| {
                *font == TerminalFont::CascadiaCode
                    || font
                        .families()
                        .iter()
                        .any(|name| installed.iter().any(|have| have == *name))
            })
            .collect()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalScheme {
    /// Andromeda in the dark app theme, GitHub Light in the light one.
    #[default]
    FollowTheme,
    Andromeda,
    GithubLight,
    Dracula,
    CatppuccinMocha,
    SolarizedDark,
    GruvboxDark,
    TokyoNight,
}

impl TerminalScheme {
    pub const ALL: [TerminalScheme; 8] = [
        TerminalScheme::FollowTheme,
        TerminalScheme::Andromeda,
        TerminalScheme::GithubLight,
        TerminalScheme::Dracula,
        TerminalScheme::CatppuccinMocha,
        TerminalScheme::SolarizedDark,
        TerminalScheme::GruvboxDark,
        TerminalScheme::TokyoNight,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TerminalScheme::FollowTheme => "Match app theme",
            TerminalScheme::Andromeda => "Andromeda",
            TerminalScheme::GithubLight => "GitHub Light",
            TerminalScheme::Dracula => "Dracula",
            TerminalScheme::CatppuccinMocha => "Catppuccin Mocha",
            TerminalScheme::SolarizedDark => "Solarized Dark",
            TerminalScheme::GruvboxDark => "Gruvbox Dark",
            TerminalScheme::TokyoNight => "Tokyo Night",
        }
    }
}

/// When g-ssh asks the update server whether a newer build is out.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChecks {
    /// On every start and every six hours while the app runs.
    OnStart,
    /// Only when the user presses Check now.
    Manual,
}

/// Where an older build put the terminal relative to the file panes.
///
/// The session no longer splits them: SFTP is a tab. The value stays so a
/// preferences file from that build still loads and round-trips.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalPosition {
    /// Files on top, terminal under them.
    #[default]
    Below,
    /// Terminal on the left, files on the right.
    Beside,
}

/// Every field carries a serde default so a file written by an older build
/// still loads.
#[derive(Clone, Serialize, Deserialize)]
pub struct Preferences {
    #[serde(default)]
    pub theme: ThemePreference,
    /// Show the history suggestions popup in the terminal, and read the
    /// server's shell history for it.
    #[serde(default = "default_true")]
    pub is_suggestions_enabled: bool,
    /// macOS: Option+key sends ESC + key (Meta) instead of typing the
    /// character the layout composes.
    #[serde(default)]
    pub is_option_meta: bool,
    /// Shared by every terminal, so a chosen size carries over to new tabs
    /// and to the next start. Read it through `Preferences::terminal_font_size`,
    /// which clamps a hand-edited value. The interface zoom scales it on screen.
    #[serde(default = "default_terminal_font_size")]
    pub terminal_font_size: f32,
    /// Whole-interface zoom. 1 is the designed size. Read it through
    /// `Preferences::ui_scale`, which snaps a hand-edited value onto the ladder.
    #[serde(default = "default_ui_scale")]
    pub ui_scale: f32,
    #[serde(default)]
    pub terminal_font: TerminalFont,
    #[serde(default)]
    pub terminal_scheme: TerminalScheme,
    /// `None` until the user answers the question, and until then the app
    /// makes no update request on its own. Set by `load_from` from the raw
    /// file, see `update_checks_in`.
    #[serde(default)]
    pub update_checks: Option<UpdateChecks>,
    /// Shared by every session, so the layout picked once stays.
    #[serde(default)]
    pub terminal_position: TerminalPosition,
    /// Whether a session shows the second file pane (this computer or
    /// another server) next to the session's own files. Off by default: most
    /// uploads come from Finder or Explorer.
    #[serde(default)]
    pub is_second_pane_shown: bool,
    /// Whether the main window shows the hosts sidebar.
    #[serde(default = "default_true")]
    pub is_sidebar_shown: bool,
    /// macOS: the vault key is in the keychain behind Touch ID.
    #[serde(default)]
    pub is_touch_id_enabled: bool,
    /// Whether a session shows the server panel on its right.
    #[serde(default)]
    pub is_server_panel_shown: bool,
    /// Inspector width in pixels, once the user has dragged its edge.
    /// Missing means the built-in width.
    #[serde(default)]
    pub server_panel_width: Option<f32>,
    /// Agent chat width in pixels, once the user has dragged its edge.
    #[serde(default)]
    pub agent_panel_width: Option<f32>,
    /// The command that edits a remote file in a terminal tab. Read it
    /// through `Preferences::editor_command`, which fills in an empty one.
    #[serde(default = "default_editor_command")]
    pub editor_command: String,
    /// Double-click and Enter on a remote file run `editor_command` instead
    /// of opening the file on this computer.
    #[serde(default)]
    pub is_editor_default_open: bool,
    /// An onboarding hint only, never for security. Kept after sign-out and
    /// vault deletion. Set by `load_from`, see `has_account_in`.
    #[serde(default)]
    pub has_account: bool,
}

/// The update answer the raw file holds. Read on its own so that a file that
/// does not load as a whole keeps it: one value this build does not know must
/// not undo the answer.
///
/// Files from 0.1.x have `is_update_check_enabled` instead. Its `true` was
/// only the default, so just `false` counts as an answer.
fn update_checks_in(data: &[u8]) -> Option<UpdateChecks> {
    let file = serde_json::from_slice::<serde_json::Value>(data).ok()?;
    if let Ok(answer) = UpdateChecks::deserialize(&file["update_checks"]) {
        return Some(answer);
    }
    (file["is_update_check_enabled"] == false).then_some(UpdateChecks::Manual)
}

/// Read from the raw file, like `update_checks_in`.
fn has_account_in(data: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(data).is_ok_and(|file| file["has_account"] == true)
}

fn default_true() -> bool {
    true
}

fn finite_width(width: Option<f32>) -> Option<f32> {
    width.filter(|width| width.is_finite() && *width > 0.)
}

fn default_editor_command() -> String {
    DEFAULT_EDITOR_COMMAND.to_string()
}

fn default_terminal_font_size() -> f32 {
    DEFAULT_TERMINAL_FONT_SIZE
}

fn default_ui_scale() -> f32 {
    crate::ui::scale::DEFAULT_UI_SCALE
}

/// A size the terminal can lay out. The file is hand-editable, so the stored
/// number can be anything, including one that is not a number.
fn clamp_terminal_font_size(size: f32) -> f32 {
    if !size.is_finite() {
        return DEFAULT_TERMINAL_FONT_SIZE;
    }
    size.clamp(MIN_TERMINAL_FONT_SIZE, MAX_TERMINAL_FONT_SIZE)
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: ThemePreference::default(),
            is_suggestions_enabled: true,
            is_option_meta: false,
            terminal_font_size: DEFAULT_TERMINAL_FONT_SIZE,
            ui_scale: default_ui_scale(),
            terminal_font: TerminalFont::default(),
            terminal_scheme: TerminalScheme::default(),
            update_checks: None,
            terminal_position: TerminalPosition::default(),
            is_second_pane_shown: false,
            is_sidebar_shown: true,
            is_touch_id_enabled: false,
            is_server_panel_shown: false,
            server_panel_width: None,
            agent_panel_width: None,
            editor_command: default_editor_command(),
            is_editor_default_open: false,
            has_account: false,
        }
    }
}

impl gpui::Global for Preferences {}

impl Preferences {
    /// Whether terminal suggestions are on. True when the preferences were
    /// never loaded, which matches the default.
    pub fn is_suggestions_enabled(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_none_or(|prefs| prefs.is_suggestions_enabled)
    }

    /// Whether Option acts as Meta in the terminal. False when the
    /// preferences were never loaded, which matches the default.
    pub fn is_option_meta(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_some_and(|prefs| prefs.is_option_meta)
    }

    /// `None` when the user has not answered, or the preferences were never
    /// loaded.
    pub fn update_checks(cx: &gpui::App) -> Option<UpdateChecks> {
        cx.try_global::<Self>()
            .and_then(|prefs| prefs.update_checks)
    }

    pub fn terminal_font_size(cx: &gpui::App) -> f32 {
        cx.try_global::<Self>()
            .map_or(DEFAULT_TERMINAL_FONT_SIZE, |prefs| {
                clamp_terminal_font_size(prefs.terminal_font_size)
            })
    }

    /// Interface zoom, snapped onto the shortcut's ladder. 1 when preferences
    /// were never loaded.
    pub fn ui_scale(cx: &gpui::App) -> f32 {
        crate::ui::scale::clamp(
            cx.try_global::<Self>()
                .map(|prefs| prefs.ui_scale)
                .unwrap_or(crate::ui::scale::DEFAULT_UI_SCALE),
        )
    }

    pub fn terminal_font(cx: &gpui::App) -> TerminalFont {
        cx.try_global::<Self>()
            .map(|prefs| prefs.terminal_font)
            .unwrap_or_default()
    }

    pub fn terminal_scheme(cx: &gpui::App) -> TerminalScheme {
        cx.try_global::<Self>()
            .map(|prefs| prefs.terminal_scheme)
            .unwrap_or_default()
    }

    pub fn is_second_pane_shown(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_some_and(|prefs| prefs.is_second_pane_shown)
    }

    /// True when the preferences were never loaded, which matches the default.
    pub fn is_sidebar_shown(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_none_or(|prefs| prefs.is_sidebar_shown)
    }

    pub fn is_touch_id_enabled(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_some_and(|prefs| prefs.is_touch_id_enabled)
    }

    /// Inspector width the user dragged to, if they have.
    pub fn server_panel_width(cx: &gpui::App) -> Option<f32> {
        finite_width(
            cx.try_global::<Self>()
                .and_then(|prefs| prefs.server_panel_width),
        )
    }

    /// Agent chat width the user dragged to, if they have.
    pub fn agent_panel_width(cx: &gpui::App) -> Option<f32> {
        finite_width(
            cx.try_global::<Self>()
                .and_then(|prefs| prefs.agent_panel_width),
        )
    }

    /// Remember a width from dragging the server panel. The write waits until
    /// the pointer settles, so a drag is one write.
    pub fn set_dragged_panel_width(agent: bool, width: f32, cx: &mut gpui::App) {
        if !width.is_finite() {
            return;
        }
        let prefs = cx.default_global::<Self>();
        let current = if agent {
            prefs.agent_panel_width
        } else {
            prefs.server_panel_width
        };
        if current == Some(width) {
            return;
        }
        if agent {
            prefs.agent_panel_width = Some(width);
        } else {
            prefs.server_panel_width = Some(width);
        }

        cx.spawn(async move |cx| {
            cx.background_executor().timer(FONT_SIZE_SAVE_DELAY).await;
            cx.update(|cx| {
                let Some(prefs) = cx.try_global::<Self>() else {
                    return;
                };
                let stored = if agent {
                    prefs.agent_panel_width
                } else {
                    prefs.server_panel_width
                };
                // A later drag started its own timer and will do the write.
                if stored != Some(width) {
                    return;
                }
                if let Err(e) = prefs.save() {
                    tracing::warn!(?e, "failed to save server panel width");
                }
            });
        })
        .detach();
    }

    pub fn editor_command(cx: &gpui::App) -> String {
        let command = cx
            .try_global::<Self>()
            .map_or("", |prefs| prefs.editor_command.trim());
        if command.is_empty() {
            return DEFAULT_EDITOR_COMMAND.to_string();
        }
        command.to_string()
    }

    pub fn is_editor_default_open(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_some_and(|prefs| prefs.is_editor_default_open)
    }

    /// False when the preferences were never loaded.
    pub fn has_account(cx: &gpui::App) -> bool {
        cx.try_global::<Self>()
            .is_some_and(|prefs| prefs.has_account)
    }

    /// Change the preferences and write them to disk. The change has already
    /// taken effect in memory, so a failed write is logged and not surfaced.
    pub fn update(cx: &mut gpui::App, change: impl FnOnce(&mut Self)) {
        let prefs = cx.default_global::<Self>();
        change(prefs);
        if let Err(e) = prefs.save() {
            tracing::warn!(?e, "failed to save preferences");
        }
    }

    /// Set the font size of every terminal. The write to disk waits until the
    /// size settles, so holding a stepper gives one write.
    pub fn set_terminal_font_size(size: f32, cx: &mut gpui::App) {
        let size = clamp_terminal_font_size(size);
        if Self::terminal_font_size(cx) == size {
            return;
        }
        cx.default_global::<Self>().terminal_font_size = size;

        cx.spawn(async move |cx| {
            cx.background_executor().timer(FONT_SIZE_SAVE_DELAY).await;
            cx.update(|cx| {
                let Some(prefs) = cx.try_global::<Self>() else {
                    return;
                };
                // A later change started its own timer and will do the write.
                if prefs.terminal_font_size != size {
                    return;
                }
                // Written on the main thread like every other preference. A
                // copy written from another thread could land after a newer
                // save and put an old value back.
                if let Err(e) = prefs.save() {
                    tracing::warn!(?e, "failed to save terminal font size");
                }
            });
        })
        .detach();
    }

    /// Set the interface zoom and remember it once it stops changing. Returns
    /// whether the zoom actually moved. The caller repaints; this only stores
    /// the number and the scale [`crate::ui::scale::px`] reads.
    pub fn set_ui_scale(scale: f32, cx: &mut gpui::App) -> bool {
        let scale = crate::ui::scale::clamp(scale);
        if Self::ui_scale(cx) == scale {
            return false;
        }
        cx.default_global::<Self>().ui_scale = scale;
        crate::ui::scale::set_factor(scale);

        cx.spawn(async move |cx| {
            cx.background_executor().timer(FONT_SIZE_SAVE_DELAY).await;
            cx.update(|cx| {
                let Some(prefs) = cx.try_global::<Self>() else {
                    return;
                };
                if prefs.ui_scale != scale {
                    return;
                }
                if let Err(e) = prefs.save() {
                    tracing::warn!(?e, "failed to save interface zoom");
                }
            });
        })
        .detach();
        true
    }

    pub fn load_or_default() -> Self {
        match Self::path() {
            Some(path) => Self::load_from(&path),
            None => {
                tracing::warn!("no home directory, using default preferences");
                Self::default()
            }
        }
    }

    /// A corrupt preferences file must never stop the app from starting, so
    /// every failure here falls back to the defaults instead of propagating.
    fn load_from(path: &Path) -> Self {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(path = %path.display(), "no preferences file, using defaults");
                return Self::default();
            }
            Err(e) => {
                tracing::warn!(?e, path = %path.display(), "failed to read preferences.json");
                return Self::default();
            }
        };
        let mut prefs = serde_json::from_slice::<Self>(&data).unwrap_or_else(|e| {
            tracing::warn!(?e, "invalid preferences.json, using defaults");
            Self::default()
        });
        prefs.ui_scale = crate::ui::scale::clamp(prefs.ui_scale);
        Self {
            update_checks: update_checks_in(&data),
            has_account: has_account_in(&data),
            ..prefs
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not find the home directory",
            )
        })?;
        self.save_to(&path)
    }

    fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        // Written beside the file and moved over it, so a crash in the
        // middle of the write cannot leave half a file.
        let unfinished = path.with_extension("json.new");
        std::fs::write(&unfinished, json)?;
        std::fs::rename(&unfinished, path)
    }

    /// `None` when the OS gives no home directory, as in some sandboxes.
    fn path() -> Option<PathBuf> {
        Some(gssh::vault::app_data_dir()?.join("preferences.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_preference_uses_snake_case_on_the_wire() {
        for (pref, wire) in [
            (ThemePreference::Dark, "\"dark\""),
            (ThemePreference::Light, "\"light\""),
            (ThemePreference::System, "\"system\""),
        ] {
            assert_eq!(serde_json::to_string(&pref).unwrap(), wire);
            assert_eq!(serde_json::from_str::<ThemePreference>(wire).unwrap(), pref);
        }
    }

    #[test]
    fn missing_and_unknown_fields_fall_back_to_dark() {
        let empty: Preferences = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.theme, ThemePreference::Dark);

        let future: Preferences =
            serde_json::from_str(r#"{"theme":"light","future_field":42}"#).unwrap();
        assert_eq!(future.theme, ThemePreference::Light);
    }

    #[test]
    fn suggestions_default_to_on_and_round_trip() {
        assert!(Preferences::default().is_suggestions_enabled);
        // A file from before the field existed must not turn suggestions off.
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert!(old.is_suggestions_enabled);

        let off = Preferences {
            is_suggestions_enabled: false,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&off).unwrap();
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert!(!back.is_suggestions_enabled);
    }

    #[test]
    fn the_update_answer_starts_unset_and_round_trips() {
        assert_eq!(Preferences::default().update_checks, None);
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert_eq!(old.update_checks, None);

        for answer in [UpdateChecks::OnStart, UpdateChecks::Manual] {
            let prefs = Preferences {
                update_checks: Some(answer),
                ..Preferences::default()
            };
            let json = serde_json::to_string(&prefs).unwrap();
            assert_eq!(update_checks_in(json.as_bytes()), Some(answer), "{json}");
        }
        assert_eq!(
            serde_json::to_string(&UpdateChecks::OnStart).unwrap(),
            r#""on_start""#
        );
        assert_eq!(
            serde_json::to_string(&UpdateChecks::Manual).unwrap(),
            r#""manual""#
        );
    }

    #[test]
    fn a_file_from_0_1_counts_only_a_turned_off_check_as_an_answer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preferences.json");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            Preferences::load_from(&path).update_checks
        };

        assert_eq!(
            load(r#"{"theme":"light","is_update_check_enabled":false}"#),
            Some(UpdateChecks::Manual)
        );
        assert_eq!(
            load(r#"{"theme":"light","is_update_check_enabled":true}"#),
            None
        );
        assert_eq!(load(r#"{"theme":"light"}"#), None);
        // An answer given in this build wins over the old key.
        assert_eq!(
            load(r#"{"update_checks":"on_start","is_update_check_enabled":false}"#),
            Some(UpdateChecks::OnStart)
        );
    }

    #[test]
    fn the_update_answer_stays_when_the_rest_of_the_file_does_not_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preferences.json");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            Preferences::load_from(&path)
        };

        // A value written by a newer build.
        let manual = load(r#"{"terminal_scheme":"from-the-future","update_checks":"manual"}"#);
        assert_eq!(manual.update_checks, Some(UpdateChecks::Manual));
        assert_eq!(manual.terminal_font_size, DEFAULT_TERMINAL_FONT_SIZE);

        assert_eq!(
            load(r#"{"terminal_scheme":7,"is_update_check_enabled":false}"#).update_checks,
            Some(UpdateChecks::Manual)
        );
        assert_eq!(
            load(r#"{"terminal_scheme":7,"update_checks":"on_start"}"#).update_checks,
            Some(UpdateChecks::OnStart)
        );
        assert_eq!(
            load(r#"{"terminal_scheme":"from-the-future"}"#).update_checks,
            None
        );
        assert_eq!(load("not json").update_checks, None);
    }

    #[test]
    fn the_account_flag_stays_when_the_rest_of_the_file_does_not_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preferences.json");
        let load = |text: &str| {
            std::fs::write(&path, text).unwrap();
            Preferences::load_from(&path)
        };

        let future = load(r#"{"terminal_scheme":"from-the-future","has_account":true}"#);
        assert!(future.has_account);
        assert_eq!(future.terminal_font_size, DEFAULT_TERMINAL_FONT_SIZE);

        assert!(load(r#"{"has_account":true}"#).has_account);
        assert!(!load(r#"{"has_account":false}"#).has_account);
        assert!(!load(r#"{"theme":"light"}"#).has_account);
        assert!(!load(r#"{"terminal_scheme":7}"#).has_account);
        assert!(!load("not json").has_account);
    }

    #[test]
    fn saving_replaces_the_file_and_leaves_nothing_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g-ssh").join("preferences.json");
        let manual = Preferences {
            update_checks: Some(UpdateChecks::Manual),
            ..Preferences::default()
        };

        Preferences::default().save_to(&path).unwrap();
        manual.save_to(&path).unwrap();

        assert_eq!(
            Preferences::load_from(&path).update_checks,
            Some(UpdateChecks::Manual)
        );
        let left: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(left.len(), 1, "{left:?}");
    }

    #[test]
    fn option_meta_defaults_to_off_and_round_trips() {
        assert!(!Preferences::default().is_option_meta);
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert!(!old.is_option_meta);

        let on = Preferences {
            is_option_meta: true,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&on).unwrap();
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert!(back.is_option_meta);
    }

    #[test]
    fn session_layout_defaults_when_missing_and_round_trips() {
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert_eq!(old.terminal_position, TerminalPosition::Below);
        assert!(!old.is_second_pane_shown);

        let changed = Preferences {
            terminal_position: TerminalPosition::Beside,
            is_second_pane_shown: true,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&changed).unwrap();
        assert!(json.contains(r#""terminal_position":"beside""#), "{json}");
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back.terminal_position, TerminalPosition::Beside);
        assert!(back.is_second_pane_shown);
    }

    #[test]
    fn server_panel_width_defaults_when_missing_and_round_trips() {
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert_eq!(old.server_panel_width, None);
        assert_eq!(old.agent_panel_width, None);

        let changed = Preferences {
            server_panel_width: Some(400.),
            agent_panel_width: Some(560.),
            ..Preferences::default()
        };
        let json = serde_json::to_string(&changed).unwrap();
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server_panel_width, Some(400.));
        assert_eq!(back.agent_panel_width, Some(560.));
    }

    #[test]
    fn sidebar_is_shown_when_missing_and_round_trips() {
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert!(old.is_sidebar_shown);

        let hidden = Preferences {
            is_sidebar_shown: false,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&hidden).unwrap();
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert!(!back.is_sidebar_shown);
    }

    #[test]
    fn editor_settings_default_when_missing_and_round_trip() {
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert_eq!(old.editor_command, DEFAULT_EDITOR_COMMAND);
        assert!(!old.is_editor_default_open);

        let changed = Preferences {
            editor_command: "sudoedit {path}".to_string(),
            is_editor_default_open: true,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&changed).unwrap();
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back.editor_command, "sudoedit {path}");
        assert!(back.is_editor_default_open);
    }

    #[test]
    fn terminal_settings_default_when_missing_and_round_trip() {
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert_eq!(old.terminal_font_size, DEFAULT_TERMINAL_FONT_SIZE);
        assert_eq!(old.terminal_font, TerminalFont::CascadiaCode);
        assert_eq!(old.terminal_scheme, TerminalScheme::FollowTheme);

        let changed = Preferences {
            terminal_font_size: 17.0,
            terminal_font: TerminalFont::JetBrainsMono,
            terminal_scheme: TerminalScheme::TokyoNight,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&changed).unwrap();
        assert!(
            json.contains(r#""terminal_font":"jet_brains_mono""#),
            "{json}"
        );
        assert!(
            json.contains(r#""terminal_scheme":"tokyo_night""#),
            "{json}"
        );
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back.terminal_font_size, 17.0);
        assert_eq!(back.terminal_font, TerminalFont::JetBrainsMono);
        assert_eq!(back.terminal_scheme, TerminalScheme::TokyoNight);
    }

    #[test]
    fn ui_scale_defaults_when_missing() {
        assert_eq!(
            Preferences::default().ui_scale,
            crate::ui::scale::DEFAULT_UI_SCALE
        );
        let old: Preferences = serde_json::from_str(r#"{"theme":"light"}"#).unwrap();
        assert_eq!(old.ui_scale, crate::ui::scale::DEFAULT_UI_SCALE);
    }

    #[test]
    fn terminal_font_size_is_clamped_to_a_usable_range() {
        assert_eq!(clamp_terminal_font_size(14.0), 14.0);
        assert_eq!(clamp_terminal_font_size(0.0), MIN_TERMINAL_FONT_SIZE);
        assert_eq!(clamp_terminal_font_size(-3.0), MIN_TERMINAL_FONT_SIZE);
        assert_eq!(clamp_terminal_font_size(900.0), MAX_TERMINAL_FONT_SIZE);
        assert_eq!(
            clamp_terminal_font_size(f32::NAN),
            DEFAULT_TERMINAL_FONT_SIZE
        );
        assert_eq!(
            clamp_terminal_font_size(f32::INFINITY),
            DEFAULT_TERMINAL_FONT_SIZE
        );
    }

    #[test]
    fn every_terminal_font_and_scheme_is_listed_once() {
        for (ix, font) in TerminalFont::ALL.iter().enumerate() {
            assert!(
                !TerminalFont::ALL[..ix].contains(font),
                "{font:?} listed twice"
            );
        }
        for (ix, scheme) in TerminalScheme::ALL.iter().enumerate() {
            assert!(
                !TerminalScheme::ALL[..ix].contains(scheme),
                "{scheme:?} listed twice"
            );
        }
    }

    #[test]
    fn available_fonts_keep_the_bundled_one_and_drop_missing_ones() {
        let installed = vec!["Menlo".to_string(), "Helvetica".to_string()];
        assert_eq!(
            TerminalFont::available(&installed),
            vec![TerminalFont::CascadiaCode, TerminalFont::Menlo]
        );
        assert_eq!(
            TerminalFont::available(&[]),
            vec![TerminalFont::CascadiaCode]
        );
    }

    #[test]
    fn nerd_fonts_match_either_published_name_and_skip_propo() {
        let by_short = TerminalFont::available(&["FiraMono NF".into()]);
        assert_eq!(
            by_short,
            vec![TerminalFont::CascadiaCode, TerminalFont::FiraMonoNerd]
        );
        let by_long = TerminalFont::available(&["JetBrainsMono Nerd Font Mono".into()]);
        assert_eq!(
            by_long,
            vec![
                TerminalFont::CascadiaCode,
                TerminalFont::JetBrainsMonoNerdMono
            ]
        );
        let propo = TerminalFont::available(&["JetBrainsMono Nerd Font Propo".into()]);
        assert_eq!(propo, vec![TerminalFont::CascadiaCode]);

        let mut seen = std::collections::HashSet::new();
        for font in TerminalFont::ALL {
            let names = font.families();
            assert_eq!(font.family(), names[0]);
            match names {
                [long, short] => {
                    if let Some(base) = long.strip_suffix(" Nerd Font Mono") {
                        assert_eq!(*short, format!("{base} NFM"));
                    } else if let Some(base) = long.strip_suffix(" Nerd Font") {
                        assert_eq!(*short, format!("{base} NF"));
                    } else {
                        panic!("{long} is not a nerd font family");
                    }
                }
                [_] => {}
                _ => panic!("{font:?} has an unexpected number of family names"),
            }
            for name in names {
                assert!(
                    seen.insert(*name),
                    "{name} is the family of more than one font"
                );
                assert!(!name.contains("Propo") && !name.ends_with(" NFP"));
            }
        }
    }

    #[test]
    fn nerd_font_preference_round_trips() {
        let changed = Preferences {
            terminal_font: TerminalFont::FiraMonoNerd,
            ..Preferences::default()
        };
        let json = serde_json::to_string(&changed).unwrap();
        assert!(
            json.contains(r#""terminal_font":"fira_mono_nerd""#),
            "{json}"
        );
        let back: Preferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back.terminal_font, TerminalFont::FiraMonoNerd);
    }

    #[test]
    fn load_from_survives_a_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preferences.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert_eq!(Preferences::load_from(&path).theme, ThemePreference::Dark);
    }

    #[test]
    fn load_from_reads_a_written_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("preferences.json");
        std::fs::write(&path, r#"{"theme":"system"}"#).unwrap();
        assert_eq!(Preferences::load_from(&path).theme, ThemePreference::System);
    }
}
