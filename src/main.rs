#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use assets::Assets;
use gpui::prelude::*;
use gpui::{
    px, relative, size, AnyView, App, Application, AssetSource, Bounds, QuitMode, TitlebarOptions,
    WindowBounds, WindowOptions,
};
use gpui_component::{theme::ThemeMode, Root};

mod assets;
mod files;
mod host_stats;
mod import;
mod logging;
mod open_tabs;
mod preferences;
mod theme;
mod touch_id;
mod ui;
mod updates;
mod version;

use gssh::ssh::shell;
use gssh::vault;
use preferences::{Preferences, ThemePreference};
use ui::root::RootView;

fn main() {
    // A second copy of this binary, started to swap in an update after quit.
    updates::apply::finish_if_requested();
    // Started from `.g-ssh-update-…\g-ssh.exe`: copy onto the installed exe
    // and reopen that. An older build unpacks the new exe and stops there.
    updates::apply::adopt_if_staged();

    gssh::app::set_version(version::CURRENT);
    if let Some(dir) = dirs::home_dir() {
        gssh::app::set_data_dir(dir.join(".g-ssh"));
    }

    vault::memory::disable_core_dumps();

    logging::init();

    let platform = gpui_platform::current_platform(false);
    let app = Application::with_platform(platform)
        .with_assets(Assets)
        // macOS otherwise keeps the process, and the Dock icon, after the
        // window closes. A click on that icon does not open a window.
        .with_quit_mode(QuitMode::LastWindowClosed);
    app.on_reopen(|cx| {
        if cx.windows().is_empty() {
            open_main_window(cx);
        }
        cx.activate(true);
    });
    app.run(|cx: &mut App| {
        // The assets folder is embedded whole, so the fonts come from
        // there and are not compiled in a second time. Source Sans 3 is
        // the interface; Cascadia Code is addresses, paths, and the
        // terminal default.
        let fonts = [
            "fonts/SourceSans3-Regular.ttf",
            "fonts/SourceSans3-Medium.ttf",
            "fonts/SourceSans3-Semibold.ttf",
            "fonts/SourceSans3-Bold.ttf",
            "fonts/CascadiaCode.ttf",
        ]
        .into_iter()
        .map(|path| {
            Assets
                .load(path)
                .expect("read the embedded assets")
                .unwrap_or_else(|| panic!("{path} is among the embedded assets"))
        })
        .collect();
        cx.text_system()
            .add_fonts(fonts)
            .expect("load interface fonts");

        gpui_component::init(cx);
        crate::ui::terminal::view::init(cx);
        crate::ui::sftp::keys::init(cx);
        crate::ui::app::init(cx);
        crate::ui::settings::init(cx);

        // Loaded before the vault so the unlock screen is already themed.
        // The zoom has to be installed first: the theme's rem is read from it.
        let prefs = Preferences::load_or_default();
        crate::ui::scale::set_factor(prefs.ui_scale);
        let theme_preference = prefs.theme;
        cx.set_global(prefs);
        theme::apply_preference(theme_preference, None, cx);

        // macOS does not quit when the last window closes unless asked.
        quit_when_the_last_window_closes();
        open_main_window(cx);

        // Clicking a transfer notification should bring g-ssh forward, not
        // just dismiss the banner.
        cx.on_system_notification_response(|_response, cx| {
            cx.activate(true);
        });

        cx.activate(true);
    });
}

fn open_main_window(cx: &mut App) {
    let bounds = Bounds::centered(None, size(px(1100.), px(700.)), cx);
    cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_min_size: Some(size(px(920.), px(540.))),
            titlebar: Some(TitlebarOptions {
                title: Some("g-ssh".into()),
                appears_transparent: true,
                traffic_light_position: None,
            }),
            // macOS: a movable window makes the native title bar drag-track
            // every click in its strip before delivering it, which lags the
            // title-bar search. Disable native moving; we drag the window
            // ourselves via `start_window_move()` on the drag region.
            // Windows must keep it: there the drag region only works
            // because the platform maps it to a caption hit-test, and gpui
            // skips that mapping when the window is not movable.
            is_movable: !cfg!(target_os = "macos"),
            ..Default::default()
        },
        |window, cx| {
            window
                .observe_window_appearance(|window, cx| {
                    if cx.global::<Preferences>().theme != ThemePreference::System {
                        return;
                    }
                    let mode = ThemeMode::from(window.appearance());
                    theme::apply_mode(mode, Some(window), cx);
                })
                .detach();

            shell::set_window_visible(window.is_visible());
            window
                .observe_window_visibility(|visibility, _, _| {
                    tracing::debug!(?visibility, "window visibility changed");
                    shell::set_window_visible(visibility.is_visible());
                })
                .detach();

            let view = cx.new(|cx| RootView::new(window, cx));
            // gpui defaults every line box to 1.618x the font size, which
            // makes rows a third taller than the text needs. The whole UI
            // is chrome, not prose, so it inherits a tight line box here.
            cx.new(|cx| Root::new(AnyView::from(view), window, cx).line_height(relative(1.3)))
        },
    )
    .expect("open window");
}

/// macOS leaves the process, and the Dock icon, running after the last window
/// closes. Ask it to quit then, so the next launch starts a new process.
#[cfg(target_os = "macos")]
fn quit_when_the_last_window_closes() {
    use objc2::ffi::class_addMethod;
    use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, Sel};

    extern "C-unwind" fn yes(_: &AnyObject, _: Sel, _: *mut AnyObject) -> Bool {
        Bool::YES
    }

    let Some(class) = AnyClass::get(c"GPUIApplicationDelegate") else {
        tracing::warn!("closing the window will leave g-ssh running");
        return;
    };
    let sel = Sel::register(c"applicationShouldTerminateAfterLastWindowClosed:");
    let added = unsafe {
        class_addMethod(
            std::ptr::from_ref(class).cast_mut(),
            sel,
            std::mem::transmute::<extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject) -> Bool, Imp>(
                yes,
            ),
            c"B@:@".as_ptr(),
        )
    };
    if !added.as_bool() {
        tracing::warn!("closing the window will leave g-ssh running");
    }
}

#[cfg(not(target_os = "macos"))]
fn quit_when_the_last_window_closes() {}
