//! Knows whether a newer build is out, and downloads it when asked. Lives for
//! the whole run of the app, so the title bar and Settings show one state.
//!
//! The requests themselves are in `crate::updates`. This file decides when
//! they are made: never on an OS without builds, on a timer only when the
//! user chose checks on start, and otherwise only when Check now is pressed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use gpui::{App, AppContext as _, Context, Entity, Global};

use crate::preferences::{Preferences, UpdateChecks};
use crate::updates::{self, Release, UpdateError};
use crate::version;

/// Long enough that the check does not compete with the window coming up.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(10);
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// How often the service looks whether a check is due. Also the wait before
/// a failed check is tried again.
const DUE_LOOK_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub enum Download {
    Idle,
    Running {
        percent: u8,
    },
    /// The archive is in place and the app is about to quit so it can be replaced.
    Installing,
    Failed(String),
}

pub struct UpdateService {
    pub is_checking: bool,
    /// How the last check ended, and when if it went well. `None` before
    /// the first one.
    last_check: Option<Result<SystemTime, String>>,
    /// The build GitHub offers, when it is newer than this app.
    pub release: Option<Release>,
    pub download: Download,
    is_cancelled: Arc<AtomicBool>,
    /// Counts cancels and resets, so an answer to work nobody waits for any
    /// more is ignored.
    generation: u64,
    /// Names the cancel file for the installer that is running, if one is.
    install_token: Option<String>,
    /// The "Check for updates?" question was put this run. Asked once per
    /// run at most, even when it was closed without an answer.
    is_question_asked: bool,
}

struct GlobalUpdateService(Entity<UpdateService>);

impl Global for GlobalUpdateService {}

enum DownloadEvent {
    Progress(u8),
    Installing,
    /// The release that was staged. `Ok` means this process should quit so
    /// the installer can replace it and reopen.
    Finished(Result<Release, UpdateError>),
}

impl UpdateService {
    pub fn install(cx: &mut App) {
        let service = cx.new(Self::new);
        cx.set_global(GlobalUpdateService(service));
    }

    pub fn global(cx: &App) -> Entity<Self> {
        cx.global::<GlobalUpdateService>().0.clone()
    }

    fn new(cx: &mut Context<Self>) -> Self {
        cx.spawn(async move |this, cx| {
            let mut delay = FIRST_CHECK_DELAY;
            loop {
                cx.background_executor().timer(delay).await;
                if this.update(cx, |this, cx| this.check_if_due(cx)).is_err() {
                    break;
                }
                // The timer stands still while the machine sleeps, so it
                // cannot count the six hours. The clock can.
                delay = DUE_LOOK_INTERVAL;
            }
        })
        .detach();

        Self {
            is_checking: false,
            last_check: None,
            release: None,
            download: Download::Idle,
            is_cancelled: Arc::new(AtomicBool::new(false)),
            generation: 0,
            install_token: None,
            is_question_asked: false,
        }
    }

    /// Whether the "Check for updates?" question should be put now. Marks it
    /// as asked, so the caller must show it when this says yes.
    pub fn take_question(&mut self, cx: &App) -> bool {
        let is_due = !self.is_question_asked
            && updates::platform().is_some()
            && Preferences::update_checks(cx).is_none();
        if is_due {
            self.is_question_asked = true;
        }
        is_due
    }

    /// The timer's check. Only in automatic mode: with no answer yet, or
    /// with manual checks, the app makes no request on its own.
    fn check_if_due(&mut self, cx: &mut Context<Self>) {
        if Preferences::update_checks(cx) != Some(UpdateChecks::OnStart) {
            return;
        }
        if is_check_due(&self.last_check, SystemTime::now()) {
            self.check(cx);
        }
    }

    /// Ask GitHub which build is current. Does nothing when this OS has
    /// no builds.
    pub fn check(&mut self, cx: &mut Context<Self>) {
        let Some(platform) = updates::platform() else {
            return;
        };
        if self.is_checking {
            return;
        }
        self.is_checking = true;
        cx.notify();

        let (tx, rx) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let _ = tx.try_send(updates::newer_release(platform, version::CURRENT));
        });
        let generation = self.generation;
        cx.spawn(async move |this, cx| {
            let Ok(answer) = rx.recv().await else { return };
            this.update(cx, |this, cx| {
                if this.generation == generation {
                    this.finish_check(answer, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    fn finish_check(
        &mut self,
        answer: Result<Option<Release>, UpdateError>,
        cx: &mut Context<Self>,
    ) {
        self.is_checking = false;
        match answer {
            Ok(offered) => {
                self.last_check = Some(Ok(SystemTime::now()));
                self.take_offer(offered);
            }
            // Shown on the About page only. A laptop that is offline must
            // not be told about it every time.
            Err(e) => {
                tracing::debug!(error = %e, "update check failed");
                self.last_check = Some(Err(e.to_string()));
            }
        }
        cx.notify();
    }

    fn take_offer(&mut self, offered: Option<Release>) {
        // The download on screen belongs to the release on screen.
        if self.is_busy() || self.release == offered {
            return;
        }
        if let Some(release) = &offered {
            tracing::info!(version = %release.version, "a newer version is available");
        }
        self.release = offered;
        self.download = Download::Idle;
    }

    /// Save the user's answer. Checks on start begin right away, unless a
    /// check went well within the last six hours. Manual keeps what is known and a
    /// download the user started: it only stops the timer's requests.
    pub fn set_update_checks(&mut self, answer: UpdateChecks, cx: &mut Context<Self>) {
        tracing::info!(?answer, "update checks set");
        Preferences::update(cx, |prefs| prefs.update_checks = Some(answer));
        self.check_if_due(cx);
        cx.notify();
    }

    /// Download the offered build and replace this app with it. The app quits
    /// when the new copy is ready, and the installer reopens it.
    pub fn start_update(&mut self, cx: &mut Context<Self>) {
        let Some(platform) = updates::platform() else {
            return;
        };
        let Some(release) = self.release.clone() else {
            return;
        };
        if self.is_busy() {
            return;
        }
        let Some(folder) = updates::cache_dir() else {
            self.download = Download::Failed("Could not find a place to store the update.".into());
            cx.notify();
            return;
        };
        self.download = Download::Running { percent: 0 };
        self.is_cancelled = Arc::new(AtomicBool::new(false));
        let token = uuid::Uuid::new_v4().simple().to_string();
        self.install_token = Some(token.clone());
        cx.notify();
        tracing::info!(version = %release.version, folder = %folder.display(), "update download started");

        let (tx, rx) = async_channel::unbounded();
        let is_cancelled = self.is_cancelled.clone();
        std::thread::spawn(move || {
            let mut last_percent = 0;
            // One event for each percent, not one for each block read.
            let on_progress = |received, total| {
                let percent = percent_of(received, total);
                if percent != last_percent {
                    last_percent = percent;
                    let _ = tx.try_send(DownloadEvent::Progress(percent));
                }
            };
            let done = updates::download_offer(
                platform,
                &release,
                version::CURRENT,
                &folder,
                &is_cancelled,
                on_progress,
            );
            let done = match done {
                Ok((release, path)) if is_cancelled.load(Ordering::Relaxed) => {
                    let _ = (release, path);
                    Err(UpdateError::Cancelled)
                }
                Ok((release, path)) => {
                    let _ = tx.try_send(DownloadEvent::Installing);
                    updates::apply::install(&path, &is_cancelled, &token).map(|()| release)
                }
                Err(error) => Err(error),
            };
            let _ = tx.try_send(DownloadEvent::Finished(done));
        });

        let generation = self.generation;
        cx.spawn(async move |this, cx| {
            while let Ok(event) = rx.recv().await {
                let handled = this.update(cx, |this, cx| {
                    if this.generation != generation {
                        return;
                    }
                    let quit = this.take_download_event(event);
                    cx.notify();
                    if quit {
                        cx.quit();
                    }
                });
                if handled.is_err() {
                    break;
                }
            }
        })
        .detach();
    }

    pub fn cancel_download(&mut self, cx: &mut Context<Self>) {
        if !matches!(
            self.download,
            Download::Running { .. } | Download::Installing
        ) {
            return;
        }
        self.stop_work();
        cx.notify();
    }

    /// The worker thread sees the flag, deletes its part file and ends.
    fn stop_work(&mut self) {
        self.is_cancelled.store(true, Ordering::Relaxed);
        if let Some(token) = self.install_token.take() {
            updates::apply::cancel_installer(&token);
        }
        self.generation += 1;
        self.is_checking = false;
        self.download = Download::Idle;
    }

    /// `true` when the new app is staged and this process should quit.
    fn take_download_event(&mut self, event: DownloadEvent) -> bool {
        match event {
            DownloadEvent::Progress(percent) => {
                self.download = Download::Running { percent };
                false
            }
            DownloadEvent::Installing => {
                self.download = Download::Installing;
                false
            }
            DownloadEvent::Finished(Ok(release)) => {
                tracing::info!(version = %release.version, "update staged, reopening");
                // Not always the build that was offered: the GitHub release may
                // have been replaced since the check.
                self.release = Some(release);
                self.download = Download::Installing;
                true
            }
            // Only a cancel the service did not ask for ends up here.
            DownloadEvent::Finished(Err(UpdateError::Cancelled)) => {
                self.download = Download::Idle;
                false
            }
            // The server has nothing newer any more, so there is no offer.
            DownloadEvent::Finished(Err(UpdateError::Withdrawn)) => {
                tracing::info!("the offered build is no longer on the GitHub release");
                self.release = None;
                self.download = Download::Idle;
                false
            }
            DownloadEvent::Finished(Err(error)) => {
                tracing::warn!(error = %error, "update failed");
                self.download = Download::Failed(failure_message(&error));
                false
            }
        }
    }

    fn is_busy(&self) -> bool {
        matches!(
            self.download,
            Download::Running { .. } | Download::Installing
        )
    }

    /// Label for the About page's update button. `None` when there is no
    /// newer build. While a download is running, the percent.
    pub fn update_action_label(&self) -> Option<String> {
        if self.release.is_none() {
            return None;
        }
        Some(match self.download {
            Download::Running { percent } => format!("Downloading {percent}%"),
            Download::Installing => "Installing\u{2026}".into(),
            Download::Idle | Download::Failed(_) => "Update".into(),
        })
    }

    /// The line beside Check now on the About page.
    pub fn result_line(&self, is_automatic: bool) -> String {
        if self.is_checking {
            return "Checking\u{2026}".into();
        }
        match (&self.last_check, &self.release) {
            (Some(Err(problem)), _) => format!("Could not check: {problem}"),
            (_, Some(release)) => format!("{} is available", release.version),
            (Some(Ok(_)), None) => "Up to date".into(),
            (None, None) if is_automatic => "Not checked yet".into(),
            (None, None) => "Checks only when you press Check now".into(),
        }
    }
}

/// A check is due when the last one failed, or went well six hours ago.
fn is_check_due(last_check: &Option<Result<SystemTime, String>>, now: SystemTime) -> bool {
    let Some(Ok(checked_at)) = last_check else {
        return true;
    };
    // A clock that was set back gives no age: check then.
    !now.duration_since(*checked_at)
        .is_ok_and(|age| age < CHECK_INTERVAL)
}

fn failure_message(error: &UpdateError) -> String {
    let kind = if is_install_error(error) {
        "update"
    } else {
        "download"
    };
    format!("Could not {kind}: {error}.")
}

fn is_install_error(error: &UpdateError) -> bool {
    matches!(
        error,
        UpdateError::NotInstalled
            | UpdateError::NotWritable
            | UpdateError::NotAnApp
            | UpdateError::Install(_)
    )
}

fn percent_of(received: u64, total: u64) -> u8 {
    if total == 0 {
        return 0;
    }
    (received.min(total) * 100 / total) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str) -> Release {
        Release {
            version: version.into(),
            notes: String::new(),
            filename: format!("g-ssh-{version}.dmg"),
            size_bytes: 1000,
            sha256: "00".into(),
            tag: format!("v{version}"),
        }
    }

    fn service() -> UpdateService {
        UpdateService {
            is_checking: false,
            last_check: None,
            release: None,
            download: Download::Idle,
            is_cancelled: Arc::new(AtomicBool::new(false)),
            generation: 0,
            install_token: None,
            is_question_asked: false,
        }
    }

    #[test]
    fn percent_is_whole_and_never_above_a_hundred() {
        assert_eq!(percent_of(0, 1000), 0);
        assert_eq!(percent_of(499, 1000), 49);
        assert_eq!(percent_of(1000, 1000), 100);
        assert_eq!(percent_of(5000, 1000), 100);
        assert_eq!(percent_of(5, 0), 0);
        assert_eq!(percent_of(300 * 1024 * 1024, 300 * 1024 * 1024), 100);
    }

    #[test]
    fn the_result_line_says_how_the_last_check_ended() {
        let mut service = service();
        assert_eq!(service.result_line(true), "Not checked yet");
        assert_eq!(
            service.result_line(false),
            "Checks only when you press Check now"
        );

        service.is_checking = true;
        assert_eq!(service.result_line(true), "Checking\u{2026}");
        service.is_checking = false;

        service.last_check = Some(Ok(SystemTime::now()));
        assert_eq!(service.result_line(true), "Up to date");

        assert_eq!(service.result_line(false), "Up to date");

        service.release = Some(release("0.2.0"));
        assert_eq!(service.result_line(true), "0.2.0 is available");
        // A manual check that found a build says so.
        assert_eq!(service.result_line(false), "0.2.0 is available");

        service.last_check = Some(Err("could not reach GitHub: timed out".into()));
        assert_eq!(
            service.result_line(true),
            "Could not check: could not reach GitHub: timed out"
        );
    }

    #[test]
    fn the_update_button_appears_only_when_a_build_is_waiting() {
        let mut service = service();
        assert_eq!(service.update_action_label(), None);

        service.release = Some(release("0.2.0"));
        assert_eq!(service.update_action_label().as_deref(), Some("Update"));

        service.download = Download::Running { percent: 42 };
        assert_eq!(
            service.update_action_label().as_deref(),
            Some("Downloading 42%")
        );

        service.download = Download::Installing;
        assert_eq!(
            service.update_action_label().as_deref(),
            Some("Installing\u{2026}")
        );
    }

    #[test]
    fn a_new_offer_replaces_the_old_one_and_its_download() {
        let mut service = service();
        service.take_offer(Some(release("0.2.0")));
        service.download = Download::Failed("Could not update: x.".into());

        // The same offer again keeps the failure on screen.
        service.take_offer(Some(release("0.2.0")));
        assert!(matches!(service.download, Download::Failed(_)));

        service.take_offer(Some(release("0.3.0")));
        assert_eq!(service.release, Some(release("0.3.0")));
        assert!(matches!(service.download, Download::Idle));

        service.take_offer(None);
        assert_eq!(service.release, None);
    }

    #[test]
    fn an_offer_does_not_change_under_a_running_download() {
        let mut service = service();
        service.take_offer(Some(release("0.2.0")));
        service.download = Download::Running { percent: 40 };

        service.take_offer(Some(release("0.3.0")));

        assert_eq!(service.release, Some(release("0.2.0")));
        assert!(matches!(
            service.download,
            Download::Running { percent: 40 }
        ));
    }

    #[test]
    fn download_events_move_the_state() {
        let mut service = service();
        service.release = Some(release("0.2.0"));

        assert!(!service.take_download_event(DownloadEvent::Progress(7)));
        assert!(matches!(service.download, Download::Running { percent: 7 }));

        assert!(!service.take_download_event(DownloadEvent::Finished(Err(UpdateError::Cancelled))));
        assert!(matches!(service.download, Download::Idle));

        assert!(
            !service.take_download_event(DownloadEvent::Finished(Err(UpdateError::WrongChecksum)))
        );
        let Download::Failed(problem) = &service.download else {
            panic!("a wrong checksum must fail the download");
        };
        assert_eq!(
            problem,
            "Could not download: the file does not match the checksum GitHub announced, so it was \
             not kept."
        );
        assert_eq!(service.release, Some(release("0.2.0")));
    }

    #[test]
    fn a_staged_update_keeps_the_build_and_asks_the_app_to_quit() {
        let mut service = service();
        service.release = Some(release("0.2.0"));

        // GitHub had 0.3.0 by the time of the download.
        let quit = service.take_download_event(DownloadEvent::Finished(Ok(release("0.3.0"))));

        assert!(quit);
        assert_eq!(service.release, Some(release("0.3.0")));
        assert!(matches!(service.download, Download::Installing));
    }

    #[test]
    fn an_install_problem_is_not_called_a_download_problem() {
        let mut service = service();
        service.release = Some(release("0.2.0"));

        assert!(
            !service.take_download_event(DownloadEvent::Finished(Err(UpdateError::NotInstalled)))
        );

        let Download::Failed(problem) = &service.download else {
            panic!("a copy that is not the installed app must fail");
        };
        assert_eq!(
            problem,
            "Could not update: this copy of g-ssh is not the installed app, so it cannot replace \
             itself."
        );
    }

    #[test]
    fn a_withdrawn_build_takes_the_offer_away() {
        let mut service = service();
        service.release = Some(release("0.2.0"));
        service.download = Download::Running { percent: 3 };

        assert!(!service.take_download_event(DownloadEvent::Finished(Err(UpdateError::Withdrawn))));

        assert_eq!(service.release, None);
        assert!(matches!(service.download, Download::Idle));
    }

    #[test]
    fn a_failed_check_is_due_again_and_a_good_one_after_six_hours() {
        let now = SystemTime::now();
        let ago = |seconds| Some(Ok(now - Duration::from_secs(seconds)));

        assert!(is_check_due(&None, now));
        assert!(is_check_due(&Some(Err("offline".into())), now));
        assert!(!is_check_due(&ago(0), now));
        assert!(!is_check_due(&ago(6 * 60 * 60 - 1), now));
        assert!(is_check_due(&ago(6 * 60 * 60), now));
        // The clock was set back after the check.
        assert!(is_check_due(&Some(Ok(now + Duration::from_secs(60))), now));
    }

    #[test]
    fn stopping_resets_the_download_and_tells_the_worker() {
        let mut service = service();
        service.download = Download::Running { percent: 40 };
        service.is_checking = true;
        let flag = service.is_cancelled.clone();

        service.stop_work();

        assert!(flag.load(Ordering::Relaxed));
        assert!(matches!(service.download, Download::Idle));
        assert!(!service.is_checking);
        assert_eq!(service.generation, 1);
    }
}
