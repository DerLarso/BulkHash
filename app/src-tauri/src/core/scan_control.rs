use crate::core::io::bulk_hash_error::BulkHashError;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

const PAUSE_POLL_FALLBACK: Duration = Duration::from_millis(25);

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum ScanControlState {
    #[default]
    Running,
    Paused,
    Cancelled,
}

impl fmt::Display for ScanControlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("Running"),
            Self::Paused => f.write_str("Paused"),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

#[derive(Debug)]
struct PauseState {
    paused: bool,
    paused_since: Option<Instant>,
    accumulated_pause: Duration,
    paused_waiters: usize,
}

impl PauseState {
    const fn new() -> Self {
        Self {
            paused: false,
            paused_since: None,
            accumulated_pause: Duration::ZERO,
            paused_waiters: 0,
        }
    }

    fn total_paused_at(&self, now: Instant) -> Duration {
        let active_pause = self
            .paused_since
            .map_or(Duration::ZERO, |since| now.saturating_duration_since(since));
        self.accumulated_pause.saturating_add(active_pause)
    }
}

#[derive(Debug)]
pub(crate) struct PauseInner {
    state: Mutex<PauseState>,
    condvar: Condvar,
    waiters_changed: Condvar,
    paused: AtomicBool,
}

impl PauseInner {
    fn new() -> Self {
        Self {
            state: Mutex::new(PauseState::new()),
            condvar: Condvar::new(),
            waiters_changed: Condvar::new(),
            paused: AtomicBool::new(false),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, PauseState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn pause(&self) {
        let mut guard = self.lock_state();
        if !guard.paused {
            guard.paused = true;
            guard.paused_since = Some(Instant::now());
            self.paused.store(true, Ordering::Release);
        }
    }

    fn resume(&self) {
        let mut guard = self.lock_state();
        if guard.paused {
            let now = Instant::now();
            guard.paused = false;
            if let Some(since) = guard.paused_since.take() {
                guard.accumulated_pause = guard
                    .accumulated_pause
                    .saturating_add(now.saturating_duration_since(since));
            }
            self.paused.store(false, Ordering::Release);
            drop(guard);
            self.condvar.notify_all();
            self.waiters_changed.notify_all();
        }
    }

    fn toggle_pause(&self) -> bool {
        let mut guard = self.lock_state();
        let now = Instant::now();
        if guard.paused {
            guard.paused = false;
            if let Some(since) = guard.paused_since.take() {
                guard.accumulated_pause = guard
                    .accumulated_pause
                    .saturating_add(now.saturating_duration_since(since));
            }
            self.paused.store(false, Ordering::Release);
            drop(guard);
            self.condvar.notify_all();
            self.waiters_changed.notify_all();
            false
        } else {
            guard.paused = true;
            guard.paused_since = Some(now);
            self.paused.store(true, Ordering::Release);
            true
        }
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    fn paused_thread_count(&self) -> usize {
        self.lock_state().paused_waiters
    }

    fn wake_all(&self) {
        // Lock and release state before notifying so a worker checking cancellation
        // under the same mutex cannot miss the notification.
        let guard = self.lock_state();
        drop(guard);
        self.condvar.notify_all();
        self.waiters_changed.notify_all();
    }

    fn snapshot_clock(&self) -> (Instant, Duration) {
        let guard = self.lock_state();
        let now = Instant::now();
        (now, guard.total_paused_at(now))
    }
}

#[derive(Debug, Clone)]
pub struct ScanCancelToken {
    cancelled: Arc<AtomicBool>,
    pause_waiters: Arc<Mutex<Vec<Weak<PauseInner>>>>,
}

impl Default for ScanCancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanCancelToken {
    #[must_use]
    pub fn new() -> Self {
        Self::from_atomic(Arc::new(AtomicBool::new(false)))
    }

    #[must_use]
    pub fn from_atomic(flag: Arc<AtomicBool>) -> Self {
        Self {
            cancelled: flag,
            pause_waiters: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify_pause_waiters();
    }

    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn as_atomic(&self) -> &AtomicBool {
        &self.cancelled
    }

    #[must_use]
    pub fn clone_atomic(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub(crate) fn register_pause_waiter(&self, pause: &Arc<PauseInner>) {
        let mut waiters = self
            .pause_waiters
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let candidate = Arc::downgrade(pause);
        let mut already_registered = false;
        waiters.retain(|existing| {
            if existing.strong_count() == 0 {
                return false;
            }
            if Weak::ptr_eq(existing, &candidate) {
                already_registered = true;
            }
            true
        });
        if !already_registered {
            waiters.push(candidate);
        }
    }

    fn notify_pause_waiters(&self) {
        let live_waiters: Vec<Arc<PauseInner>> = {
            let mut waiters = self
                .pause_waiters
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let mut live = Vec::with_capacity(waiters.len());
            waiters.retain(|weak| {
                if let Some(strong) = weak.upgrade() {
                    live.push(strong);
                    true
                } else {
                    false
                }
            });
            live
        };

        for pause in live_waiters {
            pause.wake_all();
        }
    }
}

impl From<Arc<AtomicBool>> for ScanCancelToken {
    fn from(flag: Arc<AtomicBool>) -> Self {
        Self::from_atomic(flag)
    }
}

impl AsRef<AtomicBool> for ScanCancelToken {
    fn as_ref(&self) -> &AtomicBool {
        self.as_atomic()
    }
}

#[derive(Debug, Clone)]
pub struct ScanControl {
    cancel_token: ScanCancelToken,
    pause: Arc<PauseInner>,
}

impl Default for ScanControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanControl {
    #[must_use]
    pub fn new() -> Self {
        Self::with_cancel_token(ScanCancelToken::new())
    }

    #[must_use]
    pub fn with_cancel_token(cancel_token: impl Into<ScanCancelToken>) -> Self {
        let cancel_token = cancel_token.into();
        let pause = Arc::new(PauseInner::new());
        cancel_token.register_pause_waiter(&pause);
        Self {
            cancel_token,
            pause,
        }
    }

    pub fn set_cancel_token(&mut self, cancel_token: impl Into<ScanCancelToken>) {
        let cancel_token = cancel_token.into();
        cancel_token.register_pause_waiter(&self.pause);
        self.cancel_token = cancel_token;
        if self.cancel_token.is_cancelled() {
            self.pause.wake_all();
        }
    }

    pub fn pause(&self) {
        self.pause.pause();
    }

    pub fn resume(&self) {
        self.pause.resume();
    }

    pub fn toggle_pause(&self) -> bool {
        self.pause.toggle_pause()
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.pause.is_paused()
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    pub fn reset_cancel(&self) {
        self.cancel_token.reset();
    }

    pub fn reset(&self) {
        self.cancel_token.reset();
        self.pause.resume();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    #[must_use]
    pub fn state(&self) -> ScanControlState {
        if self.is_cancelled() {
            ScanControlState::Cancelled
        } else if self.is_paused() {
            ScanControlState::Paused
        } else {
            ScanControlState::Running
        }
    }

    #[must_use]
    pub fn cancel_token(&self) -> ScanCancelToken {
        self.cancel_token.clone()
    }

    #[must_use]
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel_token.clone_atomic()
    }

    #[must_use]
    pub fn as_cancel_atomic(&self) -> &AtomicBool {
        self.cancel_token.as_atomic()
    }

    #[must_use]
    pub fn paused_thread_count(&self) -> usize {
        self.pause.paused_thread_count()
    }

    #[must_use]
    pub fn wait_for_paused_threads(&self, min_threads: usize, timeout: Duration) -> bool {
        if min_threads == 0 {
            return true;
        }

        let deadline = Instant::now() + timeout;
        let mut guard = self.pause.lock_state();

        while guard.paused && !self.is_cancelled() && guard.paused_waiters < min_threads {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let wait_slice = remaining.min(PAUSE_POLL_FALLBACK);
            let (next_guard, _) = self
                .pause
                .waiters_changed
                .wait_timeout(guard, wait_slice)
                .unwrap_or_else(PoisonError::into_inner);
            guard = next_guard;
        }

        guard.paused && !self.is_cancelled() && guard.paused_waiters >= min_threads
    }

    /// Checks whether the scan has been cancelled or paused, blocking while paused until resumed
    /// or cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::ScanCancelled`] if the scan is cancelled before or during a pause.
    #[inline]
    pub fn checkpoint(&self) -> Result<(), BulkHashError> {
        if self.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }
        if !self.is_paused() {
            return Ok(());
        }
        self.wait_while_paused()
    }

    #[cold]
    fn wait_while_paused(&self) -> Result<(), BulkHashError> {
        let mut guard = self.pause.lock_state();
        let mut counted = false;

        while guard.paused && !self.is_cancelled() {
            if !counted {
                guard.paused_waiters = guard.paused_waiters.saturating_add(1);
                counted = true;
                self.pause.waiters_changed.notify_all();
            }

            let (next_guard, _) = self
                .pause
                .condvar
                .wait_timeout(guard, PAUSE_POLL_FALLBACK)
                .unwrap_or_else(PoisonError::into_inner);
            guard = next_guard;
        }

        if counted {
            guard.paused_waiters = guard.paused_waiters.saturating_sub(1);
            self.pause.waiters_changed.notify_all();
        }

        drop(guard);

        if self.is_cancelled() {
            Err(BulkHashError::ScanCancelled)
        } else {
            Ok(())
        }
    }

    pub(crate) fn start_timer(&self) -> ScanTimer {
        ScanTimer::start(self)
    }
}

impl From<ScanCancelToken> for ScanControl {
    fn from(cancel_token: ScanCancelToken) -> Self {
        Self::with_cancel_token(cancel_token)
    }
}

impl From<Arc<AtomicBool>> for ScanControl {
    fn from(flag: Arc<AtomicBool>) -> Self {
        Self::with_cancel_token(flag)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanTimer {
    started_at: Instant,
    paused_at_start: Duration,
}

impl ScanTimer {
    pub(crate) fn start(control: &ScanControl) -> Self {
        let (started_at, paused_at_start) = control.pause.snapshot_clock();
        Self {
            started_at,
            paused_at_start,
        }
    }

    pub(crate) fn finish(self, control: &ScanControl) -> (Duration, Duration) {
        let (ended_at, paused_at_end) = control.pause.snapshot_clock();
        let wall_elapsed = ended_at.saturating_duration_since(self.started_at);
        let paused_elapsed = paused_at_end.saturating_sub(self.paused_at_start);
        let active_elapsed = wall_elapsed.saturating_sub(paused_elapsed);
        (active_elapsed, paused_elapsed)
    }
}
