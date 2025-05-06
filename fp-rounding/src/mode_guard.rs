use {
    crate::{
        arch::{read_rounding_mode, write_rounding_mode},
        rounding_mode::RoundingModeMarker,
        utils::NotSendSync,
        RoundingMode,
    },
    core::{
        marker::PhantomData,
        sync::atomic::{fence, Ordering},
    },
};

/// Helper to ensure the rounding mode is reset to the previous mode when the
/// guard is dropped and simulataneously provides some guarantee that the
/// current mode is set to the specified mode.
pub struct ModeGuard<M: RoundingModeMarker> {
    previous: RoundingMode,
    mode:     PhantomData<M>,
    _marker:  NotSendSync,
}

impl<M: RoundingModeMarker> ModeGuard<M> {
    /// Create a new mode guard.
    pub(crate) unsafe fn new() -> Self {
        let previous = unsafe { read_rounding_mode() };
        fence(Ordering::SeqCst);
        unsafe { write_rounding_mode(M::MODE) };
        fence(Ordering::SeqCst);
        Self {
            previous,
            mode: PhantomData,
            _marker: NotSendSync::default(),
        }
    }
}

/// Implement the Drop trait for `ModeGuard` to make sure the rounding mode is
/// always reset.
impl<M: RoundingModeMarker> Drop for ModeGuard<M> {
    fn drop(&mut self) {
        fence(Ordering::SeqCst);
        unsafe { write_rounding_mode(self.previous) };
        fence(Ordering::SeqCst);
    }
}
