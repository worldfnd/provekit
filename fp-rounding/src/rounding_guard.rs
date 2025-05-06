use {
    crate::{
        arch::{read_rounding_mode, write_rounding_mode},
        utils::NotSendSync,
        RoundingDirection, RoundingDirectionMarker,
    },
    core::marker::PhantomData,
};

/// Guard to mark that the floating-point rounding mode has been set.
///
/// This struct must to be passed as a (unused) reference to any function that
/// requires the non-default rounding mode for correct operation. The struct
/// serves as a proof that the alternative rounding mode is set.
///
/// # Safety
///
/// This type is marked !Send + !Sync because FPCR is a per-core / per OS-thread
/// register.
// TODO: Force one per thread.
pub struct RoundingGuard<M: RoundingDirectionMarker> {
    previous: RoundingDirection,
    mode:     PhantomData<M>,
    _marker:  NotSendSync,
}

impl<M: RoundingDirectionMarker> RoundingGuard<M> {
    /// Create a new mode guard.
    pub(crate) unsafe fn new() -> Self {
        let previous = unsafe { read_rounding_mode() };
        unsafe { write_rounding_mode(M::MODE) };
        Self {
            previous,
            mode: PhantomData,
            _marker: NotSendSync::default(),
        }
    }
}

/// Implement the Drop trait for `RoundingGuard` to make sure the rounding mode
/// is always reset.
impl<M: RoundingDirectionMarker> Drop for RoundingGuard<M> {
    fn drop(&mut self) {
        unsafe { write_rounding_mode(self.previous) };
    }
}
