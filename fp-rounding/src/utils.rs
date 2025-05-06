use std::marker::PhantomData;

/// A trait only visible in this crate. This is to prevent users from
/// implementing a trait when used as a super trait.
pub(crate) trait Sealed {}

/// Marker type that is not Send or Sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct NotSendSync(PhantomData<*const ()>);
