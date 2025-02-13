//! TODO: Figure out a way to squelch the warning on using link_section.

use linkme::distributed_slice;

/// Linker magic to collect all hash constructors.
#[distributed_slice]
pub static HASHES: [fn() -> Box<dyn crate::SmolHasher>];

/// Helper macro to register a constructing expression.
#[macro_export]
macro_rules! register_hash {
    // We need a unique identifier. We use the gensym crate for this.
    ($ctor:expr) => {
        ::gensym::gensym! { $crate::register_hash!{$ctor} }
    };
    ($gensym:ident, $ctor:expr) => {
        #[::linkme::distributed_slice($crate::HASHES)]
        fn $gensym() -> Box<dyn $crate::SmolHasher> {
            Box::new($ctor)
        }
    };
}
