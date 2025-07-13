use lief_ffi as ffi;
use std::sync::Arc;

#[derive(Clone)]
/// This structure exposes the different elements that can be configured to assemble
/// code.
pub struct AssemblerConfig {
    /// Default configuration
    pub dialect: Dialect,

    /// This attribute aims to store a function for resolving symbols in the assembly listing.
    ///
    /// For instance, given this assembly code:
    ///
    /// ```text
    /// 0x1000: mov rdi, rbx
    /// 0x1003: call _my_function
    /// ```
    ///
    /// The function `_my_function` will remain undefined unless we return its address
    /// in a callback defined in this attribute [`AssemblerConfig::symbol_resolver`]:
    ///
    /// ```rust
    /// let mut config = AssemblerConfig::default();
    ///
    /// let resolver = Arc::new(move |symbol: &str| {
    ///     return Some(0x4000);
    /// });
    ///
    /// config.symbol_resolver = Some(resolver);
    /// ```
    pub symbol_resolver: Option<Arc<dyn Fn(&str) -> Option<u64> + Send + Sync + 'static>>
}

impl Default for AssemblerConfig {
    fn default() -> AssemblerConfig {
        AssemblerConfig {
            dialect: Dialect::DEFAULT_DIALECT,
            symbol_resolver: None,
        }
    }
}

impl AssemblerConfig {
    #[doc(hidden)]
    pub fn into_ffi(&self) -> Box<ffi::AssemblerConfig_r> {
        if let Some(ref resolver) = self.symbol_resolver {
            let closure = resolver.clone();
            ffi::AssemblerConfig_r::new(move |s| closure(s))
        } else {
            ffi::AssemblerConfig_r::new(|_| None)
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// The different supported dialects
pub enum Dialect {
    DEFAULT_DIALECT,

    /// Intel syntax
    X86_INTEL,

    /// Intel syntax
    X86_ATT,
    UNKNOWN(u32),
}

impl From<u32> for Dialect {
    fn from(value: u32) -> Self {
        match value {
            0x00000000 => Dialect::DEFAULT_DIALECT,
            0x00000001 => Dialect::X86_INTEL,
            0x00000002 => Dialect::X86_ATT,
            _ => Dialect::UNKNOWN(value),

        }
    }
}

impl From<Dialect> for u32 {
    fn from(value: Dialect) -> u32 {
        match value {
            Dialect::DEFAULT_DIALECT => 0x00000000,
            Dialect::X86_INTEL => 0x00000001,
            Dialect::X86_ATT => 0x00000002,
            Dialect::UNKNOWN(value) => value,

        }
    }
}
