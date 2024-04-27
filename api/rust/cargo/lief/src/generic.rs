use crate::to_slice;
use lief_ffi as ffi;

pub trait Symbol {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractSymbol;

    fn name(&self) -> String {
        self.as_generic().name().to_string()
    }
    fn value(&self) -> u64 {
        self.as_generic().value()
    }
    fn size(&self) -> u64 {
        self.as_generic().size()
    }
}

impl std::fmt::Debug for &dyn Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Symbol")
            .field("name", &self.name())
            .field("value", &self.value())
            .field("size", &self.size())
            .finish()
    }
}

pub trait Section {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractSection;

    fn name(&self) -> String {
        self.as_generic().name().to_string()
    }
    fn size(&self) -> u64 {
        self.as_generic().size()
    }
    fn offset(&self) -> u64 {
        self.as_generic().offset()
    }
    fn virtual_address(&self) -> u64 {
        self.as_generic().virtual_address()
    }
    fn content(&self) -> &[u8] {
        to_slice!(self.as_generic().content());
    }
}

impl std::fmt::Debug for &dyn Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name())
            .field("size", &self.size())
            .field("offset", &self.offset())
            .field("virtual_address", &self.virtual_address())
            .finish()
    }
}

pub trait Relocation {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractRelocation;

    fn address(&self) -> u64 {
        self.as_generic().address()
    }
    fn size(&self) -> u64 {
        self.as_generic().size()
    }
}

impl std::fmt::Debug for &dyn Relocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relocation")
            .field("address", &self.address())
            .field("size", &self.size())
            .finish()
    }
}

pub trait Binary {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::AbstractBinary;

    fn entrypoint(&self) -> u64 {
        self.as_generic().entrypoint()
    }
    fn imagebase(&self) -> u64 {
        self.as_generic().imagebase()
    }
    fn is_pie(&self) -> bool {
        self.as_generic().is_pie()
    }
}
