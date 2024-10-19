use lief_ffi as ffi;

/// This structure wraps options to tweak the generated output of
/// functions like [`crate::objc::Metadata::to_decl_with_opt`]
pub struct DeclOpt {
    /// Whether annotations like method's address should be printed
    pub show_annotations: bool,
}

impl Default for DeclOpt {
    fn default() -> DeclOpt {
        DeclOpt {
            show_annotations: true,
        }
    }
}

impl DeclOpt {
    #[doc(hidden)]
    pub fn to_ffi(&self) -> ffi::ObjC_DeclOpt {
        ffi::ObjC_DeclOpt {
            show_annotations: self.show_annotations
        }
    }
}
