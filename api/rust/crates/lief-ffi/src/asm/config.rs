#[cxx::bridge]
pub mod ffi {
    extern "Rust" {
        #[derive(ExternType)]
        pub type AssemblerConfig_r;
        fn resolve_symbol(&self, name: &str) -> i64;
    }
}

#[allow(non_camel_case_types)]
pub struct AssemblerConfig_r {
    resolver: Box<dyn Fn(&str) -> Option<u64> + Send + Sync + 'static>,
}

impl AssemblerConfig_r {
    pub fn new<F>(resolver: F) -> Box<Self>
    where
        F: Fn(&str) -> Option<u64> + Send + Sync + 'static,
    {
        Box::new(Self {
            resolver: Box::new(resolver),
        })
    }

    fn resolve_symbol(&self, name: &str) -> i64 {
        match (self.resolver)(name) {
            Some(value) => value as i64,
            None => -1,
        }
    }
}
