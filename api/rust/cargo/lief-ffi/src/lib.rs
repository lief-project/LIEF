include!(concat!(env!("AUTOCXX_RS"), "/", "autocxx-autocxx_ffi-gen.rs"));

pub use autocxx_ffi::*;

#[allow(non_camel_case_types)]
pub struct AssemblerConfig_r {
    #[allow(dead_code)]
    resolve_symbol_impl: Box<dyn Fn(&str) -> Option<u64> + Send + Sync + 'static>,
}

impl AssemblerConfig_r {
    #[allow(non_snake_case)]
    pub fn new(F: impl Fn(&str) -> Option<u64> + Send + Sync + 'static) -> Box<Self> {
        Box::new(Self {
            resolve_symbol_impl: Box::new(F)
        })
    }
}

impl AssemblerConfig_r {
    fn resolve_symbol(&self, name: &str) -> i64 {
        if let Some(addr) =  (self.resolve_symbol_impl)(name) {
            return addr as i64;
        }
        -1
    }
}
