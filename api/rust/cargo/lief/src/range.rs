use lief_ffi as ffi;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Range {
    pub low: u64,
    pub high: u64,
}

impl Range {
    pub fn from_ffi(raw: &ffi::Range) -> Self {
        Self {
            low: raw.low,
            high: raw.high,
        }
    }
}
