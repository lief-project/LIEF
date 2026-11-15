use std::fmt;

use crate::enum_from_int;

enum_from_int! {
    #[derive(PartialOrd, Ord)]
    Error: u32 {
        ReadError = 0x00000001,
        NotFound = 0x00000002,
        NotImplemented = 0x00000003,
        NotSupported = 0x00000004,
        Corrupted = 0x00000005,
        ConversionError = 0x00000006,
        ReadOutOfBound = 0x00000007,
        ASN1BadTag = 0x00000008,
        FileError = 0x00000009,
        FileFormatError = 0x0000000a,
        ParsingError = 0x0000000b,
        BuildError = 0x0000000c,
        DataTooLarge = 0x0000000d,
        RequireExtendedVersion = 0x0000000e,
        Inconsistent = 0x0000000f,
        RuntimeError = 0x00000010,
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LIEF Error Occurred!")
    }
}
