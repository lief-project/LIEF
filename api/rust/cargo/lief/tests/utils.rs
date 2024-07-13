use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub fn get_sample_dir() -> Option<String> {
    match env::var_os("LIEF_SAMPLES_DIR") {
        Some(val) => Some(val.into_string().unwrap_or("".to_string())),
        None => {
            panic!("Can't find 'LIEF_SAMPLES_DIR'");
        }
    }
}

pub fn get_sample(path: &Path) -> Option<PathBuf> {
    let sample_dir = get_sample_dir()?;
    let sample_dir_path = PathBuf::from_str(sample_dir.as_str()).ok()?;
    Some(sample_dir_path.join(path))
}

#[allow(dead_code)]
pub fn get_elf_sample(name: &str) -> Option<PathBuf> {
    let suffix = Path::new("ELF").join(name);
    get_sample(suffix.as_path())
}

#[allow(dead_code)]
pub fn get_pe_sample(name: &str) -> Option<PathBuf> {
    let suffix = Path::new("PE").join(name);
    get_sample(suffix.as_path())
}

#[allow(dead_code)]
pub fn get_macho_sample(name: &str) -> Option<PathBuf> {
    let suffix = Path::new("MachO").join(name);
    get_sample(suffix.as_path())
}

#[allow(dead_code)]
pub fn get_pkcs7_sample(name: &str) -> Option<PathBuf> {
    let suffix = Path::new("pkcs7").join(name);
    get_sample(suffix.as_path())
}

#[allow(dead_code)]
pub fn get_pdb_sample(name: &str) -> Option<PathBuf> {
    let suffix = Path::new("PDB").join(name);
    get_sample(suffix.as_path())
}
