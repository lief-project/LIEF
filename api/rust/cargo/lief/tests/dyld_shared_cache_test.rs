mod utils;
use std::env;
use std::path::PathBuf;
use std::str::FromStr;

fn has_dyld_shared_cache_samples() -> bool {
    let dsc_dir = utils::get_sample_path().join("dyld_shared_cache");
    if dsc_dir.is_dir() {
        return true;
    }
    if let Some(dir) = env::var_os("LIEF_DSC_SAMPLES_DIR") {
        return PathBuf::from_str(&dir.into_string().unwrap_or("".to_string())).unwrap().is_dir();
    }
    return false;
}

fn get_dsc_sample(suffix: &str) -> PathBuf {
    let dir = utils::get_sample_path().join("dyld_shared_cache");
    if dir.is_dir() {
        return dir.join(suffix);
    }
    let env_dir = env::var_os("LIEF_DSC_SAMPLES_DIR")
        .unwrap()
        .into_string()
        .unwrap();
    PathBuf::from_str(&env_dir).unwrap().join(suffix)
}

fn explore_dylib(cache: &lief::dsc::DyldSharedCache, dylib: &lief::dsc::Dylib) {
    println!("{:?}", dylib);
}

fn explore_mapping_info(cache: &lief::dsc::DyldSharedCache, info: &lief::dsc::MappingInfo) {
    println!("{:?}", info);
}

fn explore_subcache(cache: &lief::dsc::DyldSharedCache, sc: &lief::dsc::SubCache) {
    println!("{:?}", sc);
}

fn run_ios_181(cache: &lief::dsc::DyldSharedCache) {
    println!("{}", cache.filename());
    println!("{}", cache.filepath());
    println!("{}", cache.load_address());
    println!("{:?}", cache.version());
    println!("{}", cache.arch_name());
    println!("{:?}", cache.platform());
    println!("{:?}", cache.arch());

    assert!(cache.find_lib_from_va(0x20d0a4010).is_some());
    assert!(cache.find_lib_from_va(0).is_none());

    assert!(cache.find_lib_from_path("/usr/lib/libobjc.A.dylib").is_some());
    assert!(cache.find_lib_from_path("/usr/lib/libobjc.X.dylib").is_none());

    assert!(cache.find_lib_from_name("liblockdown.dylib").is_some());
    assert!(cache.find_lib_from_path("liblockdown.A.dylib").is_none());

    assert!(cache.has_subcaches());

    for dylib in cache.libraries() {
        explore_dylib(cache, &dylib);
    }

    for sc in cache.subcaches() {
        explore_subcache(cache, &sc);
        for info in sc.cache().expect("Missing cache").mapping_info() {
            explore_mapping_info(cache, &info);
        }
    }

}

#[test]
fn test_api() {
    if !lief::is_extended() || !has_dyld_shared_cache_samples() {
        return;
    }
    let cache = lief::dsc::load_from_path(get_dsc_sample("ios-18.1/").to_str().unwrap(), /*arch*/"");
    assert!(cache.is_some());
    run_ios_181(&cache.unwrap());
}

