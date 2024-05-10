use std::env;
use semver::Version;
use std::path::{PathBuf, Path};
use miette::IntoDiagnostic;
use git_version::git_version;

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--long", "--dirty"],
    prefix = "git:",
    cargo_prefix = "cargo:",
    fallback="latest"
);

const GH_URL: &str = "https://github.com/lief-project/LIEF/releases/download";
const DEFAULT_S3_URL: &str = "https://lief-rs.s3.fr-par.scw.cloud";

const SUPPORTED_TARGETS: &[&str; 6] = &[
    "aarch64-apple-ios",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
];

fn get_s3_url() ->  String {
    env::var("LIEF_RUST_S3_PREFIX").unwrap_or(DEFAULT_S3_URL.to_string())
}

fn get_target() -> String {
    let current_target = env::var("TARGET").unwrap();
    let supported = SUPPORTED_TARGETS
        .iter()
        .find(|&supported| *supported == current_target);
    if supported.is_none() {
        panic!("Target: {} is not currently supported.", current_target);
    }
    current_target.to_string()
}

fn get_filename(target: &String) -> String {
    if let Some(crt) = get_crt_prefix() {
        return format!("LIEF-rs-{}-{}.zip", crt, target);
    }
    format!("LIEF-rs-{}.zip", target)
}

fn get_urls_from_cargo(target: &String, version: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let s3_prefix = get_s3_url();
    let github_url = format!("{GH_URL}/{version}/{}", get_filename(target));
    let s3_url = format!("{s3_prefix}/precompiled/{version}/{}", get_filename(target));
    let s3_latest_url = format!("{s3_prefix}/precompiled/latest/{}", get_filename(target));
    urls.push(github_url);
    urls.push(s3_url);
    urls.push(s3_latest_url); // Fallback if it's not yet a release
    urls
}

fn get_urls_from_git(target: &String, version: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let parts: Vec<&str> = version.split('-').collect();
    let cargo_version = env::var("CARGO_PKG_VERSION").unwrap();

    if parts.is_empty() { // Fallback on cargo version
        eprintln!("Invalid Git-based version. Falling back to Cargo-based version");
        return get_urls_from_cargo(target, cargo_version.as_str());
    }

    let git_ver = parts[0];
    let sem_version = Version::parse(git_ver);
    if sem_version.is_err() {
        eprintln!("Invalid Git-based version. Falling back to Cargo-based version");
        return get_urls_from_cargo(target, cargo_version.as_str());
    }

    if parts.len() == 1 { // Tagged version
        println!("Using tagged version: {git_ver}");
        let s3_prefix = get_s3_url();
        let github_url = format!("{GH_URL}/{git_ver}/{}", get_filename(target));
        let s3_url = format!("{s3_prefix}/precompiled/{git_ver}/{}", get_filename(target));
        urls.push(github_url);
        urls.push(s3_url);
        return urls;
    }

    get_nightly_url(target)
}

fn get_nightly_url(target: &String) -> Vec<String> {
    println!("Using nightly url");
    let mut urls = Vec::new();
    let s3_prefix = get_s3_url();
    let s3_url = format!("{s3_prefix}/precompiled/latest/{}", get_filename(target));
    urls.push(s3_url);
    urls
}


fn get_cache_urls() -> Vec<String> {
    let version = String::from(GIT_VERSION);
    let target = get_target();
    if version.starts_with("cargo:") {
        let tag = version.strip_prefix("cargo:").expect("Can't strip 'cargo:' prefix");
        return get_urls_from_cargo(&target, tag);
    }
    if version.starts_with("git:") {
        let git_ver = version.strip_prefix("git:")
                                .expect("Can't strip 'git:' prefix")
                                .to_string();
        return get_urls_from_git(&target, &git_ver);
    }
    get_nightly_url(&target)
}

fn emit_cargo_directives(root: &Path) -> miette::Result<()> {
    println!("cargo:rustc-link-search=native={}/lib", root.display());
    println!("cargo:rustc-env=AUTOCXX_RS={}/rs", root.display());

    println!("cargo:rustc-link-lib=lief-sys");
    println!("cargo:rustc-link-lib=LIEF");
    Ok(())
}

fn download(dst_archive: &PathBuf) -> bool {
    let urls = get_cache_urls();
    if urls.is_empty() {
        panic!("Can't determine precompiled URL for this build.\n
                Please consider opening a GitHub issue.");
    }
    for url in urls.iter() {
        println!("Trying to download from {}", url);
        let mut resp =
            reqwest::blocking::get(url).expect("failed to download LIEF cache");
        if resp.status().is_client_error() || resp.status().is_server_error() {
            eprintln!("Can't download precompiled LIEF ffi bindings from: {}", url);
            continue;
        }
        let mut out = std::fs::File::create(dst_archive).expect("failed to create zip cache file");
        std::io::copy(&mut resp, &mut out).expect("failed to copy cache content");
        return true;
    }
    false
}

fn get_crt_prefix() -> Option<String> {
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Can't access 'CARGO_CFG_TARGET_OS");
    if os.to_lowercase() != "windows" {
        return None;
    }

    let use_static_crt = {
        let target_features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
        target_features.split(',').any(|f| f == "crt-static")
    };

    if use_static_crt {
        return Some("MT".to_string());
    }

    Some("MD".to_string())
}

fn build_from_precompiled() -> miette::Result<()> {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target = env::var("TARGET").unwrap();

    println!("Target:    {}", target);
    println!("Arch:      {}", target_arch);
    println!("OS:        {}", target_os);
    println!("Version:   {}", GIT_VERSION);

    if let Ok(var) = env::var("LIEF_RUST_PRECOMPILED") {
        let root = PathBuf::from(var);
        return emit_cargo_directives(&root);
    }
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let dst_dir = out_dir.join("lief-rs");
    let dst_archive = dst_dir.join("cache.zip");
    if !dst_dir.exists() {
        std::fs::create_dir_all(&dst_dir).into_diagnostic()?;
    }
    println!("Cache dst: {}", &dst_dir.display().to_string());

    if !dst_archive.exists() && !download(&dst_archive) {
        panic!("Can't download precompiled ffi package");
    }

    let cache_file = std::fs::File::open(dst_archive).into_diagnostic()?;
    let mut zip = zip::ZipArchive::new(&cache_file).into_diagnostic()?;
    zip.extract(&dst_dir).into_diagnostic()?;
    emit_cargo_directives(&dst_dir)
}

pub fn build() -> miette::Result<()> {
    build_from_precompiled()?;
    Ok(())
}
