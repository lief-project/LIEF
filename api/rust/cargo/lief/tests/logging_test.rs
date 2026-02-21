use std::env;
use lief::logging;

#[test]
fn test_api() {
    logging::disable();
    logging::enable();
    logging::set_level(logging::Level::DEBUG);

    let mut dir = env::temp_dir();
    dir.push("lief_test.log");
    logging::set_path(dir.as_path());
    logging::log(logging::Level::INFO, "hi!");
    logging::reset();
    lief::log_dbg!("dbg: {:?}", dir);
    lief::log_info!("info: {:?}", dir);
    lief::log_warn!("warn: {:?}", dir);
    lief::log_err!("err: {dir:?}");
}
