#![allow(warnings)]
use lief::logging;
use std::env;

#[test]
fn test_api() {
    logging::disable();
    logging::enable();
    logging::set_level(logging::Level::Debug);

    let mut dir = env::temp_dir();
    dir.push("lief_test.log");
    logging::set_path(dir.as_path());
    logging::log(logging::Level::Info, "hi!");
    logging::reset();
    lief::log_dbg!("dbg: {:?}", dir);
    lief::log_info!("info: {:?}", dir);
    lief::log_warn!("warn: {:?}", dir);
    lief::log_err!("err: {dir:?}");

    logging::set_level(logging::Level::Warn);
    assert_eq!(logging::get_level(), logging::Level::Warn);

    logging::set_level(logging::Level::Debug);
    assert_eq!(logging::get_level(), logging::Level::Debug);

    // Test Scoped
    logging::set_level(logging::Level::Info);
    assert_eq!(logging::get_level(), logging::Level::Info);

    {
        let mut scoped = logging::Scoped::new(logging::Level::Debug);
        assert_eq!(logging::get_level(), logging::Level::Debug);

        scoped.set_level(logging::Level::Trace);
        assert_eq!(logging::get_level(), logging::Level::Trace);

        scoped.reset();
        assert_eq!(logging::get_level(), logging::Level::Info);

        // Set again so the drop restores INFO
        scoped.set_level(logging::Level::Err);
    }

    // After drop, original level (INFO) is restored
    assert_eq!(logging::get_level(), logging::Level::Info);

    logging::reset();
}
