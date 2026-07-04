use lief::logging;
use std::env;

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

    logging::set_level(logging::Level::WARN);
    assert_eq!(logging::get_level(), logging::Level::WARN);

    logging::set_level(logging::Level::DEBUG);
    assert_eq!(logging::get_level(), logging::Level::DEBUG);

    // Test Scoped
    logging::set_level(logging::Level::INFO);
    assert_eq!(logging::get_level(), logging::Level::INFO);

    {
        let mut scoped = logging::Scoped::new(logging::Level::DEBUG);
        assert_eq!(logging::get_level(), logging::Level::DEBUG);

        scoped.set_level(logging::Level::TRACE);
        assert_eq!(logging::get_level(), logging::Level::TRACE);

        scoped.reset();
        assert_eq!(logging::get_level(), logging::Level::INFO);

        // Set again so the drop restores INFO
        scoped.set_level(logging::Level::ERR);
    }

    // After drop, original level (INFO) is restored
    assert_eq!(logging::get_level(), logging::Level::INFO);

    logging::reset();
}
