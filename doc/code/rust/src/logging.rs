pub fn example() {
    // lief-doc: example-start
    // Set global level to Err
    lief::logging::set_level(lief::logging::Level::Err);

    {
        // Temporarily set global level to Debug (RAII)
        let _scoped = lief::logging::Scoped::new(lief::logging::Level::Debug);
        lief::logging::log(lief::logging::Level::Debug, "This is a debug message");
    }
    // lief-doc: example-end
}
