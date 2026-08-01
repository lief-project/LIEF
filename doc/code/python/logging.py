import lief


def example() -> None:
    # lief-doc: example-start
    # Set global level to Err
    lief.logging.set_level(lief.logging.Level.Err)

    # Temporarily set global level to Debug
    with lief.logging.level_scope(lief.logging.Level.Debug):
        lief.logging.log(lief.logging.Level.Debug, "This is a debug message")
    # lief-doc: example-end
