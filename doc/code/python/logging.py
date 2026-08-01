import lief


def example() -> None:
    # lief-doc: example-start
    # Set global level to ERROR
    lief.logging.set_level(lief.logging.LEVEL.ERROR)

    # Temporarily set global level to DEBUG
    with lief.logging.level_scope(lief.logging.LEVEL.DEBUG):
        lief.logging.log(lief.logging.LEVEL.DEBUG, "This is a debug message")
    # lief-doc: example-end
