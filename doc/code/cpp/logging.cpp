#include <LIEF/logging.hpp>

void example() {
  // lief-doc: example-start
  // Set global level to Err
  LIEF::logging::set_level(LIEF::logging::Level::Err);

  {
    // Temporarily set global level to Debug (RAII)
    LIEF::logging::Scoped _(LIEF::logging::Level::Debug);
    LIEF::logging::log(LIEF::logging::Level::Debug, "This is a debug message");
  }
  // lief-doc: example-end
}
