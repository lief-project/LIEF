#if defined __cplusplus
  #include <nanobind/nanobind.h>
  #include <nanobind/stl/string.h>
  #include <nanobind/stl/unique_ptr.h>
  #include <nanobind/make_iterator.h>

  #include <string>
  #include <sstream>
  #include <ostream>
  #include <memory>
  #include <vector>
  #include <algorithm>
  #include <cstdint>
#else
  #include <stdint.h>
  #include <stddef.h>
#endif
