#ifndef PY_LIEF_UTILS_H
#define PY_LIEF_UTILS_H
#include <nanobind/nanobind.h>

namespace nb = nanobind;

namespace LIEF::py {
inline bool isinstance(nb::handle obj, nb::handle type) {
    const auto result = PyObject_IsInstance(obj.ptr(), type.ptr());
    if (result == -1) {
      nb::detail::raise_python_error();
    }
    return result != 0;
}
}

#endif
