#ifndef PY_LIEF_UTILS_H
#define PY_LIEF_UTILS_H
#include <nanobind/nanobind.h>

#include <LIEF/errors.hpp>

#include <string>

namespace nb = nanobind;

namespace LIEF::py {
inline bool isinstance(nb::handle obj, nb::handle type) {
    const auto result = PyObject_IsInstance(obj.ptr(), type.ptr());
    if (result == -1) {
      nb::detail::raise_python_error();
    }
    return result != 0;
}

inline std::string type2str(nb::object obj) {
  auto pytype = nb::steal<nb::str>(nb::detail::nb_inst_name(obj.ptr()));
  return pytype.c_str();
}

result<std::string> path_to_str(nb::object pathlike);

}

#endif
