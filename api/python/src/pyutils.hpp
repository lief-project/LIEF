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
  std::string type = pytype.c_str();
  size_t pos_1 = type.find('.');
  size_t pos_2 = type.find('.', pos_1 + 1);
  if (pos_1 == std::string::npos || pos_2 == std::string::npos) {
    return type;
  }
  return "lief." + type.substr(pos_2 + 1);
}

result<std::string> path_to_str(nb::object pathlike);

}

#endif
