#pragma once

#include <nanobind/nanobind.h>
#include <string>

#include <nanobind/stl/string.h>

#include "typing.hpp"
#include "pyutils.hpp"

NAMESPACE_BEGIN(NB_NAMESPACE)

struct PathLike : public nanobind::object {
  LIEF_PY_DEFAULT_CTOR(PathLike, nanobind::object);

  NB_OBJECT_DEFAULT(PathLike, object, "Union[str | os.PathLike]", check)

  std::string to_string() const {
      if (nb::isinstance<nb::str>(*this)) {
        return nb::cast<std::string>(*this);
      }
      auto path_str = LIEF::py::path_to_str(*this);
      assert(path_str);
      return *path_str;
  }

  operator std::string() const { return to_string(); }

  static bool check(handle h) {
    return nb::isinstance<nb::str>(h) ||
      LIEF::py::path_to_str(nb::object(h, nb::detail::borrow_t{}));
  }
};

NAMESPACE_END(NB_NAMESPACE)
