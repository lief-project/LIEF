#ifndef PY_LIEF_UTILS_H
#define PY_LIEF_UTILS_H
#include <nanobind/nanobind.h>

#include <LIEF/errors.hpp>

#include <string>

namespace nb = nanobind;

namespace LIEF::py {

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

/// Call policy for a function returning a sequence of objects that reference
/// the argument at position I (e.g. 1 for `self`): each item keeps this
/// argument alive.
/// We need this in LIEF for objects that with a `pimpl` implementation returned by
/// value:
///
/// ```
/// std::vector<Member> ClassLike::members() const
/// ```
///
/// In this case, the `Member` lifetime depends on `ClassLike` even though it's
/// returned by Value. On the C++ side, such a lifetime policy is annotated with
/// `LIEF_LIFETIMEBOUND`
template<size_t I>
struct returns_references_to {
  static void precall(PyObject**, size_t, nb::detail::cleanup_list*) {}

  template<size_t N>
  static void postcall(PyObject** args, std::integral_constant<size_t, N>,
                       nb::handle ret) {
    static_assert(I > 0 && I <= N,
                  "I must be in the range [1, number of C++ arguments]");
    if (!ret.is_valid()) {
      return;
    }
    for (nb::handle item : ret) {
      NB_CALL(keep_alive_py)(NB_CTX, item.ptr(), args[I - 1]);
    }
  }
};

}

#endif
