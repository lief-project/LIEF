#include "LIEF/PDB/types/Method.hpp"
#include "PDB/pyPDB.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Method>(nb::module_& m) {
  using Method = pdb::types::Method;

  nb::class_<pdb::types::Method> method(m, "Method",
    R"doc(
    This class represents a Method (``LF_ONEMETHOD``) that can be defined in
    ClassLike PDB type
    )doc"_doc
  );

  nb::enum_<Method::TYPE>(method, "TYPE")
    .value("VANILLA", Method::TYPE::VANILLA, "Regular instance method")
    .value("VIRTUAL", Method::TYPE::VIRTUAL, "Virtual method")
    .value("STATIC", Method::TYPE::STATIC, "Static method")
    .value("FRIEND", Method::TYPE::FRIEND, "Friend method")
    .value("INTRODUCING_VIRTUAL", Method::TYPE::INTRODUCING_VIRTUAL,
           "Virtual method that introduces a new vtable slot")
    .value("PURE_VIRTUAL", Method::TYPE::PURE_VIRTUAL, "Pure virtual method (abstract)")
    .value("PURE_INTRODUCING_VIRTUAL", Method::TYPE::PURE_INTRODUCING_VIRTUAL,
           "Pure virtual method that introduces a new vtable slot");

  nb::enum_<Method::ACCESS>(method, "ACCESS")
    .value("NONE", Method::ACCESS::NONE, "No access specifier (or unknown)")
    .value("PRIVATE", Method::ACCESS::PRIVATE, "Private access")
    .value("PROTECTED", Method::ACCESS::PROTECTED, "Protected access")
    .value("PUBLIC", Method::ACCESS::PUBLIC, "Public access");

  method
    .def_prop_ro("name", &Method::name,
                 "Name of the method"_doc)

    .def_prop_ro("type", &Method::type,
                  "Type/Properties of the method (virtual, static, etc.)"_doc)

    .def_prop_ro("access", &Method::access,
                 "Visibility access (public, private, ...)"_doc)
  ;
}

}
