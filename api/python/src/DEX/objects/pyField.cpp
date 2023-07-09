#include "LIEF/DEX/Field.hpp"
#include "LIEF/DEX/Class.hpp"
#include "LIEF/DEX/Type.hpp"

#include "DEX/pyDEX.hpp"

#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::DEX::py {

template<>
void create<Field>(nb::module_& m) {

  nb::class_<Field, LIEF::Object>(m, "Field", "DEX Field representation"_doc)
    .def_prop_ro("name",
        &Field::name,
        "Field's name"_doc)

    .def_prop_ro("index", &Field::index,
        "Original DEX file index of the field"_doc)

    .def_prop_ro("has_class", &Field::has_class,
        "True if a class is associated with this field"_doc)

    .def_prop_ro("cls", nb::overload_cast<>(&Field::cls),
        "" RST_CLASS_REF(lief.DEX.Class) " associated with this field"_doc)

    .def_prop_ro("is_static", &Field::is_static,
        "True if the field is static"_doc)

    .def_prop_ro("type", nb::overload_cast<>(&Field::type),
        "" RST_CLASS_REF(lief.DEX.Type) " of this field"_doc,
        nb::rv_policy::reference_internal)

    .def_prop_ro("access_flags",
        nb::overload_cast<>(&Field::access_flags, nb::const_),
        "List of " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) ""_doc)

    .def("has",
        nb::overload_cast<ACCESS_FLAGS>(&Field::has, nb::const_),
        "Check if the given " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) " is present"_doc,
        "flag"_a)

    LIEF_DEFAULT_STR(Field);
}
}
