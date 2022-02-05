#include "LIEF/DEX/Field.hpp"
#include "LIEF/DEX/hash.hpp"

#include "pyDEX.hpp"

namespace LIEF {
namespace DEX {

template<class T>
using getter_t = T (Field::*)(void) const;

template<class T>
using no_const_getter_t = T (Field::*)(void);

template<class T>
using setter_t = void (Field::*)(T);


template<>
void create<Field>(py::module& m) {

  py::class_<Field, LIEF::Object>(m, "Field", "DEX Field representation")
    .def_property_readonly("name",
        &Field::name,
        "Field's name")

    .def_property_readonly("index",
        &Field::index,
        "Original DEX file index of the field")

    .def_property_readonly("has_class",
        &Field::has_class,
        "True if a class is associated with this field")

    .def_property_readonly("cls",
        static_cast<no_const_getter_t<Class*>>(&Field::cls),
        "" RST_CLASS_REF(lief.DEX.Class) " associated with this field")

    .def_property_readonly("is_static",
        &Field::is_static,
        "True if the field is static")

    .def_property_readonly("type",
        static_cast<no_const_getter_t<Type*>>(&Field::type),
        "" RST_CLASS_REF(lief.DEX.Type) " of this field", py::return_value_policy::reference)

    .def_property_readonly("access_flags",
        static_cast<getter_t<Field::access_flags_list_t>>(&Field::access_flags),
        "List of " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) "")

    .def("has",
        static_cast<bool(Field::*)(ACCESS_FLAGS) const>(&Field::has),
        "Check if the given " RST_CLASS_REF(lief.DEX.ACCESS_FLAGS) " is present",
        "flag"_a)

    .def("__eq__", &Field::operator==)
    .def("__ne__", &Field::operator!=)
    .def("__hash__",
        [] (const Field& fld) {
          return Hash::hash(fld);
        })

    .def("__str__",
        [] (const Field& fld) {
          std::ostringstream stream;
          stream << fld;
          return stream.str();
        });
}

}
}
