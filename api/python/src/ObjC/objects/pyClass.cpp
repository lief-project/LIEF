#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/Class.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

namespace LIEF::objc::py {
template<>
void create<objc::Class>(nb::module_& m) {
  nb::class_<objc::Class> clazz(m, "Class",
    R"doc(
    This class represents an Objective-C class (``@interface``)
    )doc"_doc
  );
  clazz
    .def_prop_ro("name", &objc::Class::name,
      R"doc(
      Name of the class
      )doc"_doc
    )
    .def_prop_ro("demangled_name", &objc::Class::demangled_name,
      R"doc(
      Demangled name of the class
      )doc"_doc
    )
    .def_prop_ro("super_class", &objc::Class::super_class,
      R"doc(
      Parent class in case of inheritance
      )doc"_doc
    )
    .def_prop_ro("is_meta", &objc::Class::is_meta,
      R"doc(

      )doc"_doc
    )
    .def_prop_ro("methods",
      [] (objc::Class& self) {
          auto methods = self.methods();
          return nb::make_iterator(nb::type<objc::Class>(), "methods_it", methods);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the different methods defined by this class.
      )doc"_doc
    )
    .def_prop_ro("protocols",
      [] (objc::Class& self) {
          auto protocols = self.protocols();
          return nb::make_iterator(nb::type<objc::Class>(), "protocols_it", protocols);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the different protocols implemented by this class.
      )doc"_doc
    )
    .def_prop_ro("properties",
      [] (objc::Class& self) {
          auto properties = self.properties();
          return nb::make_iterator(nb::type<objc::Class>(), "properties_it", properties);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the properties of this class.
      )doc"_doc
    )
    .def_prop_ro("ivars",
      [] (objc::Class& self) {
          auto ivars = self.ivars();
          return nb::make_iterator(nb::type<objc::Class>(), "ivars_it", ivars);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the different instance variables defined in this class.
      )doc"_doc
    )
  ;
}

}
