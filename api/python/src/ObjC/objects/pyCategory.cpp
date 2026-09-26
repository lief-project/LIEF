#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/Category.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

#include "pyOwningIterator.hpp"

namespace LIEF::objc::py {
template<>
void create<objc::Category>(nb::module_& m) {
  nb::class_<objc::Category> category(m, "Category",
    R"doc(
    This class represents an Objective-C category (e.g.
    ``@interface NSString (MyAdditions)``)
    )doc"_doc
  );
  category
    .def_prop_ro("name", &objc::Category::name,
      R"doc(
      Name of the category
      )doc"_doc
    )
    .def_prop_ro("class_name", &objc::Category::class_name,
      R"doc(
      (demangled) name of the class extended by this category
      )doc"_doc
    )
    .def_prop_ro("methods",
      [] (objc::Category& self) {
          auto methods = LIEF::py::owning_range(self.methods());
          return nb::make_iterator<nb::rv_policy::reference_internal>(
            nb::type<objc::Category>(), "methods_it", methods.begin(), methods.end(),
            nb::keep_alive<0, 1>()
          );
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the different methods defined by this category.
      )doc"_doc
    )
    .def_prop_ro("protocols",
      [] (objc::Category& self) {
          auto protocols = LIEF::py::owning_range(self.protocols());
          return nb::make_iterator<nb::rv_policy::reference_internal>(
            nb::type<objc::Category>(), "protocols_it", protocols.begin(), protocols.end(),
            nb::keep_alive<0, 1>()
          );
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the different protocols adopted by this category.
      )doc"_doc
    )
    .def_prop_ro("properties",
      [] (objc::Category& self) {
          auto properties = LIEF::py::owning_range(self.properties());
          return nb::make_iterator<nb::rv_policy::reference_internal>(
            nb::type<objc::Category>(), "properties_it", properties.begin(), properties.end(),
            nb::keep_alive<0, 1>()
          );
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the properties of this category.
      )doc"_doc
    )
    .def("to_decl", &Category::to_decl,
      R"doc(
      Generate a header-like string for this specific category.

      The generated output can be configured with the provided :class:`~.DeclOpt`
      parameter.
      )doc"_doc, "opt"_a = DeclOpt()
    )
  ;
}

}
