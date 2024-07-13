#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/Protocol.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/make_iterator.h>

namespace LIEF::objc::py {
template<>
void create<objc::Protocol>(nb::module_& m) {
  nb::class_<objc::Protocol> protocol(m, "Protocol",
    R"doc(
    This class represents an Objective-C ``@protocol``
    )doc"_doc
  );

  protocol
    .def_prop_ro("mangled_name", &objc::Protocol::mangled_name,
      R"doc(
      Mangled name of the protocol
      )doc"_doc
    )

    .def_prop_ro("optional_methods",
      [] (objc::Protocol& self) {
        auto methods = self.optional_methods();
        return nb::make_iterator(nb::type<objc::Protocol>(), "optional_methods_it", methods);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the methods that could be overridden
      )doc"_doc
    )
    .def_prop_ro("required_methods",
      [] (objc::Protocol& self) {
        auto methods = self.required_methods();
        return nb::make_iterator(nb::type<objc::Protocol>(), "required_methods_it", methods);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the methods of this protocol that must be implemented
      )doc"_doc
    )
    .def_prop_ro("properties",
      [] (objc::Protocol& self) {
        auto props = self.properties();
        return nb::make_iterator(nb::type<objc::Protocol>(), "properties_it", props);
      }, nb::keep_alive<0, 1>(),
      R"doc(
      Iterator over the properties defined in this protocol
      )doc"_doc
    )
  ;
}

}
