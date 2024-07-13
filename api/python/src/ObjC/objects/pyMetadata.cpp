#include "ObjC/pyObjC.hpp"
#include "LIEF/ObjC/Metadata.hpp"
#include "LIEF/ObjC/Class.hpp"

#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/make_iterator.h>


namespace LIEF::objc::py {
template<>
void create<objc::Metadata>(nb::module_& m) {
  nb::class_<objc::Metadata> meta(m, "Metadata",
    R"doc(
    This class is the main interface to inspect Objective-C metadata

    It can be instantiated using the function :attr:`lief.MachO.Binary.objc_metadata`
    )doc"_doc
  );
  meta
    .def("to_decl", &Metadata::to_decl,
      R"doc(
      Generate a header-like of all the Objective-C metadata identified in the
      binary.
      )doc"_doc
    )
    .def_prop_ro("classes",
        [] (objc::Metadata& self) {
          auto classes = self.classes();
          return nb::make_iterator(nb::type<objc::Metadata>(), "classes_it", classes);
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Return an iterator over the different Objective-C classes (``@interface``).
        )doc"_doc
    )
    .def_prop_ro("protocols",
        [] (objc::Metadata& self) {
          auto protocols = self.protocols();
          return nb::make_iterator(nb::type<objc::Metadata>(), "protocols_it", protocols);
        }, nb::keep_alive<0, 1>(),
        R"doc(
        Return an iterator over the Objective-C protocols declared in this
        binary (``@protocol``).
        )doc"_doc
    )

    .def("get_class", &objc::Metadata::get_class,
      R"doc(
      Try to find the Objective-C class with the given **mangled** name.
      )doc"_doc, "name"_a
    )

    .def("get_protocol", &objc::Metadata::get_protocol,
      R"doc(
      Try to find the Objective-C class with the given **mangled** name.
      )doc"_doc, "name"_a
    )
  ;
}

}
