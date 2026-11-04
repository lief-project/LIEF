#include "LIEF/ELF/Binary.hpp" // IWYU pragma: keep
#include "LIEF/ELF/ParserConfig.hpp"
#include "LIEF/runtime/android/Module.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "typing/StrOrPath.hpp"

namespace LIEF::runtime::android::py {

template<>
void create<Module>(nb::module_& m) {
  nb::class_<Module, runtime::Module> obj(
      m, "Module", "This class exposes an Android-specific API for a module"_doc
  );

  obj.def_prop_ro(
         "handle", &Module::handle,
         R"doc(
         Return the dlopen handle for this library.

         Return a nullptr if the function fails or if the handler can't be found
         )doc"_doc
  )
      .def("dlsym", &Module::dlsym, "name"_a,
           "Resolve the symbol with the given name for the current module"_doc)
      .def_static(
          "from_handle", &Module::from_handle,
          R"doc(
          Create a :class:`~lief.runtime.android.Module` from the given ``dlopen``
          handle (passed as an opaque pointer).
          )doc"_doc,
          "handle"_a
      )

      .def("parse_from_path",
           nb::overload_cast<>(&Module::parse_from_path, nb::const_),
           "Parse the ELF module from its path on the filesystem"_doc)

      .def(
          "parse_from_path",
          nb::overload_cast<const ELF::ParserConfig&>(&Module::parse_from_path,
                                                      nb::const_),
          "Parse the ELF module from its path on the filesystem and given the parser configuration"_doc,
          "config"_a
      )

      .def("parse_from_memory",
           nb::overload_cast<>(&Module::parse_from_memory, nb::const_),
           "Parse the ELF module from memory"_doc)

      .def("parse_from_memory",
           nb::overload_cast<const ELF::ParserConfig&>(&Module::parse_from_memory,
                                                       nb::const_),
           "Parse the ELF module from memory with the given configuration"_doc,
           "config"_a);

  m.def(
      "dlopen",
      [](LIEF::py::typing::StrOrPath name) { return dlopen(*name.to_string()); },
      "name"_a, "Load the library with the given path/name"_doc
  );
}

}
