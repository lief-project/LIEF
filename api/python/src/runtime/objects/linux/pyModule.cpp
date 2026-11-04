#include "LIEF/ELF/Binary.hpp" // IWYU pragma: keep
#include "LIEF/ELF/ParserConfig.hpp"
#include "LIEF/runtime/linux/Module.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "typing/StrOrPath.hpp"

namespace LIEF::runtime::Linux::py {

template<>
void create<Module>(nb::module_& m) {
  nb::class_<Module, runtime::Module> obj(
      m, "Module", "This class exposes a Linux-specific API for a module"_doc
  );

  obj.def_prop_ro(
         "handle", &Module::handle,
         R"doc(
         Return the ``dlopen`` handle for this library as an opaque pointer.

         Return ``None`` if the function fails or if the handler can't be found
         )doc"_doc
  )
      .def("dlsym", &Module::dlsym,
           "Resolve the symbol with the given name for the current module"_doc,
           "name"_a)

      .def_static("from_handle", &Module::from_handle,
                  R"doc(
                  Create a :class:`~lief.runtime.linux.Module` from the given ``dlopen`` handle.

                  The handle is expected to be an opaque pointer as returned by
                  :attr:`handle` or :func:`dlopen`.
                  )doc"_doc,
                  "handle"_a)

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
      [](LIEF::py::typing::StrOrPath name) {
        return Linux::dlopen(*name.to_string());
      },
      "Load the library with the given path or name."_doc, "name"_a
  );
}

}
