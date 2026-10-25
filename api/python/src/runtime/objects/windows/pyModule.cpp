#include "LIEF/PE/Binary.hpp"
#include "LIEF/PE/ParserConfig.hpp"
#include "LIEF/runtime/windows/Module.hpp"
#include "runtime/pyRuntime.hpp"

#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>

#include "typing/StrOrPath.hpp"

namespace LIEF::runtime::windows::py {

template<>
void create<Module>(nb::module_& m) {
  nb::class_<Module, runtime::Module> obj(
      m, "Module", "This class exposes a Windows-specific API for a module"_doc
  );

  obj.def_prop_ro(
         "handle", &Module::handle,
         R"doc(
         Return the ``HMODULE`` handle as an opaque pointer.

         Return ``None`` if the function fails or if the handler can't be found
         )doc"_doc
  )
      .def("dlsym", &Module::dlsym,
           "Resolve the symbol with the given name for the current module"_doc,
           "name"_a)

      .def_static("from_handle", &Module::from_handle,
                  R"doc(
                  Create a :class:`~lief.runtime.windows.Module` from the given
                  ``HMODULE`` handle (passed as an opaque pointer).
                  )doc"_doc,
                  "handle"_a)

      .def("parse_from_path",
           nb::overload_cast<>(&Module::parse_from_path, nb::const_),
           "Parse the PE module from its path on the filesystem"_doc)

      .def(
          "parse_from_path",
          nb::overload_cast<const PE::ParserConfig&>(&Module::parse_from_path,
                                                     nb::const_),
          "Parse the PE module from its path on the filesystem and given the parser configuration"_doc,
          "config"_a
      )

      .def("parse_from_memory",
           nb::overload_cast<>(&Module::parse_from_memory, nb::const_),
           "Parse the PE module from memory"_doc)

      .def("parse_from_memory",
           nb::overload_cast<const PE::ParserConfig&>(&Module::parse_from_memory,
                                                      nb::const_),
           "Parse the PE module from memory with the given configuration"_doc,
           "config"_a);


  m.def(
      "dlopen",
      [](LIEF::py::typing::StrOrPath name) {
        return windows::dlopen(*name.to_string());
      },
      "Load the windows library with the given path or name."_doc, "name"_a
  );

  m.def("find_module", &windows::find_module,
        R"doc(
        Try to get the :class:`~lief.runtime.windows.Module` with the given name.

        Return ``None`` if the module is not found.

        .. code-block:: python

           if ntdll := lief.runtime.windows.find_module("ntdll.dll"):
               print(ntdll.path)

        .. note::

           This function relies on the Windows API ``GetModuleHandle`` which is
           more efficient than the generic implementation
           :func:`lief.runtime.module_from_name`.
        )doc"_doc,
        "name"_a);
}

}
