#include "runtime/objects/pyModule.hpp"
#include "LIEF/runtime/Module.hpp"
#include "runtime/pyRuntime.hpp"

#include "nanobind/utils.hpp"
#include <nanobind/make_iterator.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unique_ptr.h>

#include "pyOwningIterator.hpp"

namespace LIEF::runtime::py {
template<>
void create<Module>(nb::module_& m) {
  nb::class_<Module> obj(
      m, "Module",
      R"doc(
      This class represents an in-memory module which can be an executable or a
      library
      )doc"_doc
  );

  obj.def_prop_ro(
         "name", &Module::name,
         "Name of the module (e.g. ``libc.so.6, kernel32.dll, libsystem_c.dylib``)"_doc
  )
      .def_prop_ro("path", &Module::path, "Path of the module"_doc)
      .def_prop_ro("imagebase", &Module::imagebase, "Imagebase of the module"_doc)
      .def_prop_ro("end", &Module::end, "End address of the module"_doc)
      .def_prop_ro("size", &Module::size, "Virtual size of the current module"_doc)
      .def("contains", &Module::contains, "addr"_a,
           "Check if the current module contains the given address"_doc)
      .def(
          "dump", [](const Module& self) { return nb::to_bytes(self.dump()); },
          "Return the content of the module as it is currently mapped in memory"_doc
      )
      .def(
          "dump",
          [](const Module& self, const std::string& filepath) {
            return nb::to_bytes(self.dump(filepath));
          },
          "Same as :meth:`dump` but also write the content into the file given in "
          "parameter"_doc,
          "filepath"_a
      )

      .LIEF_DEFAULT_STR(Module);

  m.def(
      "modules",
      []() {
        auto mods = LIEF::py::owning_range(runtime::modules());
        return nb::make_iterator<nb::rv_policy::take_ownership>(nb::type<Module>(),
                                                                "modules_iterator",
                                                                mods);
      },
      R"doc(
      Return an iterator over the different modules loaded in the current process
      )doc"_doc
  );

  m.def("module_from_name", &runtime::module_from_name, "name"_a,
        "Find the module with the given name"_doc);

  m.def("module_from_path", &runtime::module_from_path, "path"_a,
        "Find the module with the given path"_doc);

  m.def(
      "module_from_addr", &runtime::module_from_addr, "addr"_a,
      "Find the module that encompasses the given virtual address (absolute)"_doc
  );

  m.def("current_module", &runtime::current_module,
        R"doc(
        Return the module that contains the code calling this function.

        From Python, this code is LIEF's native extension, so it returns the
        module of the extension (e.g. ``_lief.{so,pyd}``).
        )doc"_doc);
}

}
