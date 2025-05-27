#include "LIEF/DWARF/editor/Type.hpp"
#include "LIEF/DWARF/editor/PointerType.hpp"
#include "LIEF/DWARF/editor/EnumType.hpp"
#include "LIEF/DWARF/editor/BaseType.hpp"
#include "LIEF/DWARF/editor/ArrayType.hpp"
#include "LIEF/DWARF/editor/FunctionType.hpp"
#include "LIEF/DWARF/editor/TypeDef.hpp"
#include "LIEF/DWARF/editor/StructType.hpp"

#include "DWARF/pyDwarf.hpp"

#include <nanobind/stl/unique_ptr.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::editor::Type>(nb::module_& m) {
  nb::class_<dw::editor::Type>(m, "Type",
    R"doc(
    This class is the base class for any types created when editing DWARF debug
    info.

    A type is owned by a :class:`lief.dwarf.editor.CompilationUnit` and should be
    created from this class.
    )doc"_doc
  )
    .def("pointer_to", &dw::editor::Type::pointer_to,
         "Create a pointer type pointing to this type"_doc)
  ;

  create<LIEF::dwarf::editor::PointerType>(m);
  create<LIEF::dwarf::editor::EnumType>(m);
  create<LIEF::dwarf::editor::BaseType>(m);
  create<LIEF::dwarf::editor::ArrayType>(m);
  create<LIEF::dwarf::editor::FunctionType>(m);
  create<LIEF::dwarf::editor::TypeDef>(m);
  create<LIEF::dwarf::editor::StructType>(m);
}

}
