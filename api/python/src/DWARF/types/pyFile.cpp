#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/File.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::File>(nb::module_& m) {
  nb::class_<dw::types::File, dw::Type> type(m, "File",
    R"doc(
    This class represents the ``DW_TAG_file_type`` type
    )doc"_doc
  );
}

}
