#include "DWARF/pyDwarf.hpp"
#include "LIEF/DWARF/Type.hpp"
#include "LIEF/DWARF/types/File.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::File>(nb::module_& m) {
  nb::class_<dw::types::File, dw::Type> type(
      m, "File", "This class represents the ``DW_TAG_file_type`` type"_doc
  );
}

}
