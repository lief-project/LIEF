#include "LIEF/DWARF/types/Base.hpp"
#include "DWARF/pyDwarf.hpp"

namespace LIEF::dwarf::py {
template<>
void create<dw::types::Base>(nb::module_& m) {
  nb::class_<dw::types::Base, dw::Type> type(m, "Base",
    R"doc(
    This class wraps the ``DW_TAG_base_type`` type which can be used -- for
    instance -- to represent integers or primitive types.
    )doc"_doc
  );

  nb::enum_<dw::types::Base::ENCODING>(type, "ENCODING")
    .value("NONE", dw::types::Base::ENCODING::NONE)
    .value("SIGNED", dw::types::Base::ENCODING::SIGNED, "Mirror ``DW_ATE_signed``"_doc)
    .value("SIGNED_CHAR", dw::types::Base::ENCODING::SIGNED_CHAR, "Mirror ``DW_ATE_signed_char``"_doc)
    .value("UNSIGNED", dw::types::Base::ENCODING::UNSIGNED, "Mirror ``DW_ATE_unsigned``"_doc)
    .value("UNSIGNED_CHAR", dw::types::Base::ENCODING::UNSIGNED_CHAR, "Mirror ``DW_ATE_unsigned_char``"_doc)
    .value("FLOAT", dw::types::Base::ENCODING::FLOAT, "Mirror ``DW_ATE_float``"_doc)
    .value("BOOLEAN", dw::types::Base::ENCODING::BOOLEAN, "Mirror ``DW_ATE_boolean``"_doc)
    .value("ADDRESS", dw::types::Base::ENCODING::ADDRESS, "Mirror ``DW_ATE_address``"_doc)
  ;

  type
    .def_prop_ro("encoding", &dw::types::Base::encoding,
      R"doc(
      Describe how the the base type is encoded and should be interpreted.
      )doc"_doc
    )
  ;
}

}
