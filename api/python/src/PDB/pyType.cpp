#include "PDB/pyPDB.hpp"
#include "LIEF/PDB/Type.hpp"

namespace LIEF::pdb::types {
class Simple;
class Array;
class BitField;
class ClassLike;
class Enum;
class Function;
class Modifier;
class Pointer;
class Union;
}

namespace LIEF::pdb::py {
template<>
void create<pdb::Type>(nb::module_& m) {
  nb::module_ types = m.def_submodule("types", "PDB Types"_doc);
  nb::class_<pdb::Type> type(m, "Type",
    R"doc()doc"_doc
  );

  nb::enum_<Type::KIND>(type, "KIND")
    .value("UNKNOWN", Type::KIND::UNKNOWN)
    .value("CLASS", Type::KIND::CLASS)
    .value("POINTER", Type::KIND::POINTER)
    .value("SIMPLE", Type::KIND::SIMPLE)
    .value("ENUM", Type::KIND::ENUM)
    .value("FUNCTION", Type::KIND::FUNCTION)
    .value("MODIFIER", Type::KIND::MODIFIER)
    .value("BITFIELD", Type::KIND::BITFIELD)
    .value("ARRAY", Type::KIND::ARRAY)
    .value("UNION", Type::KIND::UNION)
    .value("STRUCTURE", Type::KIND::STRUCTURE)
    .value("INTERFACE", Type::KIND::INTERFACE)
  ;

  type
    .def_prop_ro("kind", &pdb::Type::kind,
        R"doc(
        Discriminator for the type's subclasses
        )doc"_doc
    )
  ;

  create<pdb::types::Simple>(types);
  create<pdb::types::Array>(types);
  create<pdb::types::BitField>(types);
  create<pdb::types::ClassLike>(types);
  create<pdb::types::Enum>(types);
  create<pdb::types::Function>(types);
  create<pdb::types::Modifier>(types);
  create<pdb::types::Pointer>(types);
  create<pdb::types::Union>(types);
}
}
