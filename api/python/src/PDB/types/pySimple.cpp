#include "LIEF/PDB/types/Simple.hpp"
#include "PDB/pyPDB.hpp"

namespace LIEF::pdb::py {
template<>
void create<pdb::types::Simple>(nb::module_& m) {
  using Simple = pdb::types::Simple;

  nb::class_<pdb::types::Simple, pdb::Type> type(m, "Simple",
    R"doc(
    This class represents a primitive types (int, float, ...) which are
    also named *simple* types in the PDB format.
    )doc"_doc
  );

  nb::enum_<Simple::TYPES>(type, "TYPES")
    .value("UNKNOWN", Simple::TYPES::UNKNOWN)
    .value("VOID", Simple::TYPES::VOID_, "Void type (return type or void*)")

    .value("SCHAR", Simple::TYPES::SCHAR, "Signed Character")
    .value("UCHAR", Simple::TYPES::UCHAR, "Unsigned Character")
    .value("RCHAR", Simple::TYPES::RCHAR, "'Real' Character (char)")

    .value("WCHAR", Simple::TYPES::WCHAR, "Wide Character (wchar_t)")
    .value("CHAR16", Simple::TYPES::CHAR16, "16-bit Character (char16_t)")
    .value("CHAR32", Simple::TYPES::CHAR32, "32-bit Character (char32_t)")
    .value("CHAR8", Simple::TYPES::CHAR8, "8-bit Character (char8_t)")

    .value("SBYTE", Simple::TYPES::SBYTE, "Signed Byte")
    .value("UBYTE", Simple::TYPES::UBYTE, "Unsigned Byte")

    .value("SSHORT", Simple::TYPES::SSHORT, "Signed Short")
    .value("USHORT", Simple::TYPES::USHORT, "Unsigned Short")

    .value("SINT16", Simple::TYPES::SINT16, "Explicit Signed 16-bit Integer")
    .value("UINT16", Simple::TYPES::UINT16, "Explicit Unsigned 16-bit Integer")

    .value("SLONG", Simple::TYPES::SLONG, "Signed Long")
    .value("ULONG", Simple::TYPES::ULONG, "Unsigned Long")

    .value("SINT32", Simple::TYPES::SINT32, "Explicit Signed 32-bit Integer")
    .value("UINT32", Simple::TYPES::UINT32, "Explicit Unsigned 32-bit Integer")

    .value("SQUAD", Simple::TYPES::SQUAD, "Signed Quadword")
    .value("UQUAD", Simple::TYPES::UQUAD, "Unsigned Quadword")

    .value("SINT64", Simple::TYPES::SINT64, "Explicit Signed 64-bit Integer")
    .value("UINT64", Simple::TYPES::UINT64, "Explicit Unsigned 64-bit Integer")

    .value("SOCTA", Simple::TYPES::SOCTA, "Signed Octaword")
    .value("UOCTA", Simple::TYPES::UOCTA, "Unsigned Octaword")

    .value("SINT128", Simple::TYPES::SINT128, "Explicit Signed 128-bit Integer")
    .value("UINT128", Simple::TYPES::UINT128, "Explicit Unsigned 128-bit Integer")

    .value("FLOAT16", Simple::TYPES::FLOAT16, "16-bit Floating point")
    .value("FLOAT32", Simple::TYPES::FLOAT32, "32-bit Floating point (float)")
    .value("FLOAT32_PARTIAL_PRECISION", Simple::TYPES::FLOAT32_PARTIAL_PRECISION)

    .value("FLOAT48", Simple::TYPES::FLOAT48, "48-bit Floating point")
    .value("FLOAT64", Simple::TYPES::FLOAT64, "64-bit Floating point (double)")
    .value("FLOAT80", Simple::TYPES::FLOAT80, "80-bit Floating point")
    .value("FLOAT128", Simple::TYPES::FLOAT128, "128-bit Floating point")

    .value("COMPLEX16", Simple::TYPES::COMPLEX16)
    .value("COMPLEX32", Simple::TYPES::COMPLEX32)
    .value("COMPLEX32_PARTIAL_PRECISION", Simple::TYPES::COMPLEX32_PARTIAL_PRECISION)
    .value("COMPLEX48", Simple::TYPES::COMPLEX48)
    .value("COMPLEX64", Simple::TYPES::COMPLEX64)
    .value("COMPLEX80", Simple::TYPES::COMPLEX80)
    .value("COMPLEX128", Simple::TYPES::COMPLEX128)

    .value("BOOL8", Simple::TYPES::BOOL8, "8-bit Boolean")
    .value("BOOL16", Simple::TYPES::BOOL16, "16-bit Boolean")
    .value("BOOL32", Simple::TYPES::BOOL32, "32-bit Boolean")
    .value("BOOL64", Simple::TYPES::BOOL64, "64-bit Boolean")
    .value("BOOL128", Simple::TYPES::BOOL128, "128-bit Boolean");


  nb::enum_<Simple::MODES>(type, "MODES")
    .value("DIRECT", Simple::MODES::DIRECT, "Not a pointer (direct access)")
    .value("FAR_POINTER", Simple::MODES::FAR_POINTER, "Far pointer")
    .value("HUGE_POINTER", Simple::MODES::HUGE_POINTER, "Huge pointer")
    .value("NEAR_POINTER32", Simple::MODES::NEAR_POINTER32, "32-bit Near pointer")
    .value("FAR_POINTER32", Simple::MODES::FAR_POINTER32, "32-bit Far pointer")
    .value("NEAR_POINTER64", Simple::MODES::NEAR_POINTER64, "64-bit Near pointer")
    .value("NEAR_POINTER128", Simple::MODES::NEAR_POINTER128, "128-bit Near pointer");

  type
    .def_prop_ro("type", &Simple::type,
      "Returns the underlying primitive type."_doc
    )

    .def_prop_ro("modes", &Simple::modes,
      "Returns the mode (pointer type) of this Simple type."_doc
    )

    .def_prop_ro("is_pointer", &Simple::is_pointer,
      "Check if this simple type is a pointer."_doc
    )

    .def_prop_ro("is_signed", &Simple::is_pointer,
      "Check if the underlying type is signed."_doc
    );
}

}
