#include "LIEF/DWARF/Location.hpp"
#include "DWARF/pyDwarf.hpp"
#include "DWARF/pyLocation.hpp"
#include "nanobind/utils.hpp"

#include <vector>

#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/vector.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::Location>(nb::module_& m) {
  using Location = dw::Location;
  using Piece = dw::CompositeLocation::Piece;

  nb::class_<Location> loc(m, "Location",
    R"doc(
    This class represents where the value of a variable or a parameter lives.
    It interfaces the DWARF location expression (``DW_AT_location``).)doc"_doc);

  nb::enum_<Location::Type>(loc, "Type")
    .value("UNKNOWN", Location::Type::UNKNOWN)
    .value("REGISTER", Location::Type::REG,
           "The value is associated with a register"_doc)
    .value("ADDRESS", Location::Type::ADDRESS,
           "The value is at a fixed memory address"_doc)
    .value("FRAME_BASE", Location::Type::FRAME_BASE,
           "The value is at an offset of the frame base"_doc)
    .value("REGISTER_OFFSET", Location::Type::REGISTER_OFFSET,
           "The value is at an offset of a register"_doc)
    .value("EXPRESSION", Location::Type::EXPRESSION,
           "An unevaluated DWARF expression"_doc)
    .value("UNAVAILABLE", Location::Type::UNAVAILABLE,
           "The value is not available"_doc)
    .value("COMPOSITE", Location::Type::COMPOSITE,
           "The value is split in several pieces"_doc);

  loc
    .def_ro("type", &Location::type,
            "The kind of location"_doc)
    .def("__str__", &Location::to_string);

  nb::class_<dw::RegisterLoc, Location>(m, "RegisterLoc",
    R"doc(
    The value is associated to a register (e.g. ``DW_OP_reg5``)
    )doc"_doc)
    .def_ro("id", &dw::RegisterLoc::id,
      R"doc(
      DWARF id of the register that must be interpreted according to the
      target architecture
      )doc"_doc);

  nb::class_<dw::AddressLoc, Location>(m, "AddressLoc",
    R"doc(
    The value is located at a fixed memory address (e.g. ``DW_OP_addr``)
    )doc"_doc)
    .def_ro("address", &dw::AddressLoc::address,
            "Memory address where the value is located"_doc);

  nb::class_<dw::FrameBaseLoc, Location>(m, "FrameBaseLoc",
    R"doc(
    The value is located in memory relative to the (stack) frame base.
    )doc"_doc)
    .def_ro("offset", &dw::FrameBaseLoc::offset,
            "Signed byte offset from the frame base"_doc);

  nb::class_<dw::RegisterOffsetLoc, Location>(m, "RegisterOffsetLoc",
    R"doc(
    The value is located in memory at the address stored in a register plus a
    signed offset (e.g. ``DW_OP_breg7 +8``)
    )doc"_doc)
    .def_ro("id", &dw::RegisterOffsetLoc::id,
            "DWARF id of the register that contains the base address"_doc)
    .def_ro("offset", &dw::RegisterOffsetLoc::offset,
            "Signed byte offset added to the register's value"_doc);

  nb::class_<dw::ExpressionLoc, Location>(m, "ExpressionLoc",
    R"doc(
    A DWARF expression that is not evaluated by LIEF: implicit values,
    computed addresses, entry values, ...
    )doc"_doc)
    .def_prop_ro("expression",
      [] (const dw::ExpressionLoc& self) {
        return nb::to_bytes(self.expression);
      }, "Raw bytes of the DWARF expression"_doc)
    .def_ro("description", &dw::ExpressionLoc::description,
      R"doc(
      Textual representation of the expression
      (e.g. ``DW_OP_lit0, DW_OP_stack_value``)
      )doc"_doc);

  nb::class_<dw::UnavailableLoc, Location> _(m, "UnavailableLoc",
    R"doc(
    The value is not available at this location (e.g. optimized out)
    )doc"_doc);

  nb::class_<dw::CompositeLocation, Location> composite(m, "CompositeLocation",
    R"doc(
    The value is split into several pieces (``DW_OP_piece/DW_OP_bit_piece``),
    each one with its own location.

    For instance, a 16-bytes structure passed in the ``rdi`` and ``rsi``
    registers is described with two 8-bytes pieces.
    )doc"_doc);

  nb::class_<Piece> piece(composite, "Piece",
    "A piece of a :class:`~.CompositeLocation`"_doc);

  nb::enum_<Piece::KIND>(piece, "KIND")
    .value("BYTE", Piece::KIND::BYTE, "``DW_OP_piece``"_doc)
    .value("BIT", Piece::KIND::BIT, "``DW_OP_bit_piece``"_doc);

  piece
    .def_ro("kind", &Piece::kind,
      "Whether this piece comes from ``DW_OP_piece`` or ``DW_OP_bit_piece``"_doc)
    .def_ro("bit_size", &Piece::bit_size,
      "Size of this piece in bits"_doc)
    .def_ro("bit_offset", &Piece::bit_offset,
      "Offset (in bits) of this piece within the whole value"_doc)
    .def_ro("source_bit_offset", &Piece::source_bit_offset,
      R"doc(
      For a ``DW_OP_bit_piece``, the offset (in bits) of this piece within its
      location (e.g. the register). ``None`` otherwise.
      )doc"_doc)
    .def_prop_ro("location",
      [] (const Piece& self) { return self.location.get(); },
      "Location of this piece or ``None`` if it can't be decoded"_doc,
      nb::rv_policy::reference_internal);

  composite
    .def_prop_ro("pieces",
      [] (const dw::CompositeLocation& self) {
        std::vector<const Piece*> pieces;
        pieces.reserve(self.pieces.size());
        for (const Piece& P : self.pieces) {
          pieces.push_back(&P);
        }
        return pieces;
      },
      "The pieces of this location, ordered by their bit offset"_doc,
      nb::rv_policy::reference_internal);

  nb::class_<dw::LocationEntry>(m, "LocationEntry",
    R"doc(
    A :class:`~.Location` associated with the range of addresses where it is valid.
    )doc"_doc)
    .def_ro("range", &dw::LocationEntry::range,
      R"doc(
      Range of addresses ``[low, high)`` where the location is valid.
      )doc"_doc)
    .def_ro("section_index", &dw::LocationEntry::section_index,
      "Index of the object's section containing the range (if any)"_doc)
    .def_prop_ro("location",
      [] (const dw::LocationEntry& self) { return self.location.get(); },
      "The location or ``None`` if the DWARF expression can't be decoded"_doc,
      nb::rv_policy::reference_internal)
    .def("__str__", &dw::LocationEntry::to_string);
}
}
