#include "LIEF/DWARF/LexicalBlock.hpp"
#include "DWARF/pyDwarf.hpp"
#include "pyErr.hpp"

#include "nanobind/extra/stl/lief_optional.h"
#include <nanobind/make_iterator.h>
#include <nanobind/stl/unique_ptr.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

namespace LIEF::dwarf::py {
template<>
void create<dw::LexicalBlock>(nb::module_& m) {
  nb::class_<dw::LexicalBlock> LB(m, "LexicalBlock",
    R"doc(
    This class represents a DWARF lexical block (``DW_TAG_lexical_block``)
    )doc"_doc
  );

  LB
  .def_prop_ro("name", &dw::LexicalBlock::name,
    "Return the *name* associated with this lexical block or an empty string"_doc
  )

  .def_prop_ro("description", &dw::LexicalBlock::description,
    "Return the description associated with this lexical block or an empty string"_doc
  )

  .def_prop_ro("sub_blocks",
      [] (dw::LexicalBlock& self) {
        auto sub_blocks = self.sub_blocks();
        return nb::make_iterator<nb::rv_policy::reference_internal>(
            nb::type<dw::LexicalBlock>(), "sub_blocks_it", sub_blocks);
      }, nb::keep_alive<0, 1>(),
      "Return an iterator over the sub-LexicalBlock owned by this block."_doc
  )
  .def_prop_ro("addr", &dw::LexicalBlock::addr,
    "Return the start address of this block"_doc
  )

  .def_prop_ro("size", &dw::LexicalBlock::size,
    R"doc(
    Return the size of this block as the difference of the highest address and
    the lowest address.
    )doc"_doc
  )
  .def_prop_ro("low_pc", &dw::LexicalBlock::low_pc,
    "Return the lowest virtual address owned by this block."_doc
  )

  .def_prop_ro("high_pc", &dw::LexicalBlock::high_pc,
    "Return the highest virtual address owned by this block."_doc
  )
  .def_prop_ro("ranges", &dw::LexicalBlock::ranges,
    R"doc(
    Return a list of address ranges owned by this block.

    If the lexical block owns a contiguous range, it should return
    **a single** range.
    )doc"_doc
  )
  ;
}

}
