/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "PE/pyPE.hpp"

#include "LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp"
#include "LIEF/PE/exceptions_info/UnwindCodeX64.hpp"
#include "enums_wrapper.hpp"

#include <string>
#include <sstream>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/unique_ptr.h>

#include "nanobind/extra/stl/lief_optional.h"

namespace LIEF::PE::unwind_x64::py {
void init(nb::module_& m);
}

namespace LIEF::PE::py {

template<>
void create<RuntimeFunctionX64>(nb::module_& m) {
  nb::class_<RuntimeFunctionX64, ExceptionInfo> rfunc(m, "RuntimeFunctionX64",
    R"doc(
    This class represents an entry in the exception table (``.pdata`` section)
    for the x86-64 architecture.

    Reference: https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
    )doc"_doc);

  unwind_x64::py::init(m);

  enum_<RuntimeFunctionX64::UNWIND_FLAGS>(rfunc, "UNWIND_FLAGS", nb::is_flag())
    .value("EXCEPTION_HANDLER", RuntimeFunctionX64::UNWIND_FLAGS::EXCEPTION_HANDLER,
      R"doc(
      The function has an exception handler that should be called when looking
      for functions that need to examine exception
      )doc"_doc
    )

    .value("TERMINATE_HANDLER", RuntimeFunctionX64::UNWIND_FLAGS::TERMINATE_HANDLER,
      R"doc(
      The function has a termination handler that should be called when
      unwinding an exception.
      )doc"_doc
    )

    .value("CHAIN_INFO", RuntimeFunctionX64::UNWIND_FLAGS::CHAIN_INFO,
      R"doc(
      The chained info payload references a previous ``RUNTIME_FUNCTION``
      )doc"_doc
    );

  enum_<RuntimeFunctionX64::UNWIND_OPCODES>(rfunc, "UNWIND_OPCODES")
    .value("PUSH_NONVOL", RuntimeFunctionX64::UNWIND_OPCODES::PUSH_NONVOL,
      R"doc(
      Push a nonvolatile integer register, decrementing RSP by 8.
      The operation info is the number of the register. Because of the
      constraints on epilogs, ``PUSH_NONVOL`` unwind codes must appear first
      in the prolog and correspondingly, last in the unwind code array.
      This relative ordering applies to all other unwind codes except
      :attr:`~.UNWIND_OPCODES.PUSH_MACHFRAME`.
      )doc"_doc
    )

    .value("ALLOC_LARGE", RuntimeFunctionX64::UNWIND_OPCODES::ALLOC_LARGE,
      R"doc(
      Allocate a large-sized area on the stack.
      There are two forms. If the operation info equals 0,
      then the size of the allocation divided by 8 is recorded in the next slot,
      allowing an allocation up to 512K - 8. If the operation info equals 1,
      then the unscaled size of the allocation is recorded in the next two
      slots in little-endian format, allowing allocations up to 4GB - 8.
      )doc"_doc
    )

    .value("ALLOC_SMALL", RuntimeFunctionX64::UNWIND_OPCODES::ALLOC_SMALL,
      R"doc(
      Allocate a small-sized area on the stack. The size of the allocation is
      the operation info field * 8 + 8, allowing all to 4GB - 8.
      )doc"_doc
    )

    .value("SET_FPREG", RuntimeFunctionX64::UNWIND_OPCODES::SET_FPREG,
      R"doc(
      Establish the frame pointer register by setting the register to some
      offset of the current RSP. The offset is equal to the Frame Register
      offset (scaled) field in the UNWIND_INFO * 16, allowing offsets from
      0 to 240. The use of an offset permits establishing a frame pointer that
      points to the middle of the fixed stack allocation, helping code density
      by allowing more accesses to use short instruction forms. The operation
      info field is reserved and shouldn't be used.
      )doc"_doc
    )

    .value("SAVE_NONVOL", RuntimeFunctionX64::UNWIND_OPCODES::SAVE_NONVOL,
      R"doc(
      Save a nonvolatile integer register on the stack using a MOV instead of a
      PUSH. This code is primarily used for shrink-wrapping, where a nonvolatile
      register is saved to the stack in a position that was previously allocated.
      The operation info is the number of the register. The scaled-by-8 stack
      offset is recorded in the next unwind operation code slot, as described
      in the note above.
      )doc"_doc
    )

    .value("SAVE_NONVOL_FAR", RuntimeFunctionX64::UNWIND_OPCODES::SAVE_NONVOL_FAR,
      R"doc(
      Save a nonvolatile integer register on the stack with a long offset,
      using a MOV instead of a PUSH. This code is primarily used for
      shrink-wrapping, where a nonvolatile register is saved to the stack in a
      position that was previously allocated. The operation info is the number
      of the register. The unscaled stack offset is recorded in the next two
      unwind operation code slots, as described in the note above.
      )doc"_doc)

    .value("SAVE_XMM128", RuntimeFunctionX64::UNWIND_OPCODES::SAVE_XMM128,
      R"doc(
      Save all 128 bits of a nonvolatile XMM register on the stack.
      The operation info is the number of the register. The scaled-by-16 stack
      offset is recorded in the next slot.
      )doc"_doc
    )

    .value("SAVE_XMM128_FAR", RuntimeFunctionX64::UNWIND_OPCODES::SAVE_XMM128_FAR,
      R"doc(
      Save all 128 bits of a nonvolatile XMM register on the stack with a
      long offset. The operation info is the number of the register.
      The unscaled stack offset is recorded in the next two slots.
      )doc"_doc
    )

    .value("PUSH_MACHFRAME", RuntimeFunctionX64::UNWIND_OPCODES::PUSH_MACHFRAME,
      R"doc(
      Push a machine frame. This unwind code is used to record the effect of a
      hardware interrupt or exception.
      )doc"_doc
    )

    .value("EPILOG", RuntimeFunctionX64::UNWIND_OPCODES::EPILOG,
      R"doc(
      This entry is only revelant for version 2. It describes the function
      epilog.
      )doc"_doc
    )

    .value("SPARE", RuntimeFunctionX64::UNWIND_OPCODES::SPARE,
      R"doc(
      Reserved
      Originally SAVE_XMM128_FAR in version 1, but deprecated and removed
      )doc"_doc
    )
  ;

  enum_<RuntimeFunctionX64::UNWIND_REG>(rfunc, "UNWIND_REG")
    .value("RAX", RuntimeFunctionX64::UNWIND_REG::RAX)
    .value("RCX", RuntimeFunctionX64::UNWIND_REG::RCX)
    .value("RDX", RuntimeFunctionX64::UNWIND_REG::RDX)
    .value("RBX", RuntimeFunctionX64::UNWIND_REG::RBX)
    .value("RSP", RuntimeFunctionX64::UNWIND_REG::RSP)
    .value("RBP", RuntimeFunctionX64::UNWIND_REG::RBP)
    .value("RSI", RuntimeFunctionX64::UNWIND_REG::RSI)
    .value("RDI", RuntimeFunctionX64::UNWIND_REG::RDI)
    .value("R8", RuntimeFunctionX64::UNWIND_REG::R8)
    .value("R9", RuntimeFunctionX64::UNWIND_REG::R9)
    .value("R10", RuntimeFunctionX64::UNWIND_REG::R10)
    .value("R11", RuntimeFunctionX64::UNWIND_REG::R11)
    .value("R12", RuntimeFunctionX64::UNWIND_REG::R12)
    .value("R13", RuntimeFunctionX64::UNWIND_REG::R13)
    .value("R14", RuntimeFunctionX64::UNWIND_REG::R14)
    .value("R15", RuntimeFunctionX64::UNWIND_REG::R15);

  using unwind_info_t = RuntimeFunctionX64::unwind_info_t;
  nb::class_<unwind_info_t>(rfunc, "unwind_info_t")
    .def_rw("version", &unwind_info_t::version,
      "Version number of the unwind data, currently 1 or 2."_doc
    )

    .def_rw("flags", &unwind_info_t::flags,
      "See: :class:`lief.PE.RuntimeFunctionX64.UNWIND_FLAGS`"_doc
    )

    .def_rw("sizeof_prologue", &unwind_info_t::sizeof_prologue,
      "Length of the function prolog in bytes."_doc
    )

    .def_rw("count_opcodes", &unwind_info_t::count_opcodes,
      R"doc(
      The number of slots in the unwind codes array. Some unwind codes, for
      example, :attr:`lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.SAVE_NONVOL`,
      require more than one slot in the array.
      )doc"_doc
    )

    .def_rw("frame_reg", &unwind_info_t::frame_reg,
      R"doc(
      If nonzero, then the function uses a frame pointer (FP), and this field
      is the number of the nonvolatile register used as the frame pointer,
      using the same encoding for the operation info field of :class:`~.UNWIND_OPCODES`
      node
      )doc"_doc
    )

    .def_rw("frame_reg_offset", &unwind_info_t::frame_reg_offset,
      R"doc(
      If the frame register field is nonzero, this field is the scaled offset
      from RSP that is applied to the FP register when it's established
      )doc"_doc
    )

    .def_rw("raw_opcodes", &unwind_info_t::raw_opcodes,
      R"doc(
      An array of items that explains the effect of the prolog on the
      nonvolatile registers and RSP
      )doc"_doc
    )

    .def_rw("handler", &unwind_info_t::handler,
      R"doc(
      An image-relative pointer to either the function's language-specific
      exception or termination handler. This value is set if one of these
      flags is set: :attr:`lief.PE.RuntimeFunctionX64.UNWIND_FLAGS.EXCEPTION_HANDLER`,
      :attr:`lief.PE.UNWIND_FLAGS.TERMINATE_HANDLER`.
      )doc"_doc
    )

    .def_rw("chained", &unwind_info_t::chained,
      R"doc(
      If :attr:`lief.PE.UNWIND_FLAGS.CHAIN_INFO` is set, this attributes
      references the chained runtime function.
      )doc"_doc
    )

    .def("has", &unwind_info_t::has,
         "Check if the given flag is used"_doc)

    .def_prop_ro("opcodes", &unwind_info_t::opcodes,
      "Enhanced representation of the unwind code"_doc)
  LIEF_DEFAULT_STR(unwind_info_t);

  rfunc
    .def_prop_ro("rva_end", &RuntimeFunctionX64::rva_end,
      "Function end address"_doc
    )

    .def_prop_ro("unwind_rva", &RuntimeFunctionX64::unwind_rva,
      "Unwind info address"_doc
    )

    .def_prop_ro("size", &RuntimeFunctionX64::size,
      "Size of the function (in bytes)"_doc
    )

    .def_prop_ro("unwind_info", nb::overload_cast<>(&RuntimeFunctionX64::unwind_info),
      "Detailed unwind information"_doc
    )
  ;
}

}
