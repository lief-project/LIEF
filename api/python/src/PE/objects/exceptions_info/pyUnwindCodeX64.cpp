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
#include <nanobind/stl/unique_ptr.h>

#include "LIEF/PE/exceptions_info/UnwindCodeX64.hpp"
#include <string>
#include <sstream>
#include <nanobind/stl/string.h>

namespace LIEF::PE::unwind_x64::py {
template<class T> void create(nb::module_&);


template<>
void create<Code>(nb::module_& m) {
  nb::class_<Code>(m, "Code", "Base class for all unwind operations"_doc)
    .def_prop_ro("opcode", &Code::opcode,
      "The original opcode"_doc
    )

    .def_prop_ro("position", &Code::position,
      "Offset in the prolog"_doc
    )
  LIEF_DEFAULT_STR(Code);
}


template<>
void create<Alloc>(nb::module_& m) {
  nb::class_<Alloc, Code>(m, "Alloc",
    R"doc(
    This class represents a stack-allocation operation
    (:attr:`lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.ALLOC_SMALL`, :attr:`lief.PE.RuntimeFunctionX64.UNWIND_OPCODES.ALLOC_LARGE`)
    )doc"_doc)

  .def_prop_ro("size", &Alloc::size,
    "The size allocated"_doc
  );
}

template<>
void create<PushNonVol>(nb::module_& m) {
  nb::class_<PushNonVol, Code>(m, "PushNonVol",
    R"doc(
    Push a nonvolatile integer register, decrementing RSP by 8
    )doc"_doc)

  .def_prop_ro("reg", &PushNonVol::reg,
    "The register pushed"_doc
  );
}

template<>
void create<PushMachFrame>(nb::module_& m) {
  nb::class_<PushMachFrame, Code>(m, "PushMachFrame",
    R"doc(
    Push a machine frame
    )doc"_doc)

  .def_prop_ro("value", &PushMachFrame::value,
    "0 or 1"_doc
  );
}

template<>
void create<SetFPReg>(nb::module_& m) {
  nb::class_<SetFPReg, Code>(m, "SetFPReg",
    R"doc(
    Establish the frame pointer register by setting the register to some offset
    of the current RSP
    )doc"_doc)

  .def_prop_ro("reg", &SetFPReg::reg,
    "Frame pointer register"_doc
  );
}

template<>
void create<SaveNonVolatile>(nb::module_& m) {
  nb::class_<SaveNonVolatile, Code>(m, "SaveNonVolatile",
    R"doc(
    Save a nonvolatile integer register on the stack using a MOV instead of a
    PUSH.
    )doc"_doc)

  .def_prop_ro("reg", &SaveNonVolatile::reg,
    "The register to save"_doc
  )

  .def_prop_ro("offset", &SaveNonVolatile::offset,
    "The offset where to save the register"_doc
  );
}

template<>
void create<SaveXMM128>(nb::module_& m) {
  nb::class_<SaveXMM128, Code>(m, "SaveXMM128",
    R"doc(
    Save all 128 bits of a nonvolatile XMM register on the stack
    )doc"_doc)

  .def_prop_ro("num", &SaveXMM128::num,
    "XMM register number"_doc
  )

  .def_prop_ro("offset", &SaveXMM128::offset,
    "The offset where to save the register"_doc
  );
}

template<>
void create<Epilog>(nb::module_& m) {
  nb::class_<Epilog, Code>(m, "Epilog",
    R"doc(
    Describes the function's epilog
    )doc"_doc)

  .def_prop_ro("flags", &Epilog::flags)

  .def_prop_ro("size", &Epilog::size,
    "Size of the epilog"_doc
  );
}

template<>
void create<Spare>(nb::module_& m) {
  nb::class_<Spare, Code>(m, "Spare");
}

void init(nb::module_& m) {
  nb::module_ mod = m.def_submodule("unwind_x64",
    "This namespace wraps code related to PE-x64 unwinding code"_doc
  );

  create<Code>(mod);
  create<Alloc>(mod);
  create<PushNonVol>(mod);
  create<PushMachFrame>(mod);
  create<SetFPReg>(mod);
  create<SaveNonVolatile>(mod);
  create<SaveXMM128>(mod);
  create<Epilog>(mod);
  create<Spare>(mod);
}

}
