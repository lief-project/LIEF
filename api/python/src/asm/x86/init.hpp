#ifndef PY_LIEF_ASM_X86_INIT_H
#define PY_LIEF_ASM_X86_INIT_H
#include "pyLIEF.hpp"

namespace LIEF::assembly::x86::py {
void init(nb::module_& m);

template<class T>
void create(nb::module_&);

}
#endif
