#ifndef PY_LIEF_ASM_AARCH64_INIT_H
#define PY_LIEF_ASM_AARCH64_INIT_H
#include "pyLIEF.hpp"

namespace LIEF::assembly::aarch64::py {
void init(nb::module_& m);

template<class T>
void create(nb::module_&);

}
#endif
