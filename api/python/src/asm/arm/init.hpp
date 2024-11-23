#ifndef PY_LIEF_ASM_ARM_INIT_H
#define PY_LIEF_ASM_ARM_INIT_H
#include "pyLIEF.hpp"

namespace LIEF::assembly::arm::py {
void init(nb::module_& m);

template<class T>
void create(nb::module_&);

}
#endif
