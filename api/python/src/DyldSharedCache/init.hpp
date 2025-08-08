#ifndef PY_LIEF_DSC_INIT_H
#define PY_LIEF_DSC_INIT_H
#include "pyLIEF.hpp"

namespace LIEF::dsc::py {
void init(nb::module_& m);
void init_utils(nb::module_& m);
}
#endif
