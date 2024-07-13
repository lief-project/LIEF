#ifndef PY_LIEF_OBJC_H
#define PY_LIEF_OBJC_H
#include "pyLIEF.hpp"

namespace LIEF::objc::py {

namespace objc = LIEF::objc;

template<class T>
void create(nb::module_&);
}
#endif
