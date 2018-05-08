#ifndef LIEF_CONVERT_H_
#define LIEF_CONVERT_H_

#include "LIEF/ELF/Structures.hpp"

namespace LIEF {
namespace Convert {

template<typename X>
void swap_endian(X *x);
}
}

#endif // LIEF_CONVERT_H_
