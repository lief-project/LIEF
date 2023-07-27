#ifndef LIEF_PE_C_ENUMS_H_
#define LIEF_PE_C_ENUMS_H_
#include "LIEF/PE/undef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _LIEF_EN(N) LIEF_PE_##N
#define _LIEF_EN_2(N, TYPE) LIEF_PE_##N
#define _LIEF_EI(X) LIEF_PE_##X

#include "LIEF/PE/enums.inc"

#undef _LIEF_EN
#undef _LIEF_EN_2
#undef _LIEF_EI


#ifdef __cplusplus
}
#endif


#endif
