#ifndef LIEF_ELF_C_ENUMS_H_
#define LIEF_ELF_C_ENUMS_H_
#include "LIEF/ELF/undef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _LIEF_EN(N) LIEF_ELF_##N // enum LIEF_N {
#define _LIEF_EN_2(N, TYPE) LIEF_ELF_##N // enum LIEF_N {
#define _LIEF_EI(X) LIEF_ELF_##X //   LIEF_X

#include "LIEF/ELF/enums.inc"

#undef _LIEF_EN
#undef _LIEF_EN_2
#undef _LIEF_EI

#ifdef __cplusplus
}
#endif


#endif
