#ifndef LIEF_MACHO_C_ENUMS_H_
#define LIEF_MACHO_C_ENUMS_H_
#include "LIEF/MachO/undef.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _LIEF_EN
  #undef _LIEF_EN
#endif

#ifdef _LIEF_EN_2
  #undef _LIEF_EN_2
#endif

#ifdef _LIEF_EI
  #undef _LIEF_EI
#endif

#define _LIEF_EN(N) LIEF_MACHO_##N // enum LIEF_N {
#define _LIEF_EN_2(N, TYPE) LIEF_MACHO_##N // enum LIEF_N {
#define _LIEF_EI(X) LIEF_MACHO_##X //   LIEF_X

#include "LIEF/MachO/enums.inc"

#undef _LIEF_EN
#undef _LIEF_EN_2
#undef _LIEF_EI

#ifdef __cplusplus
}
#endif


#endif
