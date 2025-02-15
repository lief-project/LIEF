target_sources(pyLIEF PRIVATE
  pyDynamicFixup.cpp
  pyDynamicFixupARM64Kernel.cpp
  pyDynamicFixupARM64X.cpp
  pyDynamicFixupControlTransfer.cpp
  pyDynamicFixupGeneric.cpp
  pyDynamicFixupUnknown.cpp
  pyDynamicRelocationBase.cpp
  pyDynamicRelocationV1.cpp
  pyDynamicRelocationV2.cpp
  pyFunctionOverride.cpp
  pyFunctionOverrideInfo.cpp
)
