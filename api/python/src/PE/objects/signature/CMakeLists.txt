target_sources(pyLIEF PRIVATE
  pyAttribute.cpp
  pyContentInfo.cpp
  pyGenericContent.cpp
  pyPKCS9TSTInfo.cpp
  pyRsaInfo.cpp
  pySignature.cpp
  pySignerInfo.cpp
  pySpcIndirectData.cpp
  pyx509.cpp
)
add_subdirectory(attributes)
