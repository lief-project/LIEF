set(LIEF_PE_SIGNATURE_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Attribute.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ContentInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Signature.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SignerInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/x509.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/OIDToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SignatureParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/RsaInfo.cpp"
)


set(LIEF_PE_SIGNATURE_INCLUDES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/Attribute.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/ContentInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/OIDToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/Signature.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/SignatureParser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/SignerInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/x509.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/RsaInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/PE/signature/pkcs7.h"
)

source_group("Header Files\\PE\\signature" FILES ${LIEF_PE_SIGNATURE_SRC})
source_group("Header Files\\PE\\signature" FILES ${LIEF_PE_SIGNATURE_INCLUDES})

if (LIEF_PE)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_PE_SIGNATURE_SRC}
    ${LIEF_PE_SIGNATURE_INCLUDES}
  )
endif()

include("${CMAKE_CURRENT_LIST_DIR}/attributes/CMakeLists.txt")
