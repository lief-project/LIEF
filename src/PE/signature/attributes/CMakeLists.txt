set(LIEF_PE_SIGNATURE_ATTRIBUTES_SRC
  "${CMAKE_CURRENT_LIST_DIR}/GenericType.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ContentType.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/SpcSpOpusInfo.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/MsCounterSign.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MsSpcNestedSignature.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MsSpcStatementType.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/PKCS9AtSequenceNumber.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PKCS9CounterSignature.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PKCS9MessageDigest.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PKCS9SigningTime.cpp"
)

set(LIEF_PE_SIGNATURE_ATTRIBUTES_INCLUDES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/GenericType.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/ContentType.hpp"

  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/SpcSpOpusInfo.hpp"

  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/MsCounterSign.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/MsSpcStatementType.hpp"

  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/PKCS9CounterSignature.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"
)

source_group("Header Files\\PE\\signature\\attributes" FILES ${LIEF_PE_SIGNATURE_ATTRIBUTES_SRC})
source_group("Header Files\\PE\\signature\\attributes" FILES ${LIEF_PE_SIGNATURE_ATTRIBUTES_INCLUDES})

if (LIEF_PE)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_PE_SIGNATURE_ATTRIBUTES_SRC}
    ${LIEF_PE_SIGNATURE_ATTRIBUTES_INCLUDES}
  )
endif()

