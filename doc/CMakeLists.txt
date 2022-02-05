find_package(Doxygen)
find_package(Sphinx)

if(NOT DOXYGEN_FOUND)
  message(STATUS "Doc disabled: doxygen not found")
elseif(NOT SPHINX_FOUND)
  message(FATAL "Doc disabled: sphinx-build not found")
elseif(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
  message(STATUS "You have to build the doc in another directory !")
else()
  message(STATUS "Sphinx: ${SPHINX_EXECUTABLE}")
  add_custom_target(lief-doxygen
      COMMAND
        ${CMAKE_COMMAND} -E env
          "LIEF_VERSION=${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH}-${LIEF_COMMIT_HASH}"
          "LIEF_INPUT=${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include/LIEF ${CMAKE_SOURCE_DIR}/api/c/include ${CMAKE_SOURCE_DIR}/doc/doxygen/"
          "LIEF_EXCLUDE=${CMAKE_BINARY_DIR}/include/LIEF/third-party"
          "LIEF_INCLUDE_PATH=${CMAKE_BINARY_DIR}/include ${CMAKE_SOURCE_DIR}/include"
          "LIEF_DOXYGEN_WARN_FILE=${CMAKE_BINARY_DIR}/doxygen-warn.log"
        ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/doc/doxygen/Doxyfile
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating Doxygen documentation" VERBATIM)

  add_custom_target(lief-sphinx
      COMMAND ${CMAKE_COMMAND} -E env
        "PYTHONPATH=${CMAKE_SOURCE_DIR}:${CMAKE_BINARY_DIR}/../:${CMAKE_BINARY_DIR}/api/python:$ENV{PYTHONPATH}"
        "LIEF_DOXYGEN_XML=${CMAKE_CURRENT_BINARY_DIR}/doxygen/xml/"
        ${SPHINX_EXECUTABLE} -a -E -j4 -w ${CMAKE_BINARY_DIR}/sphinx-warn.log ${CMAKE_SOURCE_DIR}/doc/sphinx sphinx-doc
        DEPENDS pyLIEF lief-doxygen
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating Sphinx Documentation" VERBATIM)

  add_custom_target(lief-doc ALL
      DEPENDS lief-sphinx lief-doxygen
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating documentation with Doxygen and Sphinx" VERBATIM)

  add_custom_target(lief-quick-sphinx
      COMMAND ${CMAKE_COMMAND} -E env
        "PYTHONPATH=${CMAKE_SOURCE_DIR}:${CMAKE_BINARY_DIR}/../:${CMAKE_BINARY_DIR}/api/python:$ENV{PYTHONPATH}"
        "LIEF_DOXYGEN_XML=${CMAKE_CURRENT_BINARY_DIR}/doxygen/xml/"
        "FORCE_RTD_THEME=0"
        ${SPHINX_EXECUTABLE} -j4 -w ${CMAKE_BINARY_DIR}/sphinx-warn.log ${CMAKE_SOURCE_DIR}/doc/sphinx sphinx-doc
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating Sphinx documentation quickly" VERBATIM)

    install(
      DIRECTORY
      ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html/
      DESTINATION
      share/LIEF/doc/doxygen
      COMPONENT doc)

    install(
      DIRECTORY
      ${CMAKE_CURRENT_BINARY_DIR}/sphinx-doc/
      DESTINATION
      share/LIEF/doc/sphinx
      COMPONENT doc)
endif()
