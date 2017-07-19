find_package(Doxygen)
find_program(SPHINX_BUILD_BIN NAMES sphinx-build)

if(NOT DOXYGEN_FOUND)
    message(STATUS "Doc disabled: doxygen not found")
elseif(NOT SPHINX_BUILD_BIN)
    message(STATUS "Doc disabled: sphinx-build not found")
elseif(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
  message(STATUS "You have to build the doc in another directory !")
else()
    configure_file(
      ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/Doxyfile.in
      ${CMAKE_CURRENT_BINARY_DIR}/doxygen/Doxyfile @ONLY)

    configure_file(
      ${CMAKE_CURRENT_SOURCE_DIR}/sphinx/conf.py.in
      ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/conf.py @ONLY)

    file(GLOB PACKER_DOC_RST RELATIVE
      "${CMAKE_CURRENT_SOURCE_DIR}/sphinx"
      "${CMAKE_CURRENT_SOURCE_DIR}/sphinx/*.rst")

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/sphinx/
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src
      PATTERN "*.in" EXCLUDE)

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/sphinx/_static
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static
    )

    ###################
    # FIND PACKAGE
    ####################

    file(
      COPY ${CMAKE_SOURCE_DIR}/examples/cmake/find_package/CMakeLists.txt
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/
    )

    file(
      RENAME ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/CMakeLists.txt
      ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/CMakeFindPackage.cmake
    )

    # Find Package Readme
    file(
      COPY ${CMAKE_SOURCE_DIR}/examples/cmake/find_package/README.rst
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/
    )

    file(
      RENAME ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/README.rst
      ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/ReadmeFindPackage.rst
    )

    ####################
    # EXTERNAL PROJECT
    ####################

    file(
      COPY ${CMAKE_SOURCE_DIR}/examples/cmake/external_project/CMakeLists.txt
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/
    )

    file(
      RENAME ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/CMakeLists.txt
      ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/CMakeExternalProject.cmake
    )

    file(
      COPY ${CMAKE_SOURCE_DIR}/examples/cmake/external_project/README.rst
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/
    )

    file(
      RENAME ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/README.rst
      ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src/_static/ReadmeExternalProject.rst
    )

    ####################

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html
      PATTERN "*.css")

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html
      PATTERN "*.js")

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/fonts
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html
      )

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/js
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html
      )

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/css
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen/html
      )

    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/header.html
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen)


    file(
      COPY ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/footer.html
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen)

    file(
      COPY ${CMAKE_SOURCE_DIR}/README.md
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/doxygen
    )

  add_custom_target(doc-lief ALL
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/doxygen/Doxyfile
      COMMAND ${CMAKE_COMMAND} -E env "PYTHONPATH=${PROJECT_BINARY_DIR}/api/python:$ENV{PYTHONPATH}" ${SPHINX_BUILD_BIN} ${CMAKE_CURRENT_BINARY_DIR}/sphinx-src sphinx-doc
      DEPENDS pyLIEF LIB_LIEF_STATIC
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating documentation with Doxygen and Sphinx" VERBATIM)

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
