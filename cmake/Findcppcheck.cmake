# - try to find cppcheck tool
#
# Cache Variables:
#  CPPCHECK_EXECUTABLE
#
# Non-cache variables you might use in your CMakeLists.txt:
#  CPPCHECK_FOUND
#  CPPCHECK_POSSIBLEERROR_ARG
#  CPPCHECK_UNUSEDFUNC_ARG
#  CPPCHECK_STYLE_ARG
#  CPPCHECK_QUIET_ARG
#  CPPCHECK_INCLUDEPATH_ARG
#  CPPCHECK_FAIL_REGULAR_EXPRESSION
#  CPPCHECK_WARN_REGULAR_EXPRESSION
#  CPPCHECK_MARK_AS_ADVANCED - whether to mark our vars as advanced even
#    if we don't find this program.
#
# Requires these CMake modules:
#  FindPackageHandleStandardArgs (known included with CMake >=2.6.2)
#
# Original Author:
# 2009-2010 Ryan Pavlik <rpavlik@iastate.edu> <abiryan@ryand.net>
# http://academic.cleardefinition.com
# Iowa State University HCI Graduate Program/VRAC
#
# Copyright Iowa State University 2009-2010.
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

file(TO_CMAKE_PATH "${CPPCHECK_ROOT_DIR}" CPPCHECK_ROOT_DIR)
set(CPPCHECK_ROOT_DIR
	"${CPPCHECK_ROOT_DIR}"
	CACHE
	PATH
	"Path to search for cppcheck")

# cppcheck app bundles on Mac OS X are GUI, we want command line only
set(_oldappbundlesetting ${CMAKE_FIND_APPBUNDLE})
set(CMAKE_FIND_APPBUNDLE NEVER)

if(CPPCHECK_EXECUTABLE AND NOT EXISTS "${CPPCHECK_EXECUTABLE}")
	set(CPPCHECK_EXECUTABLE "notfound" CACHE PATH FORCE "")
endif()

# If we have a custom path, look there first.
if(CPPCHECK_ROOT_DIR)
	find_program(CPPCHECK_EXECUTABLE
		NAMES
		cppcheck
		cli
		PATHS
		"${CPPCHECK_ROOT_DIR}"
		PATH_SUFFIXES
		cli
		NO_DEFAULT_PATH)
endif()

find_program(CPPCHECK_EXECUTABLE NAMES cppcheck)

# Restore original setting for appbundle finding
set(CMAKE_FIND_APPBUNDLE ${_oldappbundlesetting})

# Find out where our test file is
get_filename_component(_cppcheckmoddir ${CMAKE_CURRENT_LIST_FILE} PATH)
set(_cppcheckdummyfile "${_cppcheckmoddir}/Findcppcheck.cpp")
if(NOT EXISTS "${_cppcheckdummyfile}")
	message(FATAL_ERROR
		"Missing file ${_cppcheckdummyfile} - should be alongside Findcppcheck.cmake, can be found at https://github.com/rpavlik/cmake-modules")
endif()

function(_cppcheck_test_arg _resultvar _arg)
	if(NOT CPPCHECK_EXECUTABLE)
		set(${_resultvar} NO)
		return()
	endif()
	execute_process(COMMAND
		"${CPPCHECK_EXECUTABLE}"
		"${_arg}"
		"--quiet"
		"${_cppcheckdummyfile}"
		RESULT_VARIABLE
		_cppcheck_result
		OUTPUT_QUIET
		ERROR_QUIET)
	if("${_cppcheck_result}" EQUAL 0)
		set(${_resultvar} YES PARENT_SCOPE)
	else()
		set(${_resultvar} NO PARENT_SCOPE)
	endif()
endfunction()

function(_cppcheck_set_arg_var _argvar _arg)
	if("${${_argvar}}" STREQUAL "")
		_cppcheck_test_arg(_cppcheck_arg "${_arg}")
		if(_cppcheck_arg)
			set(${_argvar} "${_arg}" PARENT_SCOPE)
		endif()
	endif()
endfunction()

if(CPPCHECK_EXECUTABLE)

	# Check for the two types of command line arguments by just trying them
	_cppcheck_set_arg_var(CPPCHECK_STYLE_ARG "--enable=style")
	_cppcheck_set_arg_var(CPPCHECK_STYLE_ARG "--style")
	if("${CPPCHECK_STYLE_ARG}" STREQUAL "--enable=style")

		_cppcheck_set_arg_var(CPPCHECK_UNUSEDFUNC_ARG
			"--enable=unusedFunction")
		_cppcheck_set_arg_var(CPPCHECK_INFORMATION_ARG "--enable=information")
		_cppcheck_set_arg_var(CPPCHECK_MISSINGINCLUDE_ARG
			"--enable=missingInclude")
		_cppcheck_set_arg_var(CPPCHECK_POSIX_ARG "--enable=posix")
		_cppcheck_set_arg_var(CPPCHECK_POSSIBLEERROR_ARG
			"--enable=possibleError")
		_cppcheck_set_arg_var(CPPCHECK_POSSIBLEERROR_ARG "--enable=all")

		if(MSVC)
			set(CPPCHECK_TEMPLATE_ARG --template vs)
			set(CPPCHECK_FAIL_REGULAR_EXPRESSION "[(]error[)]")
			set(CPPCHECK_WARN_REGULAR_EXPRESSION "[(]style[)]")
		elseif(CMAKE_COMPILER_IS_GNUCXX)
			set(CPPCHECK_TEMPLATE_ARG --template gcc)
			set(CPPCHECK_FAIL_REGULAR_EXPRESSION " error: ")
			set(CPPCHECK_WARN_REGULAR_EXPRESSION " style: ")
		else()
			set(CPPCHECK_TEMPLATE_ARG --template gcc)
			set(CPPCHECK_FAIL_REGULAR_EXPRESSION " error: ")
			set(CPPCHECK_WARN_REGULAR_EXPRESSION " style: ")
		endif()
	elseif("${CPPCHECK_STYLE_ARG}" STREQUAL "--style")
		# Old arguments
		_cppcheck_set_arg_var(CPPCHECK_UNUSEDFUNC_ARG "--unused-functions")
		_cppcheck_set_arg_var(CPPCHECK_POSSIBLEERROR_ARG "--all")
		set(CPPCHECK_FAIL_REGULAR_EXPRESSION "error:")
		set(CPPCHECK_WARN_REGULAR_EXPRESSION "[(]style[)]")
	else()
		# No idea - some other issue must be getting in the way
		message(STATUS
			"WARNING: Can't detect whether CPPCHECK wants new or old-style arguments!")
	endif()

	set(CPPCHECK_QUIET_ARG "--quiet")
	set(CPPCHECK_INCLUDEPATH_ARG "-I")

endif()

set(CPPCHECK_ALL
	"${CPPCHECK_EXECUTABLE} ${CPPCHECK_POSSIBLEERROR_ARG} ${CPPCHECK_UNUSEDFUNC_ARG} ${CPPCHECK_STYLE_ARG} ${CPPCHECK_QUIET_ARG} ${CPPCHECK_INCLUDEPATH_ARG} some/include/path")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(cppcheck
	DEFAULT_MSG
	CPPCHECK_ALL
	CPPCHECK_EXECUTABLE
	CPPCHECK_POSSIBLEERROR_ARG
	CPPCHECK_UNUSEDFUNC_ARG
	CPPCHECK_STYLE_ARG
	CPPCHECK_INCLUDEPATH_ARG
	CPPCHECK_QUIET_ARG)

if(CPPCHECK_FOUND OR CPPCHECK_MARK_AS_ADVANCED)
	mark_as_advanced(CPPCHECK_ROOT_DIR)
endif()

mark_as_advanced(CPPCHECK_EXECUTABLE)
