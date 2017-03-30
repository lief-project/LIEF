# - Run cppcheck on c++ source files as a custom target and a test
#
#  include(CppcheckTargets)
#  add_cppcheck(<target-name> [UNUSED_FUNCTIONS] [STYLE] [POSSIBLE_ERROR] [FORCE] [FAIL_ON_WARNINGS]) -
#    Create a target to check a target's sources with cppcheck and the indicated options
#  add_cppcheck_sources(<target-name> [UNUSED_FUNCTIONS] [STYLE] [POSSIBLE_ERROR] [FORCE] [FAIL_ON_WARNINGS]) -
#    Create a target to check standalone sources with cppcheck and the indicated options
#
# Requires these CMake modules:
#  Findcppcheck
#
# Requires CMake 2.6 or newer (uses the 'function' command)
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

if(__add_cppcheck)
	return()
endif()
set(__add_cppcheck YES)

if(NOT CPPCHECK_FOUND)
	find_package(cppcheck QUIET)
endif()

if(CPPCHECK_FOUND)
	if(NOT TARGET all_cppcheck)
		add_custom_target(all_cppcheck)
		set_target_properties(all_cppcheck PROPERTIES EXCLUDE_FROM_ALL TRUE)
	endif()
endif()

function(add_cppcheck_sources _targetname)
	if(CPPCHECK_FOUND)
		set(_cppcheck_args)
		set(_input ${ARGN})
		list(FIND _input UNUSED_FUNCTIONS _unused_func)
		if("${_unused_func}" GREATER "-1")
			list(APPEND _cppcheck_args ${CPPCHECK_UNUSEDFUNC_ARG})
			list(REMOVE_AT _input ${_unused_func})
		endif()

		list(FIND _input STYLE _style)
		if("${_style}" GREATER "-1")
			list(APPEND _cppcheck_args ${CPPCHECK_STYLE_ARG})
			list(REMOVE_AT _input ${_style})
		endif()

		list(FIND _input POSSIBLE_ERROR _poss_err)
		if("${_poss_err}" GREATER "-1")
			list(APPEND _cppcheck_args ${CPPCHECK_POSSIBLEERROR_ARG})
			list(REMOVE_AT _input ${_poss_err})
		endif()

		list(FIND _input FORCE _force)
		if("${_force}" GREATER "-1")
			list(APPEND _cppcheck_args "--force")
			list(REMOVE_AT _input ${_force})
		endif()

		list(FIND _input FAIL_ON_WARNINGS _fail_on_warn)
		if("${_fail_on_warn}" GREATER "-1")
			list(APPEND
				CPPCHECK_FAIL_REGULAR_EXPRESSION
				${CPPCHECK_WARN_REGULAR_EXPRESSION})
			list(REMOVE_AT _input ${_fail_on_warn})
		endif()

		set(_files)
		foreach(_source ${_input})
			get_source_file_property(_cppcheck_loc "${_source}" LOCATION)
			if(_cppcheck_loc)
				# This file has a source file property, carry on.
				get_source_file_property(_cppcheck_lang "${_source}" LANGUAGE)
				if("${_cppcheck_lang}" MATCHES "CXX")
					list(APPEND _files "${_cppcheck_loc}")
				endif()
			else()
				# This file doesn't have source file properties - figure it out.
				get_filename_component(_cppcheck_loc "${_source}" ABSOLUTE)
				if(EXISTS "${_cppcheck_loc}")
					list(APPEND _files "${_cppcheck_loc}")
				else()
					message(FATAL_ERROR
						"Adding CPPCHECK for file target ${_targetname}: "
						"File ${_source} does not exist or needs a corrected path location "
						"since we think its absolute path is ${_cppcheck_loc}")
				endif()
			endif()
		endforeach()

		if("1.${CMAKE_VERSION}" VERSION_LESS "1.2.8.0")
			# Older than CMake 2.8.0
			add_test(${_targetname}_cppcheck_test
				"${CPPCHECK_EXECUTABLE}"
				${CPPCHECK_TEMPLATE_ARG}
				${_cppcheck_args} "--inline-suppr"
				${_files})
		else()
			# CMake 2.8.0 and newer
			add_test(NAME
				${_targetname}_cppcheck_test
				COMMAND
				"${CPPCHECK_EXECUTABLE}"
				${CPPCHECK_TEMPLATE_ARG}
				${_cppcheck_args} "--inline-suppr"
				${_files})
		endif()

		set_tests_properties(${_targetname}_cppcheck_test
			PROPERTIES
			FAIL_REGULAR_EXPRESSION
			"${CPPCHECK_FAIL_REGULAR_EXPRESSION}")

		add_custom_command(TARGET
			all_cppcheck
			PRE_BUILD
			COMMAND
			${CPPCHECK_EXECUTABLE}
			${CPPCHECK_QUIET_ARG}
			${CPPCHECK_TEMPLATE_ARG}
			${_cppcheck_args} "--inline-suppr"
			${_files}
			WORKING_DIRECTORY
			"${CMAKE_CURRENT_SOURCE_DIR}"
			COMMENT
			"${_targetname}_cppcheck: Running cppcheck on target ${_targetname}..."
			VERBATIM)
	endif()
endfunction()

function(add_cppcheck _name)
	if(NOT TARGET ${_name})
		message(FATAL_ERROR
			"add_cppcheck given a target name that does not exist: '${_name}' !")
	endif()
	if(CPPCHECK_FOUND)
    set(_cppcheck_args CACHE STRING "${_cppcheck_args} ")
    #set(_cppcheck_args "${_cppcheck_args} ")
		list(FIND ARGN UNUSED_FUNCTIONS _unused_func)
		if("${_unused_func}" GREATER "-1")
			list(APPEND _cppcheck_args ${CPPCHECK_UNUSEDFUNC_ARG})
		endif()

		list(FIND ARGN STYLE _style)
		if("${_style}" GREATER "-1")
			list(APPEND _cppcheck_args ${CPPCHECK_STYLE_ARG})
		endif()

    list(FIND ARGN POSSIBLE_ERROR _poss_err)
		if("${_poss_err}" GREATER "-1")
			list(APPEND _cppcheck_args ${CPPCHECK_POSSIBLEERROR_ARG})
		endif()

		list(FIND ARGN FORCE _force)
		if("${_force}" GREATER "-1")
			list(APPEND _cppcheck_args "--force")
		endif()

		list(FIND _input FAIL_ON_WARNINGS _fail_on_warn)
		if("${_fail_on_warn}" GREATER "-1")
			list(APPEND
				CPPCHECK_FAIL_REGULAR_EXPRESSION
				${CPPCHECK_WARN_REGULAR_EXPRESSION})
			list(REMOVE_AT _input ${_unused_func})
		endif()

		get_target_property(_cppcheck_includes "${_name}" INCLUDE_DIRECTORIES)
		set(_includes)
		foreach(_include ${_cppcheck_includes})
			list(APPEND _includes "-I${_include}")
		endforeach()

		get_target_property(_cppcheck_sources "${_name}" SOURCES)
		set(_files)
		foreach(_source ${_cppcheck_sources})
			get_source_file_property(_cppcheck_lang "${_source}" LANGUAGE)
			get_source_file_property(_cppcheck_loc "${_source}" LOCATION)
			if("${_cppcheck_lang}" MATCHES "CXX")
				list(APPEND _files "${_cppcheck_loc}")
			endif()
		endforeach()

		if("1.${CMAKE_VERSION}" VERSION_LESS "1.2.8.0")
			# Older than CMake 2.8.0
			add_test(${_name}_cppcheck_test
				"${CPPCHECK_EXECUTABLE}"
				${CPPCHECK_TEMPLATE_ARG}
				${_cppcheck_args} "--inline-suppr"
				${_files})
		else()
			# CMake 2.8.0 and newer
			add_test(NAME
				${_name}_cppcheck_test
				COMMAND
				"${CPPCHECK_EXECUTABLE}"
				${CPPCHECK_TEMPLATE_ARG}
				${_cppcheck_args} "--inline-suppr"
				${_files})
		endif()

		set_tests_properties(${_name}_cppcheck_test
			PROPERTIES
			FAIL_REGULAR_EXPRESSION
			"${CPPCHECK_FAIL_REGULAR_EXPRESSION}")
    MESSAGE(STATUS "CPPCHECKargs: ${_cppcheck_args}")
		add_custom_command(TARGET
			all_cppcheck
			PRE_BUILD
			COMMAND
			${CPPCHECK_EXECUTABLE}
			${CPPCHECK_QUIET_ARG}
			${CPPCHECK_TEMPLATE_ARG}
			${_cppcheck_args} "--inline-suppr"
			${_includes}
			${_files}
			WORKING_DIRECTORY
			"${CMAKE_CURRENT_SOURCE_DIR}"
			COMMENT
			"${_name}_cppcheck: Running cppcheck on target ${_name}..."
			VERBATIM)
	endif()

endfunction()
