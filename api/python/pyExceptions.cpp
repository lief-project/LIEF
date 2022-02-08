/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pyLIEF.hpp"
#include "LIEF/exception.hpp"

void init_LIEF_exceptions(py::module& m) {
  auto& exception = py::register_exception<LIEF::exception>(m, "exception");
  auto& bad_file  = py::register_exception<LIEF::bad_file>(m, "bad_file", exception.ptr());
  py::register_exception<LIEF::bad_format>(m, "bad_format", bad_file.ptr());
  py::register_exception<LIEF::not_implemented>(m, "not_implemented", exception.ptr());
  py::register_exception<LIEF::not_supported>(m, "not_supported", exception.ptr());
  py::register_exception<LIEF::read_out_of_bound>(m, "read_out_of_bound", exception.ptr());
  py::register_exception<LIEF::integrity_error>(m, "integrity_error", exception.ptr());
  py::register_exception<LIEF::not_found>(m, "not_found", exception.ptr());
  py::register_exception<LIEF::corrupted>(m, "corrupted", exception.ptr());
  py::register_exception<LIEF::conversion_error>(m, "conversion_error", exception.ptr());
  py::register_exception<LIEF::type_error>(m, "type_error", exception.ptr());
  py::register_exception<LIEF::builder_error>(m, "builder_error", exception.ptr());
  py::register_exception<LIEF::parser_error>(m, "parser_error", exception.ptr());
  auto& pe_error = py::register_exception<LIEF::pe_error>(m, "pe_error", exception.ptr());
  py::register_exception<LIEF::pe_bad_section_name>(m, "pe_bad_section_name", pe_error.ptr());
}
