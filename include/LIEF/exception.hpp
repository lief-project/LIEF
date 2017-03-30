/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_EXCEPTIONS_H_
#define LIEF_EXCEPTIONS_H_

#include <exception>
#include <stdexcept>
#include <string>

#include "LIEF/visibility.h"

namespace LIEF {

class DLL_PUBLIC exception : public std::exception {
  public:

    exception(const exception& other);
    explicit exception(const std::string& msg);
    explicit exception(const char* msg);
    virtual const char* what(void) const noexcept override;
    virtual ~exception() noexcept;

  protected:
    std::string msg_;

};

class DLL_PUBLIC bad_file : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC bad_format : public bad_file {
  public:
  using bad_file::bad_file;
  using bad_file::what;
};

class DLL_PUBLIC not_implemented : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC not_supported : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC integrity_error : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC read_out_of_bound : public exception {
  public:
  using exception::exception;
  using exception::what;
  explicit read_out_of_bound(uint64_t offset, uint64_t size);
  explicit read_out_of_bound(uint64_t offset);

};

class DLL_PUBLIC not_found : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC corrupted : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC conversion_error : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC type_error : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC builder_error : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC parser_error : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC pe_error : public exception {
  public:
  using exception::exception;
  using exception::what;
};

class DLL_PUBLIC pe_bad_section_name : public pe_error {
  public:
  using pe_error::pe_error;
  using pe_error::what;
};

} //namespace ELF
#endif
