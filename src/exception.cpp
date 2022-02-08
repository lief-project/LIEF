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
#include <sstream>
#include <utility>

#include "LIEF/exception.hpp"
#include "logging.hpp"
#include "LIEF/config.h"


namespace LIEF {
exception::exception(const exception&) = default;
exception::~exception() noexcept = default;

exception::exception(std::string msg) : msg_{std::move(msg)} {

#if defined(LIEF_LOGGING_SUPPORT)
//std::ostringstream oss;
//oss << std::endl << el::base::debug::StackTrace();
//this->msg_ += oss.str();
#endif

}
exception::exception(const char* msg) : msg_{msg} {
#if defined(LIEF_LOGGING_SUPPORT)
//std::ostringstream oss;
//oss << std::endl << el::base::debug::StackTrace();
//this->msg_ += oss.str();
#endif
}

const char* exception::what() const noexcept {
  return this->msg_.c_str();
}


read_out_of_bound::read_out_of_bound(uint64_t offset, uint64_t size) : LIEF::exception("") {
  std::ostringstream oss;
  oss << "Try to read 0x" << std::hex << size
      << " bytes from 0x" << std::hex << offset
      << " (" << std::hex << offset + size << ") which is bigger than the binary's size";
  this->msg_ += oss.str();
}

read_out_of_bound::read_out_of_bound(uint64_t offset) : LIEF::exception("") {
  std::ostringstream oss;
  oss << "Offset: 0x" << std::hex << offset << " is bigger than the binary size";
  this->msg_ += oss.str();
}

}
