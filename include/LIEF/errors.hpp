/* Copyright 2021 - 2022 R. Thomas
 * Copyright 2021 - 2022 Quarkslab
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
#ifndef LIEF_ERROR_H_
#define LIEF_ERROR_H_
#include <system_error>
#include <LIEF/third-party/leaf.hpp>

//! LIEF error codes definition
enum class lief_errors {
  read_error = 1,
  not_found,
  not_implemented,
  not_supported,

  corrupted,
  conversion_error,

  read_out_of_bound,
  asn1_bad_tag,
  file_error,

  file_format_error,
  parsing_error,
  build_error,

  data_too_large,
  /*
   * When adding a new error, do not forget
   * to update the Python bindings as well (pyErr.cpp)
   *
   */
};

const std::error_category& error_category();
std::error_code make_error_code(lief_errors e);

namespace std {
  template<>
  struct is_error_code_enum<lief_errors>: std::true_type
  {};
}

const std::error_category& lief_error_category();

//! Create an standard error code from lief_errors
inline std::error_code make_error_code(lief_errors e) {
  return std::error_code(int(e), lief_error_category());
}


namespace LIEF {
//! Wrapper that contains an Object (``T``) or an error
//!
//! The LEAF implementation exposes the method ``value()`` to access the underlying object (if no error)
//!
//! Typical usage is:
//!
//! \code{.cpp}
//! result<int> intval = my_function();
//! if (intval) {
//!  int val = intval.value();
//! } else { // There is an error
//!  std::cout << get_error(intval).message() << "\n";
//! }
//! \endcode
//!
//! See https://boostorg.github.io/leaf/ for more details
template<typename T>
using result = boost::leaf::result<T>;

//! Abstraction over the implementation
template<typename T>
using error_result_t = typename result<T>::error_resul;

//! Abstraction over the implementation
using error_t = boost::leaf::error_id;

//! Create an error_t from a lief_errors
error_t return_error(lief_errors);

//! Get the error code associated with the result
template<class T>
std::error_code get_error(result<T>& err) {
  return make_error_code(lief_errors(boost::leaf::error_id(err.error()).value()));
}

//! Return the lief_errors when the provided ``result<T>`` is an error
template<class T>
lief_errors as_lief_err(result<T>& err) {
  return lief_errors(boost::leaf::error_id(err.error()).value());
}

//! Opaque structure used by ok_error_t
struct ok_t {};

//! Return success for function with return type ok_error_t.
inline ok_t ok() {
  return ok_t{};
}

//! Opaque structure that is used by LIEF to avoid
//! writing ``result<void> f(...)``. Instead, it makes the output
//! explicit such as:
//!
//! \code{.cpp}
//! ok_error_t process() {
//!   if (fail) {
//!     return make_error_code(...);
//!   }
//!   return ok();
//! }
//! \endcode
using ok_error_t = result<ok_t>;

}





#endif
