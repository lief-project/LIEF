#ifndef LIEF_ERROR_H_
#define LIEF_ERROR_H_
#include <system_error>
#include <LIEF/third-party/boost/leaf/all.hpp>

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


//! Wrapper that contains an Object or an error
//!
//! The LEAF implementation exposes the method ``value()`` to access the underlying object (if no error)
//!
//! Typical usage is:
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

}





#endif
