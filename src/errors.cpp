#include "LIEF/errors.hpp"

const std::error_category& lief_error_category() {
  struct category: std::error_category {
    const char* name() const noexcept override {
      return "LIEF";
    }

    std::string message(int code) const override {
      switch (lief_errors(code)) {
        case lief_errors::read_error:        return "read_error";
        case lief_errors::not_found:         return "not_found";
        case lief_errors::not_implemented:   return "not_implemented";
        case lief_errors::not_supported:     return "not_supported";
        case lief_errors::corrupted:         return "corrupted";
        case lief_errors::conversion_error:  return "conversion_error";
        case lief_errors::read_out_of_bound: return "read_out_of_bound";
        case lief_errors::asn1_bad_tag:      return "asn1_bad_tag";
        case lief_errors::file_error:        return "file_error";
        default: return "error";
      }
    }
  };

  static category c;
  return c;
}


LIEF::error_t LIEF::return_error(lief_errors e) {
  return boost::leaf::new_error(e);
}
