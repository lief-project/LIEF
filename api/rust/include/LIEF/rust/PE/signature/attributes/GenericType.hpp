#pragma once
#include "LIEF/PE/signature/attributes/GenericType.hpp"
#include "Attribute.hpp"
#include "LIEF/rust/Span.hpp"
#include "LIEF/rust/helpers.hpp"

class PE_GenericType : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::GenericType;
  PE_GenericType(const lief_t& base) :
    PE_Attribute(base) {}

  auto oid() const {
    return to_unique_string(impl().oid());
  }
  auto raw_content() const {
    return make_span(impl().raw_content());
  }

  static auto classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const {
    return as<lief_t>(this);
  }
};
