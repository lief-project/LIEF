#pragma once
#include "LIEF/PE/signature/attributes/GenericType.hpp"
#include "Attribute.hpp"

class PE_GenericType : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::GenericType;
  PE_GenericType(const lief_t& base) : PE_Attribute(base) {}

  std::string oid() const {
    return impl().oid();
  }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
