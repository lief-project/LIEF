#pragma once
#include "LIEF/PE/signature/attributes/MsSpcStatementType.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_MsSpcStatementType : public PE_Attribute {
  using lief_t = LIEF::PE::MsSpcStatementType;
  public:
  PE_MsSpcStatementType(const lief_t& base) : PE_Attribute(base) {}

  std::string oid() const {
    return impl().oid();
  }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
