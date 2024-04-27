#pragma once
#include "LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"
#include "LIEF/rust/PE/signature/Signature.hpp"
#include "LIEF/rust/PE/signature/attributes/Attribute.hpp"

class PE_MsSpcNestedSignature : public PE_Attribute {
  public:
  using lief_t = LIEF::PE::MsSpcNestedSignature;
  PE_MsSpcNestedSignature(const lief_t& base) : PE_Attribute(base) {}

  auto sig() const {
    return std::make_unique<PE_Signature>(impl().sig());
  }

  static bool classof(const PE_Attribute& attr) {
    return lief_t::classof(&attr.get());
  }

  private:
  const lief_t& impl() const { return as<lief_t>(this); }
};
