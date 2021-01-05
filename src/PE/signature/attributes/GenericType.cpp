#include "LIEF/PE/signature/attributes/GenericType.hpp"
namespace LIEF {
namespace PE {

GenericType::GenericType() :
  Attribute(SIG_ATTRIBUTE_TYPES::GENERIC_TYPE)
{}

GenericType::GenericType(const GenericType&) = default;
GenericType& GenericType::operator=(const GenericType&) = default;

std::unique_ptr<Attribute> GenericType::clone(void) const {
  return std::unique_ptr<Attribute>(new GenericType{*this});
}

GenericType::GenericType(oid_t oid, std::vector<uint8_t> raw) :
  Attribute(SIG_ATTRIBUTE_TYPES::GENERIC_TYPE),
  oid_{std::move(oid)},
  raw_{std::move(raw)}
{}

void GenericType::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string GenericType::print() const {
  return this->oid() + " (" + std::to_string(this->raw_content().size()) + " bytes)";
}


GenericType::~GenericType() = default;

}
}
