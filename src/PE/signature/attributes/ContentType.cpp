#include "LIEF/PE/signature/attributes/ContentType.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"

namespace LIEF {
namespace PE {

ContentType::ContentType() :
  Attribute(SIG_ATTRIBUTE_TYPES::CONTENT_TYPE)
{}

ContentType::ContentType(const ContentType&) = default;
ContentType& ContentType::operator=(const ContentType&) = default;

std::unique_ptr<Attribute> ContentType::clone(void) const {
  return std::unique_ptr<Attribute>(new ContentType{*this});
}

ContentType::ContentType(oid_t oid) :
  Attribute(SIG_ATTRIBUTE_TYPES::CONTENT_TYPE),
  oid_{std::move(oid)}
{}

void ContentType::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string ContentType::print() const {
  return this->oid() + " (" + oid_to_string(this->oid()) + ")";
}


ContentType::~ContentType() = default;


}
}
