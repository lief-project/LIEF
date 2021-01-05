#include "LIEF/PE/signature/attributes/PKCS9AtSequenceNumber.hpp"

namespace LIEF {
namespace PE {

PKCS9AtSequenceNumber::PKCS9AtSequenceNumber() :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_AT_SEQUENCE_NUMBER)
{}

PKCS9AtSequenceNumber::PKCS9AtSequenceNumber(const PKCS9AtSequenceNumber&) = default;
PKCS9AtSequenceNumber& PKCS9AtSequenceNumber::operator=(const PKCS9AtSequenceNumber&) = default;

std::unique_ptr<Attribute> PKCS9AtSequenceNumber::clone(void) const {
  return std::unique_ptr<Attribute>(new PKCS9AtSequenceNumber{*this});
}

PKCS9AtSequenceNumber::PKCS9AtSequenceNumber(uint32_t num) :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_AT_SEQUENCE_NUMBER),
  number_{num}
{}

void PKCS9AtSequenceNumber::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string PKCS9AtSequenceNumber::print() const {
  return std::to_string(this->number());
}


PKCS9AtSequenceNumber::~PKCS9AtSequenceNumber() = default;

}
}
