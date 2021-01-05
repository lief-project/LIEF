#include "LIEF/PE/signature/attributes/PKCS9MessageDigest.hpp"
#include "LIEF/utils.hpp"

namespace LIEF {
namespace PE {

PKCS9MessageDigest::PKCS9MessageDigest() :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST)
{}

PKCS9MessageDigest::PKCS9MessageDigest(const PKCS9MessageDigest&) = default;
PKCS9MessageDigest& PKCS9MessageDigest::operator=(const PKCS9MessageDigest&) = default;

PKCS9MessageDigest::PKCS9MessageDigest(std::vector<uint8_t> digest) :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_MESSAGE_DIGEST),
  digest_{std::move(digest)}
{}

std::unique_ptr<Attribute> PKCS9MessageDigest::clone(void) const {
  return std::unique_ptr<Attribute>(new PKCS9MessageDigest{*this});
}


void PKCS9MessageDigest::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string PKCS9MessageDigest::print() const {
  return hex_dump(this->digest());
}


PKCS9MessageDigest::~PKCS9MessageDigest() = default;

}
}
