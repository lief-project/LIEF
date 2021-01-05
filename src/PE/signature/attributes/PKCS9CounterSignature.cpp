#include "LIEF/PE/signature/attributes/PKCS9CounterSignature.hpp"
#include <sstream>
namespace LIEF {
namespace PE {

PKCS9CounterSignature::PKCS9CounterSignature() :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_COUNTER_SIGNATURE)
{}

PKCS9CounterSignature::PKCS9CounterSignature(const PKCS9CounterSignature&) = default;
PKCS9CounterSignature& PKCS9CounterSignature::operator=(const PKCS9CounterSignature&) = default;

PKCS9CounterSignature::PKCS9CounterSignature(std::vector<SignerInfo> signers) :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_COUNTER_SIGNATURE),
  signers_{std::move(signers)}
{}

std::unique_ptr<Attribute> PKCS9CounterSignature::clone(void) const {
  return std::unique_ptr<Attribute>(new PKCS9CounterSignature{*this});
}


void PKCS9CounterSignature::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string PKCS9CounterSignature::print() const {
  std::ostringstream oss;
  it_const_signers_t signers = this->signers();
  oss << std::to_string(signers.size()) << " signer(s): \n";
  for (const SignerInfo& signer : signers) {
    oss << signer << "\n";
  }
  return oss.str();
}


PKCS9CounterSignature::~PKCS9CounterSignature() = default;

}
}
