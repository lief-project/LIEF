#include <sstream>

#include "LIEF/PE/signature/attributes/MsSpcNestedSignature.hpp"

namespace LIEF {
namespace PE {

MsSpcNestedSignature::MsSpcNestedSignature() :
  Attribute(SIG_ATTRIBUTE_TYPES::MS_SPC_NESTED_SIGN)
{}

MsSpcNestedSignature::MsSpcNestedSignature(const MsSpcNestedSignature&) = default;
MsSpcNestedSignature& MsSpcNestedSignature::operator=(const MsSpcNestedSignature&) = default;

MsSpcNestedSignature::MsSpcNestedSignature(Signature sig) :
  Attribute(SIG_ATTRIBUTE_TYPES::MS_SPC_NESTED_SIGN),
  sig_{std::move(sig)}
{}

std::unique_ptr<Attribute> MsSpcNestedSignature::clone(void) const {
  return std::unique_ptr<Attribute>(new MsSpcNestedSignature{*this});
}


void MsSpcNestedSignature::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string MsSpcNestedSignature::print() const {
  std::ostringstream oss;
  oss << "Nested signature:\n";
  oss << this->sig();
  return oss.str();
}


MsSpcNestedSignature::~MsSpcNestedSignature() = default;

}
}
