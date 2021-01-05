#include "LIEF/PE/signature/attributes/MsSpcStatementType.hpp"
#include "LIEF/PE/signature/OIDToString.hpp"
namespace LIEF {
namespace PE {

MsSpcStatementType::MsSpcStatementType() :
  Attribute(SIG_ATTRIBUTE_TYPES::MS_SPC_STATEMENT_TYPE)
{}

MsSpcStatementType::MsSpcStatementType(const MsSpcStatementType&) = default;
MsSpcStatementType& MsSpcStatementType::operator=(const MsSpcStatementType&) = default;

std::unique_ptr<Attribute> MsSpcStatementType::clone(void) const {
  return std::unique_ptr<Attribute>(new MsSpcStatementType{*this});
}

MsSpcStatementType::MsSpcStatementType(oid_t oid) :
  Attribute(SIG_ATTRIBUTE_TYPES::MS_SPC_STATEMENT_TYPE),
  oid_{std::move(oid)}
{}

void MsSpcStatementType::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string MsSpcStatementType::print() const {
  return this->oid() + " (" + oid_to_string(this->oid()) + ")";
}


MsSpcStatementType::~MsSpcStatementType() = default;

}
}
