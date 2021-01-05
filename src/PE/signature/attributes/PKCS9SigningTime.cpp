#include <spdlog/fmt/fmt.h>
#include "LIEF/PE/signature/attributes/PKCS9SigningTime.hpp"
namespace LIEF {
namespace PE {

PKCS9SigningTime::PKCS9SigningTime() :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_SIGNING_TIME)
{}

PKCS9SigningTime::PKCS9SigningTime(const PKCS9SigningTime&) = default;
PKCS9SigningTime& PKCS9SigningTime::operator=(const PKCS9SigningTime&) = default;

std::unique_ptr<Attribute> PKCS9SigningTime::clone(void) const {
  return std::unique_ptr<Attribute>(new PKCS9SigningTime{*this});
}

PKCS9SigningTime::PKCS9SigningTime(time_t time) :
  Attribute(SIG_ATTRIBUTE_TYPES::PKCS9_SIGNING_TIME),
  time_{std::move(time)}
{}

void PKCS9SigningTime::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

std::string PKCS9SigningTime::print() const {
  const time_t& time = this->time();
  return fmt::format("{}/{}/{} - {}:{}:{}",
                       time[0], time[1], time[2], time[3], time[4], time[5]);
}


PKCS9SigningTime::~PKCS9SigningTime() = default;

}
}
