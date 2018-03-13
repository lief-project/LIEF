/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstring>
#include <iomanip>
#include <numeric>
#include <sstream>

#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1.h"
#include <mbedtls/oid.h>

#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/x509.hpp"

namespace LIEF {
namespace PE {

x509::x509(void) :
  x509_cert_{nullptr}
{}


x509::x509(mbedtls_x509_crt* ca) :
  x509_cert_{ca}
{}

x509::x509(const x509& other) :
  Object::Object{other}
{
  mbedtls_x509_crt* crt = new mbedtls_x509_crt{};
  mbedtls_x509_crt_init(crt);
  mbedtls_x509_crt_parse_der(crt, other.x509_cert_->raw.p, other.x509_cert_->raw.len);

  this->x509_cert_ = crt;

}

x509& x509::operator=(x509 other) {
  this->swap(other);
  return *this;
}


void x509::swap(x509& other) {
  std::swap(this->x509_cert_, other.x509_cert_);
}

uint32_t x509::version(void) const {
  return this->x509_cert_->version;
}

std::vector<uint8_t> x509::serial_number(void) const {
  return {this->x509_cert_->serial.p, this->x509_cert_->serial.p + this->x509_cert_->serial.len};
}

oid_t x509::signature_algorithm(void) const {
  char oid_str[256];
  mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &this->x509_cert_->sig_oid);
  return oid_t{oid_str};

}

x509::date_t x509::valid_from(void) const {
  return {{
    this->x509_cert_->valid_from.year,
    this->x509_cert_->valid_from.mon,
    this->x509_cert_->valid_from.day,
    this->x509_cert_->valid_from.hour,
    this->x509_cert_->valid_from.min,
    this->x509_cert_->valid_from.sec
  }};
}

x509::date_t x509::valid_to(void) const {
  return {{
    this->x509_cert_->valid_to.year,
    this->x509_cert_->valid_to.mon,
    this->x509_cert_->valid_to.day,
    this->x509_cert_->valid_to.hour,
    this->x509_cert_->valid_to.min,
    this->x509_cert_->valid_to.sec
  }};
}


std::string x509::issuer(void) const {
  char buffer[1024];
  mbedtls_x509_dn_gets(buffer, sizeof(buffer), &this->x509_cert_->issuer);
  return {buffer};
}

std::string x509::subject(void) const {
  char buffer[1024];
  mbedtls_x509_dn_gets(buffer, sizeof(buffer), &this->x509_cert_->subject);
  return {buffer};
}


void x509::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

x509::~x509(void) {
  mbedtls_x509_crt_free(this->x509_cert_);
  delete this->x509_cert_;
}

std::ostream& operator<<(std::ostream& os, const x509& x509_cert) {

  constexpr uint8_t wsize = 30;
  const std::vector<uint8_t>& sn = x509_cert.serial_number();
  std::string sn_str = std::accumulate(
      std::begin(sn),
      std::end(sn),
      std::string(""),
      [] (std::string lhs, uint8_t x) {
        std::stringstream ss;
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<uint32_t>(x);
        return lhs.empty() ? ss.str() : lhs + ":" + ss.str();
      });

  const x509::date_t& valid_from = x509_cert.valid_from();
  const x509::date_t& valid_to   = x509_cert.valid_to();

  //// 2018-01-11 20:39:31
  std::string valid_from_str =
    std::to_string(valid_from[0]) + "-" +
    std::to_string(valid_from[1]) + "-" +
    std::to_string(valid_from[2]) + " " +
    std::to_string(valid_from[3]) + ":" +
    std::to_string(valid_from[4]) + ":" +
    std::to_string(valid_from[5]);


  std::string valid_to_str =
    std::to_string(valid_to[0]) + "-" +
    std::to_string(valid_to[1]) + "-" +
    std::to_string(valid_to[2]) + " " +
    std::to_string(valid_to[3]) + ":" +
    std::to_string(valid_to[4]) + ":" +
    std::to_string(valid_to[5]);


  os << std::hex << std::left;
  os << std::setw(wsize) << std::setfill(' ') << "Version:       "       << x509_cert.version() << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Serial Number: "       << sn_str << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Signature Algorithm: " << oid_to_string(x509_cert.signature_algorithm()) << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Valid from: "          << valid_from_str << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Valid to: "            << valid_to_str << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Issuer: "              << x509_cert.issuer() << std::endl;
  os << std::setw(wsize) << std::setfill(' ') << "Subject: "             << x509_cert.subject() << std::endl;


  //os << std::endl << std::endl;
  //std::vector<char> buffer(2048, 0);
  //mbedtls_x509_crt_info(buffer.data(), buffer.size(), "", x509_cert.x509_cert_);
  //std::string foo(buffer.data());
  //os << foo;
  return os;
}

}
}
