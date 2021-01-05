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
#include <map>
#include <fstream>

#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/error.h"

#include "logging.hpp"

#include "LIEF/PE/signature/OIDToString.hpp"
#include "LIEF/PE/signature/x509.hpp"
#include "LIEF/PE/signature/RsaInfo.hpp"
#include "LIEF/PE/EnumToString.hpp"

namespace LIEF {
namespace PE {

x509::certificates_t x509::parse(const std::string& path) {

  std::ifstream cert_fs(path);
  if (not cert_fs) {
    LIEF_WARN("Can't open {}", path);
    return {};
  }
  cert_fs.unsetf(std::ios::skipws);
  cert_fs.seekg(0, std::ios::end);
  const size_t size = cert_fs.tellg();
  cert_fs.seekg(0, std::ios::beg);

  std::vector<uint8_t> raw(size + 1, 0);
  cert_fs.read(reinterpret_cast<char*>(raw.data()), raw.size());
  return x509::parse(std::move(raw));
}

x509::certificates_t x509::parse(const std::vector<uint8_t>& content) {
  std::unique_ptr<mbedtls_x509_crt> ca{new mbedtls_x509_crt{}};
  mbedtls_x509_crt_init(ca.get());
  //LIEF_INFO("{}", reinterpret_cast<const char*>(content.data()));
  int ret = mbedtls_x509_crt_parse(ca.get(), content.data(), content.size());
  if (ret != 0) {
    std::string strerr(1024, 0);
    mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
    LIEF_WARN("Fail to parse certificate blob: '{}'", strerr);
    return {};
  }
  std::vector<x509> crts;

  mbedtls_x509_crt* prev = nullptr;
  mbedtls_x509_crt* current = ca.release();
  while (current != nullptr and current != prev) {
    mbedtls_x509_crt* next = current->next;
    current->next = nullptr;
    crts.emplace_back(current);
    prev = current;
    current = next;
  }
  return crts;
}

x509::x509() = default;

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
  return buffer;
}

std::string x509::subject(void) const {
  char buffer[1024];
  mbedtls_x509_dn_gets(buffer, sizeof(buffer), &this->x509_cert_->subject);
  return buffer;
}

std::vector<uint8_t> x509::raw(void) const {
  return {this->x509_cert_->raw.p, this->x509_cert_->raw.p + this->x509_cert_->raw.len};
}


x509::KEY_TYPES x509::key_type() const {
  static const std::map<mbedtls_pk_type_t, x509::KEY_TYPES> mtype2asi = {
    {MBEDTLS_PK_NONE,       KEY_TYPES::NONE       },
    {MBEDTLS_PK_RSA,        KEY_TYPES::RSA        },
    {MBEDTLS_PK_ECKEY,      KEY_TYPES::ECKEY      },
    {MBEDTLS_PK_ECKEY_DH,   KEY_TYPES::ECKEY_DH   },
    {MBEDTLS_PK_ECDSA,      KEY_TYPES::ECDSA      },
    {MBEDTLS_PK_RSA_ALT,    KEY_TYPES::RSA_ALT    },
    {MBEDTLS_PK_RSASSA_PSS, KEY_TYPES::RSASSA_PSS },
  };

  mbedtls_pk_context* ctx = &(this->x509_cert_->pk);
  mbedtls_pk_type_t type  = mbedtls_pk_get_type(ctx);

  auto&& it_key = mtype2asi.find(type);
  if (it_key != std::end(mtype2asi)) {
    return it_key->second;
  }
  return KEY_TYPES::NONE;
}


std::unique_ptr<RsaInfo> x509::rsa_info(void) const {
  if (this->key_type() == KEY_TYPES::RSA) {
    mbedtls_pk_context& ctx = this->x509_cert_->pk;
    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(ctx);
    return std::unique_ptr<RsaInfo>{new RsaInfo{rsa_ctx}};
  }
  return nullptr;
}

bool x509::check_signature(const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature, ALGORITHMS algo) const {
  static const std::map<ALGORITHMS, mbedtls_md_type_t> LIEF2MBED_MD = {
    {ALGORITHMS::MD2, MBEDTLS_MD_MD2},
    {ALGORITHMS::MD4, MBEDTLS_MD_MD4},
    {ALGORITHMS::MD5, MBEDTLS_MD_MD5},

    {ALGORITHMS::SHA_1,   MBEDTLS_MD_SHA1},
    {ALGORITHMS::SHA_256, MBEDTLS_MD_SHA256},
    {ALGORITHMS::SHA_384, MBEDTLS_MD_SHA384},
    {ALGORITHMS::SHA_512, MBEDTLS_MD_SHA512},
  };

  auto it_md = LIEF2MBED_MD.find(algo);
  if (it_md == std::end(LIEF2MBED_MD)) {
    LIEF_ERR("Can't find algorithm {}", to_string(algo));
    return false;
  }
  mbedtls_pk_context& ctx = this->x509_cert_->pk;

  int ret = mbedtls_pk_verify(&ctx,
    /* MD_HASH_ALGO       */ it_md->second,
    /* Input Hash         */ hash.data(), hash.size(),
    /* Signature provided */ signature.data(), signature.size());

  if (ret != 0) {
    std::string strerr(1024, 0);
    mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
    LIEF_INFO("decrypt() failed with error: '{}'", strerr);
    return false;
  }
  return true;
}


x509::VERIFICATION_FLAGS x509::is_trusted_by(const std::vector<x509>& ca) const {
  std::vector<x509> ca_list = ca; // Explicit copy since we will modify mbedtls_x509_crt->next
  for (size_t i = 0; i < ca_list.size() - 1; ++i) {
    ca_list[i].x509_cert_->next = ca_list[i + 1].x509_cert_;
  }

  uint32_t flags = 0;
  mbedtls_x509_crt_profile profile = {
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_MD5)   |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1)   |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    1          /* Min RSA key   */,
  };

  int ret = mbedtls_x509_crt_verify_with_profile(
      /* crt          */ this->x509_cert_,
      /* Trusted CA   */ ca_list.front().x509_cert_,
      /* CA's CRLs    */ nullptr,
      /* profile      */ &profile,
      /* Common Name  */ nullptr,
      /* Verification */ &flags,
      /* verification function */ nullptr,
      /* verification params   */ nullptr);

  if (ret != 0) {
    std::string strerr(1024, 0);
    mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
    std::string out(1024, 0);
    mbedtls_x509_crt_verify_info(const_cast<char*>(out.data()), out.size(), "", flags);
    LIEF_WARN("X509 verify failed with: {} (0x{:x})\n{}", strerr, ret, out);
  }

  // Clear the chain since ~x509() will delete each object
  for (size_t i = 0; i < ca_list.size(); ++i) {
    ca_list[i].x509_cert_->next = nullptr;
  }
  return static_cast<VERIFICATION_FLAGS>(flags);
}

x509::VERIFICATION_FLAGS x509::verify(const x509& ca) const {
  uint32_t flags = 0;
  mbedtls_x509_crt_profile profile = {
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1)   |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    0xFFFFFFF, /* Any PK alg    */
    0xFFFFFFF, /* Any curve     */
    1          /* Min RSA key */,
  };

  int ret = mbedtls_x509_crt_verify_with_profile(
      /* crt          */ ca.x509_cert_,
      /* Trusted CA   */ this->x509_cert_,
      /* CA's CRLs    */ nullptr,
      /* profile      */ &profile,
      /* Common Name  */ nullptr,
      /* Verification */ &flags,
      /* verification function */ nullptr,
      /* verification params   */ nullptr);

  if (ret != 0) {
    std::string strerr(1024, 0);
    mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
    std::string out(1024, 0);
    mbedtls_x509_crt_verify_info(const_cast<char*>(out.data()), out.size(), "", flags);
    LIEF_WARN("X509 verify failed with: {} (0x{:x})\n{}", strerr, ret, out);
  }
  return static_cast<VERIFICATION_FLAGS>(flags);
}

void x509::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

x509::~x509(void) {
  mbedtls_x509_crt_free(this->x509_cert_);
  delete this->x509_cert_;
}

std::ostream& operator<<(std::ostream& os, const x509& x509_cert) {
  std::vector<char> buffer(2048, 0);
  int ret = mbedtls_x509_crt_info(buffer.data(), buffer.size(), "", x509_cert.x509_cert_);
  if (ret < 0) {
    os << "Can't print certificate information\n";
    return os;
  }
  std::string crt_str(buffer.data());
  os << crt_str;
  return os;
}

}
}
