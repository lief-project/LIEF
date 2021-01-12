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

#include "LIEF/utils.hpp"

namespace {
  // Copy this function from mbedtls sinc it is not exported
  inline int x509_get_current_time( mbedtls_x509_time *now )
  {
      struct tm *lt, tm_buf;
      mbedtls_time_t tt;
      int ret = 0;

      tt = mbedtls_time( NULL );
      lt = mbedtls_platform_gmtime_r( &tt, &tm_buf );

      if( lt == NULL )
          ret = -1;
      else
      {
          now->year = lt->tm_year + 1900;
          now->mon  = lt->tm_mon  + 1;
          now->day  = lt->tm_mday;
          now->hour = lt->tm_hour;
          now->min  = lt->tm_min;
          now->sec  = lt->tm_sec;
      }

      return( ret );
  }
}


namespace LIEF {
namespace PE {

inline x509::date_t from_mbedtls(const mbedtls_x509_time& time) {
  return {
    time.year,
    time.mon,
    time.day,
    time.hour,
    time.min,
    time.sec
  };
}

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


bool x509::check_time(const date_t& before, const date_t& after) {
  // Implementation taken
  // from https://github.com/ARMmbed/mbedtls/blob/1c54b5410fd48d6bcada97e30cac417c5c7eea67/library/x509.c#L926-L962
  if (before[0] > after[0]) {
    LIEF_DEBUG("{} > {}", before[0], after[0]);
    return false;
  }

  if (
      before[0] == after[0] and
      before[1]  > after[1]
     )
  {
    LIEF_DEBUG("{} > {}", before[1], after[1]);
    return false;
  }

  if (
      before[0] == after[0] and
      before[1] == after[1] and
      before[2]  > after[2]
     )
  {
    LIEF_DEBUG("{} > {}", before[2], after[2]);
    return false;
  }

  if (
      before[0] == after[0] and
      before[1] == after[1] and
      before[2] == after[2] and
      before[3]  > after[3]
     )
  {
    LIEF_DEBUG("{} > {}", before[3], after[3]);
    return false;
  }

  if (
      before[0] == after[0] and
      before[1] == after[1] and
      before[2] == after[2] and
      before[3] == after[3] and
      before[4]  > after[4]
     )
  {
    LIEF_DEBUG("{} > {}", before[4], after[4]);
    return false;
  }

  if (
      before[0] == after[0] and
      before[1] == after[1] and
      before[2] == after[2] and
      before[3] == after[3] and
      before[4] == after[4] and
      before[5]  > after[5]
     )
  {
    LIEF_DEBUG("{} > {}", before[5], after[5]);
    return false;
  }

  if (
      before[0] == after[0] and
      before[1] == after[1] and
      before[2] == after[2] and
      before[3] == after[3] and
      before[4] == after[4] and
      before[5] == after[5] and
      before[6]  > after[6]
     )
  {
    LIEF_DEBUG("{} > {}", before[6], after[6]);
    return false;
  }

  return true;
}

bool x509::time_is_past(const date_t& to) {
  mbedtls_x509_time now;

  if (x509_get_current_time(&now) != 0) {
    return true;
  }
  // check_time(): true if now < to else false
  return not check_time(from_mbedtls(now), to);
}

bool x509::time_is_future(const date_t& from) {
  mbedtls_x509_time now;

  if (x509_get_current_time(&now) != 0) {
    return true;
  }
  return check_time(from_mbedtls(now), from);
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
  return from_mbedtls(this->x509_cert_->valid_from);
}

x509::date_t x509::valid_to(void) const {
  return from_mbedtls(this->x509_cert_->valid_to);
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
    mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(this->x509_cert_->pk);
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

  /* If the verification failed with mbedtls_pk_verify it
   * does not necessity means that the signatures don't match.
   *
   * For RSA public-key scheme, mbedtls encodes the hash with rsa_rsassa_pkcs1_v15_encode() so that it expands
   * the hash value with encoded data. On some samples, this encoding failed.
   *
   * In the approach below, we manually decrypt and unpad the output of the DEC(signature)
   * as defined in the RFC #2313
   */
  if (ret != 0) {
    if (mbedtls_pk_get_type(&ctx) == MBEDTLS_PK_RSA) {
      auto* ctx_rsa = reinterpret_cast<mbedtls_rsa_context*>(ctx.pk_ctx);
      if ((ctx_rsa->len * 8) < 100 or (ctx_rsa->len * 8) > 2048 * 10) {
        LIEF_INFO("RSA Key length is not valid ({} bits)", ctx_rsa->len * 8);
        return false;
      }
      std::vector<uint8_t> decrypted(ctx_rsa->len);

      int ret_rsa_public = mbedtls_rsa_public(ctx_rsa, signature.data(), decrypted.data());
      if (ret_rsa_public != 0) {
        std::string strerr(1024, 0);
        mbedtls_strerror(ret_rsa_public, const_cast<char*>(strerr.data()), strerr.size());
        LIEF_INFO("RSA public key operation failed: '{}'", strerr);
        return false;
      }

      // Check padding header
      if (decrypted[0] != 0x00 and decrypted[1] != 0x01 and decrypted[2] != 0xff) {
        return false;
      }

      std::vector<uint8_t> unpadded;
      for (size_t i = 2; i < decrypted.size(); ++i) {
        if (decrypted[i] == 0) {
          unpadded = std::vector<uint8_t>(std::begin(decrypted) + i + 1, std::end(decrypted));
          break;
        }
        if (decrypted[i] != 0xFF) {
          return false;
        }
      }
      if (unpadded == hash) {
        return true;
      }
    }
    if (ret != 0) {
      std::string strerr(1024, 0);
      mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
      LIEF_INFO("decrypt() failed with error: '{}'", strerr);
      return false;
    }
    return true;
  }
  return true;
}


x509::VERIFICATION_FLAGS x509::is_trusted_by(const std::vector<x509>& ca) const {
  std::vector<x509> ca_list = ca; // Explicit copy since we will modify mbedtls_x509_crt->next
  for (size_t i = 0; i < ca_list.size() - 1; ++i) {
    ca_list[i].x509_cert_->next = ca_list[i + 1].x509_cert_;
  }

  VERIFICATION_FLAGS result = VERIFICATION_FLAGS::OK;
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
    result = VERIFICATION_FLAGS::BADCERT_NOT_TRUSTED;
  }

  // Clear the chain since ~x509() will delete each object
  for (size_t i = 0; i < ca_list.size(); ++i) {
    ca_list[i].x509_cert_->next = nullptr;
  }
  return result;
}

x509::VERIFICATION_FLAGS x509::verify(const x509& ca) const {
  uint32_t flags = 0;
  VERIFICATION_FLAGS result = VERIFICATION_FLAGS::OK;
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
    result = VERIFICATION_FLAGS::BADCERT_NOT_TRUSTED;
  }
  return result;
}

std::vector<oid_t> x509::ext_key_usage() const {
  if ((this->x509_cert_->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) == 0) {
    return {};
  }
  mbedtls_asn1_sequence* current = &this->x509_cert_->ext_key_usage;
  std::vector<oid_t> oids;
  while (current != nullptr) {
    char oid_str[256] = {0};
    int ret = mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &current->buf);
    if (ret != MBEDTLS_ERR_OID_BUF_TOO_SMALL) {
      LIEF_DEBUG("OID: {}", oid_str);
      oids.push_back(oid_str);
    } else {
      std::string strerr(1024, 0);
      mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
      LIEF_WARN("{}", strerr);
    }
    if (current->next == current) {
      break;
    }
    current = current->next;
  }
  return oids;
}

std::vector<oid_t> x509::certificate_policies() const {
  if ((this->x509_cert_->ext_types & MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES) == 0) {
    return {};
  }

  mbedtls_x509_sequence& policies = this->x509_cert_->certificate_policies;
  mbedtls_asn1_sequence* current = &policies;
  std::vector<oid_t> oids;
  while (current != nullptr) {
    char oid_str[256] = {0};
    int ret = mbedtls_oid_get_numeric_string(oid_str, sizeof(oid_str), &current->buf);
    if (ret != MBEDTLS_ERR_OID_BUF_TOO_SMALL) {
      oids.push_back(oid_str);
    } else {
      std::string strerr(1024, 0);
      mbedtls_strerror(ret, const_cast<char*>(strerr.data()), strerr.size());
      LIEF_WARN("{}", strerr);
    }
    if (current->next == current) {
      break;
    }
    current = current->next;
  }
  return oids;
}

bool x509::is_ca() const {
  if ((this->x509_cert_->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) == 0) {
    return true;
  }
  return this->x509_cert_->ca_istrue;
}

std::vector<x509::KEY_USAGE> x509::key_usage() const {
  static const std::map<uint32_t, KEY_USAGE> MBEDTLS_MAP = {
    {MBEDTLS_X509_KU_DIGITAL_SIGNATURE, KEY_USAGE::DIGITAL_SIGNATURE},
    {MBEDTLS_X509_KU_NON_REPUDIATION,   KEY_USAGE::NON_REPUDIATION},
    {MBEDTLS_X509_KU_KEY_ENCIPHERMENT,  KEY_USAGE::KEY_ENCIPHERMENT},
    {MBEDTLS_X509_KU_DATA_ENCIPHERMENT, KEY_USAGE::DATA_ENCIPHERMENT},
    {MBEDTLS_X509_KU_KEY_AGREEMENT,     KEY_USAGE::KEY_AGREEMENT},
    {MBEDTLS_X509_KU_KEY_CERT_SIGN,     KEY_USAGE::KEY_CERT_SIGN},
    {MBEDTLS_X509_KU_CRL_SIGN,          KEY_USAGE::CRL_SIGN},
    {MBEDTLS_X509_KU_ENCIPHER_ONLY,     KEY_USAGE::ENCIPHER_ONLY},
    {MBEDTLS_X509_KU_DECIPHER_ONLY,     KEY_USAGE::DECIPHER_ONLY},
  };

  if ((this->x509_cert_->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) == 0) {
    return {};
  }

  const uint32_t ku = this->x509_cert_->key_usage;
  std::vector<KEY_USAGE> usages;
  for (const auto& p : MBEDTLS_MAP) {
    if ((ku & p.first) > 0) {
      usages.push_back(p.second);
    }
  }
  return usages;
}

std::vector<uint8_t> x509::signature() const {
  mbedtls_x509_buf sig =  this->x509_cert_->sig;
  return {sig.p, sig.p + sig.len};
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
