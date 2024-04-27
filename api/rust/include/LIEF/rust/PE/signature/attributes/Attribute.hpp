#pragma once
#include "LIEF/PE/signature/Attribute.hpp"
#include "LIEF/rust/Mirror.hpp"

class PE_Attribute : public Mirror<LIEF::PE::Attribute> {
  public:
  friend class PE_ContentType;
  friend class PE_GenericType;
  friend class PE_MsSpcNestedSignature;
  friend class PE_MsSpcStatementType;
  friend class PE_PKCS9AtSequenceNumber;
  friend class PE_PKCS9CounterSignature;
  friend class PE_PKCS9MessageDigest;
  friend class PE_PKCS9SigningTime;
  friend class PE_SpcSpOpusInfo;
  using lief_t = LIEF::PE::Attribute;
  using Mirror::Mirror;
};
