

enum ACCESS_FLAGS {
  ACC_UNKNOWN               = 0x0,
  ACC_PUBLIC                = 0x1,
  ACC_PRIVATE               = 0x2,
  ACC_PROTECTED             = 0x4,
  ACC_STATIC                = 0x8,
  ACC_FINAL                 = 0x10,
  ACC_SYNCHRONIZED          = 0x20,
  ACC_VOLATILE              = 0x40,
  ACC_BRIDGE                = 0x40,
  ACC_TRANSIENT             = 0x80,
  ACC_VARARGS               = 0x80,
  ACC_NATIVE                = 0x100,
  ACC_INTERFACE             = 0x200,
  ACC_ABSTRACT              = 0x400,
  ACC_STRICT                = 0x800,
  ACC_SYNTHETIC             = 0x1000,
  ACC_ANNOTATION            = 0x2000,
  ACC_ENUM                  = 0x4000,
  ACC_CONSTRUCTOR           = 0x10000,
  ACC_DECLARED_SYNCHRONIZED = 0x20000
};


enum METHOD_TYPES {
  METHOD_UNKNOWN      = 0x00,
  METHOD_VIRTUAL      = 0x01,
  METHOD_DIRECT       = 0x02, // Deprecated

  METHOD_EXTERN       = 0x03,
  METHOD_CTOR         = 0x04,
  METHOD_STATIC       = 0x05,
  METHOD_STATIC_CTOR  = 0x06,
};

