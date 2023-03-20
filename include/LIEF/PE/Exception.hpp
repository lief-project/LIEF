#ifndef LIEF_PE_EXCEPTION_H_
#define LIEF_PE_EXCEPTION_H_

#include "LIEF/Abstract/Function.hpp"
namespace LIEF {
namespace PE {
namespace details {

enum unwind_info_version
{
  version_v1 = 1,
  version_v2 = 2,
};

enum unwind_code_opcode {
  UWOP_PUSH_NONVOL = 0,
  UWOP_ALLOC_LARGE = 1,
  UWOP_ALLOC_SMALL = 2,
  UWOP_SET_FPREG = 3,
  UWOP_SAVE_NONVOL = 4,
  UWOP_SAVE_NONVOL_FAR = 5,
  UWOP_EPILOG = 6,
  UWOP_SAVE_XMM128 = 8,
  UWOP_SAVE_XMM128_FAR = 9,
  UWOP_PUSH_MACHFRAME = 10
};

enum unwind_info_reg
{
  x86_64_RAX = 0,
  x86_64_RCX,
  x86_64_RDX,
  x86_64_RBX,
  x86_64_RSP,
  x86_64_RBP,
  x86_64_RSI,
  x86_64_RDI,
  x86_64_R8,
  x86_64_R9,
  x86_64_R10,
  x86_64_R11,
  x86_64_R12,
  x86_64_R13,
  x86_64_R14,
  x86_64_R15,
  x86_64_XMM0,
  x86_64_XMM1,
  x86_64_XMM2,
  x86_64_XMM3,
  x86_64_XMM4,
  x86_64_XMM5,
  x86_64_XMM6,
  x86_64_XMM7,
  x86_64_XMM8,
  x86_64_XMM9,
  x86_64_XMM10,
  x86_64_XMM11,
  x86_64_XMM12,
  x86_64_XMM13,
  x86_64_XMM14,
  x86_64_XMM15
};




enum class unwind_operation
{
  push,
  alloc,
  frame,
  mov

};

enum class exception_handle_flag:uint64_t
{
  exception_handle = 1 << 0,
  termination_handle = 1 << 1,
};

struct unwind_info
{
  size_t offset;
  unwind_operation operation;
  size_t reg;
  size_t reg_offset;

};

class Unwind
{
public:
  using unwinds = std::vector<unwind_info>;

  size_t prelog_size;
  size_t frame_reg;
  size_t frame_offset;
  unwinds unwinds_;

};
}


class LIEF_API Exception : public LIEF::Function
{
public:
  using handle_flags_t = std::vector< details::exception_handle_flag>;
  Exception(uint64_t address,uint64_t end);
  using exceptions_t = std::vector<Exception>;
  details::Unwind unwind;
  handle_flags_t handle_flag;
  size_t handle_rva;
  size_t info_rva;
  


};


}}
#endif // !LIEF_PE_EXCEPTION_H_