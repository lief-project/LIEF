#include "pyELF.hpp"
#include "ELF/Structures.hpp"

namespace LIEF {
namespace ELF {
void init_ELF32_sizes(py::module& m) {
  enum SIZES : size_t {};
  py::enum_<SIZES>(m, "SIZES")
    .value("ADDR",    static_cast<SIZES>(sizeof(details::Elf32_Addr)))
    .value("OFF",     static_cast<SIZES>(sizeof(details::Elf32_Off)))
    .value("HALF",    static_cast<SIZES>(sizeof(details::Elf32_Half)))
    .value("WORD",    static_cast<SIZES>(sizeof(details::Elf32_Word)))
    .value("SWORD",   static_cast<SIZES>(sizeof(details::Elf32_Sword)))
    .value("INT",     static_cast<SIZES>(sizeof(uint32_t)))
    .value("EHDR",    static_cast<SIZES>(sizeof(details::Elf32_Ehdr)))
    .value("SHDR",    static_cast<SIZES>(sizeof(details::Elf32_Shdr)))
    .value("PHDR",    static_cast<SIZES>(sizeof(details::Elf32_Phdr)))
    .value("SYM",     static_cast<SIZES>(sizeof(details::Elf32_Sym)))
    .value("REL",     static_cast<SIZES>(sizeof(details::Elf32_Rel)))
    .value("RELA",    static_cast<SIZES>(sizeof(details::Elf32_Rela)))
    .value("DYN",     static_cast<SIZES>(sizeof(details::Elf32_Dyn)))
    .value("VERNEED", static_cast<SIZES>(sizeof(details::Elf32_Verneed)))
    .value("VERNAUX", static_cast<SIZES>(sizeof(details::Elf32_Vernaux)))
    .value("AUXV",    static_cast<SIZES>(sizeof(details::Elf32_Auxv)))
    .value("VERDEF",  static_cast<SIZES>(sizeof(details::Elf32_Verdef)))
    .value("VERDAUX", static_cast<SIZES>(sizeof(details::Elf32_Verdaux)));
}


void init_ELF64_sizes(py::module& m) {
  enum SIZES : size_t {};
  py::enum_<SIZES>(m, "SIZES")
    .value("ADDR",    static_cast<SIZES>(sizeof(details::Elf64_Addr)))
    .value("OFF",     static_cast<SIZES>(sizeof(details::Elf64_Off)))
    .value("HALF",    static_cast<SIZES>(sizeof(details::Elf64_Half)))
    .value("WORD",    static_cast<SIZES>(sizeof(details::Elf64_Word)))
    .value("SWORD",   static_cast<SIZES>(sizeof(details::Elf64_Sword)))
    .value("INT",     static_cast<SIZES>(sizeof(uint64_t)))
    .value("EHDR",    static_cast<SIZES>(sizeof(details::Elf64_Ehdr)))
    .value("SHDR",    static_cast<SIZES>(sizeof(details::Elf64_Shdr)))
    .value("PHDR",    static_cast<SIZES>(sizeof(details::Elf64_Phdr)))
    .value("SYM",     static_cast<SIZES>(sizeof(details::Elf64_Sym)))
    .value("REL",     static_cast<SIZES>(sizeof(details::Elf64_Rel)))
    .value("RELA",    static_cast<SIZES>(sizeof(details::Elf64_Rela)))
    .value("DYN",     static_cast<SIZES>(sizeof(details::Elf64_Dyn)))
    .value("VERNEED", static_cast<SIZES>(sizeof(details::Elf64_Verneed)))
    .value("VERNAUX", static_cast<SIZES>(sizeof(details::Elf64_Vernaux)))
    .value("AUXV",    static_cast<SIZES>(sizeof(details::Elf64_Auxv)))
    .value("VERDEF",  static_cast<SIZES>(sizeof(details::Elf64_Verdef)))
    .value("VERDAUX", static_cast<SIZES>(sizeof(details::Elf64_Verdaux)));
}

}
}
