#include "LIEF/BinaryStream/Convert.hpp"
#include "LIEF/BinaryStream/BinaryStream.hpp"

/* In place conversions for BinaryStream/VectorStream data */

namespace LIEF {
namespace Convert {

/*
 * ELF conversions
 */

/** ELF header */
template <typename Elf_Ehdr>
void swap_endian_Elf_Ehdr(Elf_Ehdr *hdr) {
  hdr->e_type      = BinaryStream::swap_endian(hdr->e_type);
  hdr->e_machine   = BinaryStream::swap_endian(hdr->e_machine);
  hdr->e_version   = BinaryStream::swap_endian(hdr->e_version);
  hdr->e_entry     = BinaryStream::swap_endian(hdr->e_entry);
  hdr->e_phoff     = BinaryStream::swap_endian(hdr->e_phoff);
  hdr->e_shoff     = BinaryStream::swap_endian(hdr->e_shoff);
  hdr->e_flags     = BinaryStream::swap_endian(hdr->e_flags);
  hdr->e_ehsize    = BinaryStream::swap_endian(hdr->e_ehsize);
  hdr->e_phentsize = BinaryStream::swap_endian(hdr->e_phentsize);
  hdr->e_phnum     = BinaryStream::swap_endian(hdr->e_phnum);
  hdr->e_shentsize = BinaryStream::swap_endian(hdr->e_shentsize);
  hdr->e_shnum     = BinaryStream::swap_endian(hdr->e_shnum);
  hdr->e_shstrndx  = BinaryStream::swap_endian(hdr->e_shstrndx);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Ehdr>(LIEF::ELF::Elf32_Ehdr *hdr) {
  swap_endian_Elf_Ehdr(hdr);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Ehdr>(LIEF::ELF::Elf64_Ehdr *hdr) {
  swap_endian_Elf_Ehdr(hdr);
}


/** ELF Section Header */
template <typename Elf_Shdr>
void swap_endian_Elf_Shdr(Elf_Shdr *shdr) {
  shdr->sh_name      = BinaryStream::swap_endian(shdr->sh_name);
  shdr->sh_type      = BinaryStream::swap_endian(shdr->sh_type);
  shdr->sh_flags     = BinaryStream::swap_endian(shdr->sh_flags);
  shdr->sh_addr      = BinaryStream::swap_endian(shdr->sh_addr);
  shdr->sh_offset    = BinaryStream::swap_endian(shdr->sh_offset);
  shdr->sh_size      = BinaryStream::swap_endian(shdr->sh_size);
  shdr->sh_link      = BinaryStream::swap_endian(shdr->sh_link);
  shdr->sh_info      = BinaryStream::swap_endian(shdr->sh_info);
  shdr->sh_addralign = BinaryStream::swap_endian(shdr->sh_addralign);
  shdr->sh_entsize   = BinaryStream::swap_endian(shdr->sh_entsize);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Shdr>(LIEF::ELF::Elf32_Shdr *shdr) {
  swap_endian_Elf_Shdr(shdr);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Shdr>(LIEF::ELF::Elf64_Shdr *shdr) {
  swap_endian_Elf_Shdr(shdr);
}


/** ELF Program Header */
template <typename Elf_Phdr>
void swap_endian_Elf_Phdr(Elf_Phdr *phdr) {
  phdr->p_type   = BinaryStream::swap_endian(phdr->p_type);
  phdr->p_offset = BinaryStream::swap_endian(phdr->p_offset);
  phdr->p_vaddr  = BinaryStream::swap_endian(phdr->p_vaddr);
  phdr->p_paddr  = BinaryStream::swap_endian(phdr->p_paddr);
  phdr->p_filesz = BinaryStream::swap_endian(phdr->p_filesz);
  phdr->p_memsz  = BinaryStream::swap_endian(phdr->p_memsz);
  phdr->p_flags  = BinaryStream::swap_endian(phdr->p_flags);
  phdr->p_align  = BinaryStream::swap_endian(phdr->p_align);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Phdr>(LIEF::ELF::Elf32_Phdr *phdr) {
  swap_endian_Elf_Phdr(phdr);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Phdr>(LIEF::ELF::Elf64_Phdr *phdr) {
  swap_endian_Elf_Phdr(phdr);
}


/** ELF Symbols */
template <typename Elf_Sym>
void swap_endian_Elf_Sym(Elf_Sym *sym) {
  sym->st_name  = BinaryStream::swap_endian(sym->st_name);
  sym->st_value = BinaryStream::swap_endian(sym->st_value);
  sym->st_size  = BinaryStream::swap_endian(sym->st_size);
  sym->st_info  = BinaryStream::swap_endian(sym->st_info);
  sym->st_other = BinaryStream::swap_endian(sym->st_other);
  sym->st_shndx = BinaryStream::swap_endian(sym->st_shndx);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Sym>(LIEF::ELF::Elf32_Sym *sym) {
  swap_endian_Elf_Sym(sym);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Sym>(LIEF::ELF::Elf64_Sym *sym) {
  swap_endian_Elf_Sym(sym);
}

/** ELF Relocations */
template <typename REL_T>
void swap_endian_Elf_Rel(REL_T *rel) {
  rel->r_offset = BinaryStream::swap_endian(rel->r_offset);
  rel->r_info   = BinaryStream::swap_endian(rel->r_info);
}

template <typename RELA_T>
void swap_endian_Elf_Rela(RELA_T *rel) {
  rel->r_offset = BinaryStream::swap_endian(rel->r_offset);
  rel->r_info   = BinaryStream::swap_endian(rel->r_info);
  rel->r_addend = BinaryStream::swap_endian(rel->r_addend);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Rel>(LIEF::ELF::Elf32_Rel *rel) {
  swap_endian_Elf_Rel(rel);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Rel>(LIEF::ELF::Elf64_Rel *rel) {
  swap_endian_Elf_Rel(rel);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Rela>(LIEF::ELF::Elf32_Rela *rel) {
  swap_endian_Elf_Rela(rel);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Rela>(LIEF::ELF::Elf64_Rela *rel) {
  swap_endian_Elf_Rela(rel);
}


/** ELF Dynamic Symbol */
template <typename Elf_Dyn>
void swap_endian_Elf_Dyn(Elf_Dyn *dyn) {
  dyn->d_tag      = BinaryStream::swap_endian(dyn->d_tag);
  dyn->d_un.d_val = BinaryStream::swap_endian(dyn->d_un.d_val);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Dyn>(LIEF::ELF::Elf32_Dyn *dyn) {
  swap_endian_Elf_Dyn(dyn);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Dyn>(LIEF::ELF::Elf64_Dyn *dyn) {
  swap_endian_Elf_Dyn(dyn);
}


/** ELF Verneed */
template <typename Elf_Verneed>
void swap_endian_Elf_Verneed(Elf_Verneed *ver) {
    ver->vn_version = BinaryStream::swap_endian(ver->vn_version);
    ver->vn_cnt     = BinaryStream::swap_endian(ver->vn_cnt);
    ver->vn_file    = BinaryStream::swap_endian(ver->vn_file);
    ver->vn_aux     = BinaryStream::swap_endian(ver->vn_aux);
    ver->vn_next    = BinaryStream::swap_endian(ver->vn_next);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Verneed>(LIEF::ELF::Elf32_Verneed *ver) {
  swap_endian_Elf_Verneed(ver);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Verneed>(LIEF::ELF::Elf64_Verneed *ver) {
  swap_endian_Elf_Verneed(ver);
}


/** ELF Vernaux */
template <typename Elf_Vernaux>
void swap_endian_Elf_Vernaux(Elf_Vernaux *ver) {
    ver->vna_hash  = BinaryStream::swap_endian(ver->vna_hash);
    ver->vna_flags = BinaryStream::swap_endian(ver->vna_flags);
    ver->vna_other = BinaryStream::swap_endian(ver->vna_other);
    ver->vna_name  = BinaryStream::swap_endian(ver->vna_name);
    ver->vna_next  = BinaryStream::swap_endian(ver->vna_next);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Vernaux>(LIEF::ELF::Elf32_Vernaux *ver) {
  swap_endian_Elf_Vernaux(ver);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Vernaux>(LIEF::ELF::Elf64_Vernaux *ver) {
  swap_endian_Elf_Vernaux(ver);
}

/** ELF Symbol Version Definition */
template <typename Elf_Verdef>
void swap_endian_Elf_Verdef(Elf_Verdef *ver) {
      ver->vd_version = BinaryStream::swap_endian(ver->vd_version);
      ver->vd_flags   = BinaryStream::swap_endian(ver->vd_flags);
      ver->vd_ndx     = BinaryStream::swap_endian(ver->vd_ndx);
      ver->vd_cnt     = BinaryStream::swap_endian(ver->vd_cnt);
      ver->vd_hash    = BinaryStream::swap_endian(ver->vd_hash);
      ver->vd_aux     = BinaryStream::swap_endian(ver->vd_aux);
      ver->vd_next    = BinaryStream::swap_endian(ver->vd_next);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Verdef>(LIEF::ELF::Elf32_Verdef *ver) {
  swap_endian_Elf_Verdef(ver);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Verdef>(LIEF::ELF::Elf64_Verdef *ver) {
  swap_endian_Elf_Verdef(ver);
}


template <typename Elf_Verdaux>
void swap_endian_Elf_Verdaux(Elf_Verdaux *ver) {
  ver->vda_name = BinaryStream::swap_endian(ver->vda_name);
  ver->vda_next = BinaryStream::swap_endian(ver->vda_next);
}

template<> 
void swap_endian<LIEF::ELF::Elf32_Verdaux>(LIEF::ELF::Elf32_Verdaux *ver) {
  swap_endian_Elf_Verdaux(ver);
}

template<> 
void swap_endian<LIEF::ELF::Elf64_Verdaux>(LIEF::ELF::Elf64_Verdaux *ver) {
  swap_endian_Elf_Verdaux(ver);
}

}
}
