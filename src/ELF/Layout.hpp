#ifndef LIEF_ELF_LAYOUT_H_
#define LIEF_ELF_LAYOUT_H_
#include <unordered_map>
#include <string>
#include <vector>
namespace LIEF {
namespace ELF {
class Section;
class Binary;
class Layout {
  public:
  Layout(Binary& bin);

  inline virtual const std::unordered_map<std::string, size_t>& shstr_map() const {
    return shstr_name_map_;
  }

  inline virtual const std::unordered_map<std::string, size_t>& strtab_map() const {
    return strtab_name_map_;
  }

  inline virtual const std::vector<uint8_t>& raw_shstr() const {
    return raw_shstrtab_;
  }

  inline virtual const std::vector<uint8_t>& raw_strtab() const {
    return raw_strtab_;
  }

  inline void set_strtab_section(Section& section) {
    strtab_section_ = &section;
  }

  inline void set_dyn_sym_idx(int32_t val) {
    new_symndx_ = val;
  }

  bool is_strtab_shared_shstrtab() const;
  size_t section_strtab_size();
  size_t section_shstr_size();

  virtual ~Layout();

  protected:
  Layout() = delete;
  Binary* binary_ = nullptr;

  std::unordered_map<std::string, size_t> shstr_name_map_;
  std::unordered_map<std::string, size_t> strtab_name_map_;

  std::vector<uint8_t> raw_shstrtab_;
  std::vector<uint8_t> raw_strtab_;

  Section* strtab_section_ = nullptr;
  int32_t new_symndx_ = -1;
};
}
}
#endif
