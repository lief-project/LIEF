#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <LIEF/LIEF.h>


int main(int argc, char **argv) {
  size_t i, j;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <elf binary>\n", argv[0]);
    return EXIT_FAILURE ;
  }

  Elf_Binary_t *elf_binary = elf_parse(argv[1]);
  fprintf(stdout, "Binary Name: %s\n", elf_binary->name);
  fprintf(stdout, "Interpreter: %s\n", elf_binary->interpreter);

  Elf_Header_t header = elf_binary->header;
  uint8_t *identity = header.identity;
  fprintf(stdout, "Header\n");
  fprintf(stdout, "======\n");
  fprintf(stdout, "Magic: %x %x %x %x\n",             identity[0], identity[1], identity[2], identity[3]);
  fprintf(stdout, "Class: %s\n",                      ELF_CLASS_to_string(identity[LIEF_ELF_EI_CLASS]));
  fprintf(stdout, "Endianness: %s\n",                 ELF_DATA_to_string(identity[LIEF_ELF_EI_DATA]));
  fprintf(stdout, "Version: %s\n",                    VERSION_to_string(identity[LIEF_ELF_EI_VERSION]));
  fprintf(stdout, "OS/ABI: %s\n",                     OS_ABI_to_string(identity[LIEF_ELF_EI_OSABI]));
  fprintf(stdout, "File type: %s\n",                  E_TYPE_to_string(header.file_type));
  fprintf(stdout, "Architecture: %s\n",               ARCH_to_string(header.machine_type));
  fprintf(stdout, "Version: %s\n",                    VERSION_to_string(header.object_file_version));
  fprintf(stdout, "Segments offset: 0x%" PRIx64 "\n", header.program_headers_offset);
  fprintf(stdout, "Sections offset: 0x%" PRIx64 "\n", header.section_headers_offset);
  fprintf(stdout, "Processor flags: %x\n",            header.processor_flags);
  fprintf(stdout, "Header Size: %x\n",                header.header_size);
  fprintf(stdout, "Program header size: %x\n",        header.program_header_size);
  fprintf(stdout, "Nb segments: %d\n",                header.numberof_segments);
  fprintf(stdout, "Section header size: %x\n",        header.section_header_size);
  fprintf(stdout, "Nb sections: %d\n",                header.numberof_sections);
  fprintf(stdout, "Name string table idx: %d\n",      header.name_string_table_idx);

  Elf_Section_t** sections = elf_binary->sections;
  /*for (size_t i = 0; sections[i] != NULL; ++i) {*/
  for (i = 0; i < header.numberof_sections; ++i) {
    Elf_Section_t* section = sections[i];
    fprintf(stdout, ""
        "%-20s "
        "%-10s "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "%d "
        "0x%06" PRIx64 " "
        "0x%06" PRIx64 " "
        "%.6f "
        "\n",
        section->name,
        ELF_SECTION_TYPES_to_string(section->type),
        section->virtual_address,
        section->size,
        section->offset,
        section->link,
        section->alignment,
        section->entry_size,
        section->entropy
        );
    if (section->size > 3) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          section->content[0], section->content[1], section->content[2]);
    }
  }

  /* Dynamic symbols */
  fprintf(stdout, "Dynamic symbols:\n");
  Elf_Symbol_t** dynamic_symbols = elf_binary->dynamic_symbols;
  for (i = 0; dynamic_symbols[i] != NULL; ++i) {
    Elf_Symbol_t* symbol = dynamic_symbols[i];
    const char* import_export = "";

    if (symbol->is_imported) {
      import_export = "I";
    }

    if (symbol->is_imported) {
      import_export = "E";
    }

    fprintf(stdout, ""
        "%-20s "
        "%-10s "
        "%-10s "
        "0x%02x "
        "0x%02x"
        "0x%010" PRIx64 " "
        "0x%06" PRIx64 " "
        "%-3s "
        "\n",
        symbol->name,
        ELF_SYMBOL_TYPES_to_string(symbol->type),
        SYMBOL_BINDINGS_to_string(symbol->binding),
        symbol->other,
        symbol->shndx,
        symbol->value,
        symbol->size,
        import_export
        );
  }

  /* Static symbols */
  fprintf(stdout, "Static symbols:\n");
  Elf_Symbol_t** static_symbols = elf_binary->static_symbols;
  for (i = 0; static_symbols[i] != NULL; ++i) {
    Elf_Symbol_t* symbol = static_symbols[i];

    const char* import_export = "";

    if (symbol->is_imported) {
      import_export = "I";
    }

    if (symbol->is_imported) {
      import_export = "E";
    }

    fprintf(stdout, ""
        "%-20s "
        "%-10s "
        "%-10s "
        "0x%02x "
        "0x%02x"
        "0x%010" PRIx64 " "
        "0x%06" PRIx64 " "
        "%-3s "
        "\n",
        symbol->name,
        ELF_SYMBOL_TYPES_to_string(symbol->type),
        SYMBOL_BINDINGS_to_string(symbol->binding),
        symbol->other,
        symbol->shndx,
        symbol->value,
        symbol->size,
        import_export
        );
  }


  fprintf(stdout, "Segments:\n");
  Elf_Segment_t** segments = elf_binary->segments;
  for (i = 0; segments[i] != NULL; ++i) {
    Elf_Segment_t* segment = segments[i];
    fprintf(stdout, ""
        "%-20s "
        "0x%06"  PRIx32 " "
        "0x%010" PRIx64 " "
        "0x%06"  PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%06"  PRIx64 " "
        "0x%06"  PRIx64 " "
        "\n",
        SEGMENT_TYPES_to_string(segment->type),
        segment->flags,
        segment->virtual_address,
        segment->virtual_size,
        segment->offset,
        segment->size,
        segment->alignment
        );
    if (segment->size > 3) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          segment->content[0], segment->content[1], segment->content[2]);
    }
  }

  Elf_DynamicEntry_t **dynamic_entries = elf_binary->dynamic_entries;
  for (i = 0; dynamic_entries[i] != NULL; ++i) {
    Elf_DynamicEntry_t* entry = dynamic_entries[i];
    switch(entry->tag) {
      case LIEF_ELF_DT_NEEDED:
        {
          Elf_DynamicEntry_Library_t* e = (Elf_DynamicEntry_Library_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value,
            e->name
            );
          break;
        }
      case LIEF_ELF_DT_SONAME:
        {
          Elf_DynamicEntry_SharedObject_t* e = (Elf_DynamicEntry_SharedObject_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value,
            e->name
            );
          break;
        }

      case LIEF_ELF_DT_RPATH:
        {
          Elf_DynamicEntry_Rpath_t* e = (Elf_DynamicEntry_Rpath_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value,
            e->rpath
            );
          break;
        }

      case LIEF_ELF_DT_RUNPATH:
        {
          Elf_DynamicEntry_RunPath_t* e = (Elf_DynamicEntry_RunPath_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value,
            e->runpath
            );
          break;
        }

      case LIEF_ELF_DT_FLAGS:
        {
          Elf_DynamicEntry_Flags_t* e = (Elf_DynamicEntry_Flags_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " ",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value);

          enum LIEF_ELF_DYNAMIC_FLAGS* flags = e->flags;
          for (j = 0; flags[j] != 0; ++j) {
            fprintf(stdout, "%s ", DYNAMIC_FLAGS_to_string(flags[j]));
          }

          fprintf(stdout, "\n");
          break;
        }

      case LIEF_ELF_DT_FLAGS_1:
        {
          Elf_DynamicEntry_Flags_t* e = (Elf_DynamicEntry_Flags_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " ",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value);

          enum LIEF_ELF_DYNAMIC_FLAGS_1* flags = e->flags_1;
          for (j = 0; flags[j] != 0; ++j) {
            fprintf(stdout, "%s ", DYNAMIC_FLAGS_1_to_string(flags[j]));
          }

          fprintf(stdout, "\n");
          break;
        }


      case LIEF_ELF_DT_INIT_ARRAY:
      case LIEF_ELF_DT_FINI_ARRAY:
      case LIEF_ELF_DT_PREINIT_ARRAY:
        {
          Elf_DynamicEntry_Array_t* e = (Elf_DynamicEntry_Array_t*)entry;
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " ",
            DYNAMIC_TAGS_to_string(e->tag),
            e->value
            );
          uint64_t* array = e->array;
          for (j = 0; array[j] != 0; ++j) {
            fprintf(stdout, "" "0x%06" PRIx64 " ", array[j]);
          }

          fprintf(stdout, "\n");
          break;
        }

      default:
        {
          fprintf(stdout, ""
            "%-20s "
            "0x%010" PRIx64 " "
            "\n",
            DYNAMIC_TAGS_to_string(entry->tag),
            entry->value
            );
          break;
        }
    }
  }



  elf_binary_destroy(elf_binary);

  return EXIT_SUCCESS;
}
