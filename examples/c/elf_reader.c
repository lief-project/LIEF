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

  if (elf_binary == NULL) {
    return EXIT_FAILURE;
  }

  fprintf(stdout, "Interpreter: %s\n", elf_binary->interpreter);

  Elf_Header_t header = elf_binary->header;
  uint8_t *identity = header.identity;
  fprintf(stdout, "Header\n");
  fprintf(stdout, "======\n");
  fprintf(stdout, "Magic: %x %x %x %x\n",             identity[0], identity[1], identity[2], identity[3]);
  fprintf(stdout, "Class: %d\n",                      identity[LIEF_EI_CLASS]);
  fprintf(stdout, "Endianness: %d\n",                 identity[LIEF_EI_DATA]);
  fprintf(stdout, "Version: %d\n",                    identity[LIEF_EI_VERSION]);
  fprintf(stdout, "OS/ABI: %d\n",                     identity[LIEF_EI_OSABI]);
  fprintf(stdout, "File type: %d\n",                  header.file_type);
  fprintf(stdout, "Architecture: %d\n",               header.machine_type);
  fprintf(stdout, "Version: %d\n",                    header.object_file_version);
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
  for (i = 0; i < header.numberof_sections && sections[i] != NULL; ++i) {
    Elf_Section_t* section = sections[i];
    fprintf(stdout, ""
        "%-20s "
        "%d "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "%d "
        "0x%06" PRIx64 " "
        "0x%06" PRIx64 " "
        "%.6f "
        "\n",
        section->name,
        section->type,
        section->virtual_address,
        section->size,
        section->offset,
        section->link,
        section->alignment,
        section->entry_size,
        section->entropy
        );
    if (section->size > 3 && section->content != NULL) {
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
        "%d "
        "%d "
        "0x%02x "
        "0x%02x"
        "0x%010" PRIx64 " "
        "0x%06" PRIx64 " "
        "%-3s "
        "\n",
        symbol->name,
        symbol->type,
        symbol->binding,
        symbol->other,
        symbol->shndx,
        symbol->value,
        symbol->size,
        import_export
        );
  }

  /* symtab symbols */
  fprintf(stdout, "symtab symbols:\n");
  Elf_Symbol_t** symtab_symbols = elf_binary->symtab_symbols;
  for (i = 0; symtab_symbols[i] != NULL; ++i) {
    Elf_Symbol_t* symbol = symtab_symbols[i];

    const char* import_export = "";

    if (symbol->is_imported) {
      import_export = "I";
    }

    if (symbol->is_imported) {
      import_export = "E";
    }

    fprintf(stdout, ""
        "%-20s "
        "%d "
        "%d "
        "0x%02x "
        "0x%02x"
        "0x%010" PRIx64 " "
        "0x%06" PRIx64 " "
        "%-3s "
        "\n",
        symbol->name,
        symbol->type,
        symbol->binding,
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
        "%d "
        "0x%06"  PRIx32 " "
        "0x%010" PRIx64 " "
        "0x%06"  PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%06"  PRIx64 " "
        "0x%06"  PRIx64 " "
        "\n",
        segment->type,
        segment->flags,
        segment->virtual_address,
        segment->virtual_size,
        segment->offset,
        segment->size,
        segment->alignment
        );
    if (segment->size > 3 && segment->content != NULL) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          segment->content[0], segment->content[1], segment->content[2]);
    }
  }

  Elf_DynamicEntry_t **dynamic_entries = elf_binary->dynamic_entries;
  for (i = 0; dynamic_entries[i] != NULL; ++i) {
    Elf_DynamicEntry_t* entry = dynamic_entries[i];
    switch(entry->tag) {
      case LIEF_DT_NEEDED:
        {
          Elf_DynamicEntry_Library_t* e = (Elf_DynamicEntry_Library_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            e->tag,
            e->value,
            e->name
            );
          break;
        }
      case LIEF_DT_SONAME:
        {
          Elf_DynamicEntry_SharedObject_t* e = (Elf_DynamicEntry_SharedObject_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            e->tag,
            e->value,
            e->name
            );
          break;
        }

      case LIEF_DT_RPATH:
        {
          Elf_DynamicEntry_Rpath_t* e = (Elf_DynamicEntry_Rpath_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            e->tag,
            e->value,
            e->rpath
            );
          break;
        }

      case LIEF_DT_RUNPATH:
        {
          Elf_DynamicEntry_RunPath_t* e = (Elf_DynamicEntry_RunPath_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " "
            "%-20s "
            "\n",
            e->tag,
            e->value,
            e->runpath
            );
          break;
        }

      case LIEF_DT_FLAGS:
        {
          Elf_DynamicEntry_Flags_t* e = (Elf_DynamicEntry_Flags_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " ",
            e->tag,
            e->value);

          fprintf(stdout, "\n");
          break;
        }

      case LIEF_DT_FLAGS_1:
        {
          Elf_DynamicEntry_Flags_t* e = (Elf_DynamicEntry_Flags_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " ",
            e->tag,
            e->value);
          fprintf(stdout, "\n");
          break;
        }


      case LIEF_DT_INIT_ARRAY:
      case LIEF_DT_FINI_ARRAY:
      case LIEF_DT_PREINIT_ARRAY:
        {
          Elf_DynamicEntry_Array_t* e = (Elf_DynamicEntry_Array_t*)entry;
          fprintf(stdout, ""
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " ",
            e->tag,
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
            "0x%010" PRIx64 " "
            "0x%010" PRIx64 " "
            "\n",
            entry->tag,
            entry->value
            );
          break;
        }
    }
  }

  elf_binary_destroy(elf_binary);

  return EXIT_SUCCESS;
}
