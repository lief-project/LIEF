#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <LIEF/LIEF.h>


void print_binary(Macho_Binary_t* binary) {
  Macho_Header_t header = binary->header;
  fprintf(stdout, "Header\n");
  fprintf(stdout, "========\n");
  fprintf(stdout, "Magic: 0x%" PRIx32 "\n",              header.magic);
  fprintf(stdout, "CPU Type: %d\n",                      header.cpu_type);
  fprintf(stdout, "CPU SubType: 0x%" PRIx32 "\n",        header.cpu_subtype);
  fprintf(stdout, "File type: %d\n",                     header.file_type);
  fprintf(stdout, "Number of commands: 0x%" PRIx32 "\n", header.nb_cmds);
  fprintf(stdout, "Commands size: 0x%" PRIx32 "\n",      header.sizeof_cmds);
  fprintf(stdout, "flags: 0x%" PRIx32 "\n",              header.flags);
  fprintf(stdout, "reserved: 0x%" PRIx32 "\n",           header.reserved);

  fprintf(stdout, "Commands\n");
  fprintf(stdout, "========\n");
  Macho_Command_t** commands = binary->commands;
  size_t i = 0;
  for (i = 0; commands[i] != NULL; ++i) {
    Macho_Command_t* command = commands[i];
    fprintf(stdout, ""
        "%d "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "\n",
        command->command,
        command->size,
        command->offset
        );
    if (command->size > 3) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          command->data[0], command->data[1], command->data[2]);
    }
  }

  fprintf(stdout, "Segments\n");
  fprintf(stdout, "========\n");
  Macho_Segment_t** segments = binary->segments;
  for (i = 0; segments[i] != NULL; ++i) {
    Macho_Segment_t* segment = segments[i];
    fprintf(stdout, ""
        "%-20s "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "\n",
        segment->name,
        segment->virtual_address,
        segment->virtual_size,
        segment->file_size,
        segment->file_offset,
        segment->max_protection,
        segment->init_protection,
        segment->numberof_sections,
        segment->flags
        );

    if (segment->file_size > 3) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          segment->content[0], segment->content[1], segment->content[2]);
    }
  }


  fprintf(stdout, "Sections\n");
  fprintf(stdout, "========\n");
  Macho_Section_t** sections = binary->sections;
  for (i = 0; sections[i] != NULL; ++i) {
    Macho_Section_t* section = sections[i];
    fprintf(stdout, ""
        "%-20s "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "%d "
        "0x%02" PRIx32 " "
        "0x%02" PRIx32 " "
        "0x%02" PRIx32 " "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "0x%010" PRIx64 " "
        "%.6f "
        "\n",
        section->name,
        section->alignment,
        section->relocation_offset,
        section->numberof_relocations,
        section->flags,
        section->type,
        section->reserved1,
        section->reserved2,
        section->reserved3,
        section->virtual_address,
        section->offset,
        section->size,
        section->entropy
        );
    if (section->size > 3) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          section->content[0], section->content[1], section->content[2]);
    }
  }

  fprintf(stdout, "Symbols\n");
  fprintf(stdout, "=======\n");
  Macho_Symbol_t** symbols = binary->symbols;
  for (i = 0; symbols[i] != NULL; ++i) {
    Macho_Symbol_t* symbol = symbols[i];
    fprintf(stdout, ""
        "%-30s "
        "0x%02" PRIx32 " "
        "0x%02" PRIx32 " "
        "0x%04" PRIx16 " "
        "0x%010" PRIx64 " "
        "\n",
        symbol->name,
        (uint32_t)symbol->type,
        (uint32_t)symbol->numberof_sections,
        symbol->description,
        symbol->value
        );
  }


}

int main(int argc, char **argv) {
  size_t idx;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <MachO binary>\n", argv[0]);
    return EXIT_FAILURE ;
  }

  Macho_Binary_t** macho_binaries = macho_parse(argv[1]);

  if (macho_binaries == NULL) {
    return EXIT_FAILURE;
  }

  for (idx = 0; macho_binaries[idx] != NULL; ++idx) {
    print_binary(macho_binaries[idx]);
  }


  macho_binaries_destroy(macho_binaries);

  return EXIT_SUCCESS;

}
