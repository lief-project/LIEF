#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <LIEF/LIEF.h>


int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pe binary>\n", argv[0]);
    return EXIT_FAILURE ;
  }

  Pe_Binary_t *pe_binary = pe_parse(argv[1]);

  fprintf(stdout, "Binary Name: %s\n", pe_binary->name);

  Pe_DosHeader_t dos_header = pe_binary->dos_header;

  uint16_t *reserved = dos_header.reserved;
  uint16_t *reserved2 = dos_header.reserved2;

  fprintf(stdout, "DosHeader\n");
  fprintf(stdout, "=========\n");
  fprintf(stdout, "Used bytes in the last page: 0x%x\n",   dos_header.used_bytes_in_the_last_page);
  fprintf(stdout, "File size in pages: 0x%x\n",            dos_header.file_size_in_pages);
  fprintf(stdout, "Number of relocations: 0x%x\n",         dos_header.numberof_relocation);
  fprintf(stdout, "Header size in paragraphs: 0x%x\n",     dos_header.header_size_in_paragraphs);
  fprintf(stdout, "Minimum extra paragraphs: 0x%x\n",      dos_header.minimum_extra_paragraphs);
  fprintf(stdout, "Maximum extra paragraphs: 0x%x\n",      dos_header.maximum_extra_paragraphs);
  fprintf(stdout, "Initial relative ss: 0x%x\n",           dos_header.initial_relative_ss);
  fprintf(stdout, "Initial sp: 0x%x\n",                    dos_header.initial_sp);
  fprintf(stdout, "Checksum: 0x%x\n",                      dos_header.checksum);
  fprintf(stdout, "Initial ip: 0x%x\n",                    dos_header.initial_ip);
  fprintf(stdout, "Initial relative cs: 0x%x\n",           dos_header.initial_relative_cs);
  fprintf(stdout, "Address of relocation table: 0x%x\n",   dos_header.addressof_relocation_table);
  fprintf(stdout, "Overlay number: 0x%x\n",                dos_header.overlay_number);
  fprintf(stdout, "Reserved: %x %x %x %x\n",               reserved[0], reserved[1], reserved[2], reserved[3]);
  fprintf(stdout, "OEM id: 0x%x\n",                        dos_header.oem_id);
  fprintf(stdout, "OEM info: 0x%x\n",                      dos_header.oem_info);
  fprintf(stdout, "Reserved2: %x %x %x %x %x %x %x %x %x %x\n",
      reserved2[0], reserved2[1], reserved2[2], reserved2[3], reserved2[4],
      reserved2[5], reserved2[6], reserved2[7], reserved2[8], reserved2[9]);
  fprintf(stdout, "Address of new exeheader: 0x%x\n",      dos_header.addressof_new_exeheader);


  Pe_Header_t header = pe_binary->header;
  fprintf(stdout, "Header\n");
  fprintf(stdout, "======\n");
  fprintf(stdout, "Machine: %s\n",                   MACHINE_TYPES_to_string(header.machine));
  fprintf(stdout, "Number of sections: %d\n",        header.numberof_sections);
  fprintf(stdout, "Timestamp: 0x%x\n",               header.time_date_stamp);
  fprintf(stdout, "Pointer to symbol table: 0x%x\n", header.pointerto_symbol_table);
  fprintf(stdout, "Number of symbols: %d\n",         header.numberof_symbols);
  fprintf(stdout, "Sizeof optional header: 0x%x\n",  header.sizeof_optional_header);
  fprintf(stdout, "Characteristics: 0x%x\n",         header.characteristics);


  Pe_OptionalHeader_t optional_header = pe_binary->optional_header;
  fprintf(stdout, "Optional Header\n");
  fprintf(stdout, "===============\n");
  fprintf(stdout, "Magic: %s\n", PE_TYPES_to_string(optional_header.magic));
  fprintf(stdout, "Major linker version: 0x%x\n",           optional_header.major_linker_version);
  fprintf(stdout, "Minor linker version: 0x%x\n",           optional_header.minor_linker_version);
  fprintf(stdout, "Size ofcode: 0x%x\n",                    optional_header.sizeof_code);
  fprintf(stdout, "Size of initialized data: 0x%x\n",       optional_header.sizeof_initialized_data);
  fprintf(stdout, "Size of uninitialized data: 0x%x\n",     optional_header.sizeof_uninitialized_data);
  fprintf(stdout, "Address of entrypoint: 0x%x\n",          optional_header.addressof_entrypoint);
  fprintf(stdout, "Base of code: 0x%x\n",                   optional_header.baseof_code);
  fprintf(stdout, "Base of data: 0x%x\n",                   optional_header.baseof_data);
  fprintf(stdout, "Imagebase: 0x%" PRIx64 "\n",             optional_header.imagebase);
  fprintf(stdout, "Section alignment: 0x%x\n",              optional_header.section_alignment);
  fprintf(stdout, "File alignment: 0x%x\n",                 optional_header.file_alignment);
  fprintf(stdout, "Major operating system version: 0x%x\n", optional_header.major_operating_system_version);
  fprintf(stdout, "Minor operating system version: 0x%x\n", optional_header.minor_operating_system_version);
  fprintf(stdout, "Major image version: 0x%x\n",            optional_header.major_image_version);
  fprintf(stdout, "Minor image version: 0x%x\n",            optional_header.minor_image_version);
  fprintf(stdout, "Major subsystem version: 0x%x\n",        optional_header.major_subsystem_version);
  fprintf(stdout, "Minor subsystem version: 0x%x\n",        optional_header.minor_subsystem_version);
  fprintf(stdout, "Win32 version value: 0x%x\n",            optional_header.win32_version_value);
  fprintf(stdout, "Size of image: 0x%x\n",                  optional_header.sizeof_image);
  fprintf(stdout, "Size of headers: 0x%x\n",                optional_header.sizeof_headers);
  fprintf(stdout, "Checksum: 0x%x\n",                       optional_header.checksum);
  fprintf(stdout, "subsystem: %s\n",                        SUBSYSTEM_to_string(optional_header.subsystem));
  fprintf(stdout, "DLL characteristics: 0x%x\n",            optional_header.dll_characteristics);
  fprintf(stdout, "Size of stack reserve: 0x%" PRIx64 "\n", optional_header.sizeof_stack_reserve);
  fprintf(stdout, "Size of stack commit: 0x%" PRIx64 "\n",  optional_header.sizeof_stack_commit);
  fprintf(stdout, "Size of heap reserve: 0x%" PRIx64 "\n",  optional_header.sizeof_heap_reserve);
  fprintf(stdout, "Size of heap commit: 0x%" PRIx64 "\n",   optional_header.sizeof_heap_commit);
  fprintf(stdout, "Loader flags: 0x%x\n",                   optional_header.loader_flags);
  fprintf(stdout, "Number of rva and size: 0x%x\n",         optional_header.numberof_rva_and_size);


  fprintf(stdout, "\nDataDirectories\n");
  fprintf(stdout,   "===============\n");
  Pe_DataDirectory_t** data_directories = pe_binary->data_directories;
  for (size_t i = 0; data_directories[i] != NULL; ++i) {
    fprintf(stdout, "RVA 0x%"  PRIx32 "\n", data_directories[i]->rva);
    fprintf(stdout, "Size 0x%" PRIx32 "\n", data_directories[i]->size);
  }

  fprintf(stdout, "\nSections\n");
  fprintf(stdout,   "========\n");

  Pe_Section_t** sections = pe_binary->sections;
  for (size_t i = 0; sections[i] != NULL; ++i) {
    Pe_Section_t* section = sections[i];
    fprintf(stdout, ""
        "%-20s "
        "0x%06" PRIx64 " "
        "0x%06" PRIx64 " "
        "0x%06" PRIx64 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "0x%06" PRIx32 " "
        "%.6f "
        "\n",
        section->name,
        section->virtual_address,
        section->size,
        section->offset,
        section->virtual_size,
        section->pointerto_relocation,
        section->pointerto_line_numbers,
        section->characteristics,
        section->entropy
        );

    if (section->size > 3 && section->content != NULL) {
      fprintf(stdout, "content[0..3]: %02x %02x %02x\n",
          section->content[0], section->content[1], section->content[2]);
    }
  }


  fprintf(stdout, "\nImports\n");
  fprintf(stdout,   "========\n");
  Pe_Import_t** imports = pe_binary->imports;
  if (imports != NULL) {
    for (size_t i = 0; imports[i] != NULL; ++i) {
      fprintf(stdout, "Name: %s\n", imports[i]->name);
      Pe_ImportEntry_t** entries = imports[i]->entries;
      for (size_t i = 0; entries[i] != NULL; ++i) {
        if (entries[i]->name != NULL) {
          fprintf(stdout, "   %s\n", entries[i]->name);
        }
      }

    }
  }



  pe_binary_destroy(pe_binary);

  return EXIT_SUCCESS;

}
