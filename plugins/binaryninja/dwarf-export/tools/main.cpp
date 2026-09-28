#include <string_view>
#include <system_error>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#include <LIEF/utils.hpp>
#include <binaryninja/binaryninjaapi.h>
#include <binaryninja/binaryninjacore.h>
#include <fmt/format.h>

#include "binaryninja/dwarf-export/DwarfExport.hpp"
#include "binaryninja/dwarf-export/log.hpp"
#include "binaryninja/utils.hpp"

namespace BN = BinaryNinja;
namespace fs = std::filesystem;

using Logger = binaryninja::core::Logger;

void usage(FILE* stream, const char* program) {
  fmt::print(stream,
             "Usage: {} <input.bndb> [--debug] [--output <out.dwarf>]\n\n"
             "Export saved Binary Ninja analysis as DWARF.\n"
             "  -o, --output <path>  Output file (default: <input>.dwarf next to "
             "the database)\n"
             "  -d, --debug          Debug logs\n",
             "  -h, --help           Show this help\n", program);
}


int export_dwarf(const fs::path& input, const fs::path& output,
                 bool debug = false) {

  std::error_code ec;
  if (!fs::is_regular_file(input, ec)) {
    fmt::print(stderr, "Error: cannot read input file '{}'.\n", input.string());
    return EXIT_FAILURE;
  }

  if (fs::exists(output, ec)) {
    if (fs::equivalent(input, output, ec)) {
      fmt::print(stderr, "Error: output must not overwrite the input database.\n");
      return EXIT_FAILURE;
    }

    if (ec || !fs::is_regular_file(output, ec)) {
      fmt::print(stderr, "Error: invalid output file '{}'.\n", output.string());
      return EXIT_FAILURE;
    }

  } else if (ec) {
    fmt::print(stderr, "Error: cannot access output '{}': {}.\n", output.string(),
               ec.message());
    return EXIT_FAILURE;
  }

  if (!LIEF::is_extended()) {
    fmt::print(stderr, "Error: DWARF export requires LIEF Extended.\n");
    return EXIT_FAILURE;
  }

  binaryninja::CoreSession session;
  BN::LogToStderr(WarningLog);
  BN::SetBundledPluginDirectory(BN::GetBundledPluginDirectory());

  Logger::instance(dwarf_plugin::BN_PLUGIN_LOG_NAME)
      .set_level(debug ? Logger::Level::Debug : Logger::Level::Warn);

  if (!BN::InitPlugins()) {
    fmt::print(stderr, "Error: could not initialize Binary Ninja plugins.\n");
    return EXIT_FAILURE;
  }

  BN::Ref<BN::BinaryView> view =
      BN::Load(input.string(), /*updateAnalysis=*/false);

  if (!view) {
    fmt::print(stderr, "Error: could not load '{}'.\n", input.string());
    return EXIT_FAILURE;
  }

  binaryninja::CloseView close_view{*view};

  if (!view->GetFile()->IsBackedByDatabase()) {
    fmt::print(stderr, "Error: '{}' is not a Binary Ninja database.\n",
               input.string());
    return EXIT_FAILURE;
  }

  if (!view->GetDefaultArchitecture() || !view->GetDefaultPlatform()) {
    fmt::print(stderr,
               "Error: input has no supported architecture or platform.\n");
    return EXIT_FAILURE;
  }

  BN::Ref<BN::TemporaryFile> temporary = new BN::TemporaryFile();

  if (!temporary->IsValid()) {
    fmt::print(stderr, "Error: could not create a temporary DWARF file.\n");
    return EXIT_FAILURE;
  }

  const std::string temporary_path = temporary->GetPath();

  auto exporter = dwarf_plugin::DwarfExport::from_bv(*view);
  if (exporter->save(temporary_path).empty() ||
      fs::file_size(temporary_path, ec) == 0 || ec)
  {
    fmt::print(stderr, "Error: could not generate DWARF for '{}'.\n",
               input.string());
    return EXIT_FAILURE;
  }

  if (!fs::copy_file(temporary_path, output, fs::copy_options::overwrite_existing,
                     ec))
  {
    fmt::print(stderr, "Error: could not write '{}': {}.\n", output.string(),
               ec.message());
    return EXIT_FAILURE;
  }

  fmt::print("DWARF saved to {}\n", output.string());
  return EXIT_SUCCESS;
}


int main(int argc, const char** argv) {
  fs::path input;
  fs::path output;

  bool positional_only = false;
  bool debug = false;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];
    if (!positional_only && (arg == "--help" || arg == "-h")) {
      usage(stdout, argv[0]);
      return EXIT_SUCCESS;
    }

    if (!positional_only && (arg == "--debug" || arg == "-d")) {
      debug = true;
      continue;
    }

    if (!positional_only && arg == "--") {
      positional_only = true;
      continue;
    }

    if (!positional_only &&
        (arg == "--output" || arg == "-o" || arg.starts_with("--output=")))
    {
      if (!output.empty()) {
        fmt::print(stderr, "Error: output may only be specified once.\n");
        return EXIT_FAILURE;
      }

      if (arg.starts_with("--output=")) {
        arg.remove_prefix(std::string_view("--output=").size());
      } else if (i + 1 < argc && argv[i + 1][0] != '-') {
        arg = argv[++i];
      } else {
        fmt::print(stderr, "Error: {} requires an output path.\n", arg);
        return EXIT_FAILURE;
      }

      if (arg.empty()) {
        fmt::print(stderr, "Error: output path must not be empty.\n");
        return EXIT_FAILURE;
      }

      output = arg;
      continue;
    }

    if (!positional_only && arg.starts_with('-')) {
      fmt::print(stderr, "Error: unknown option '{}'.\n", arg);
      usage(stderr, argv[0]);
      return EXIT_FAILURE;
    }

    if (!input.empty() || arg.empty()) {
      fmt::print(stderr, "Error: expected one input database.\n");
      usage(stderr, argv[0]);
      return EXIT_FAILURE;
    }

    input = arg;
  }

  if (input.empty()) {
    usage(stderr, argv[0]);
    return EXIT_FAILURE;
  }

  if (output.empty()) {
    output = input;
    output.replace_extension(".dwarf");
  }

  return export_dwarf(input, output, debug);
}
