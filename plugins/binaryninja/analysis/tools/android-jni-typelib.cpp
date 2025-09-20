#include <filesystem>
#include "log.hpp"

#include <binaryninja/binaryninjaapi.h>

using namespace BinaryNinja;

int main(int argc, const char** argv) {
  if (argc != 3) {
    BN_ERR("Usage: {} <path>/jni.h <output>", argv[0]);
    BN_ERR("-- Example: {} $ANDROID_HOME/ndk/29.0.13846066/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/jni.h $HOME/android-jni.bntl", argv[0]);
    return EXIT_FAILURE;
  }

  std::filesystem::path jni_file = argv[1];
  if (!std::filesystem::is_regular_file(jni_file)) {
    BN_ERR("Missing file: {}", jni_file.string());
    return EXIT_FAILURE;
  }
  InitPlugins();

  Ref<Platform> Platform = Platform::GetByName("linux-aarch64");
  Ref<Architecture> Arch = Platform->GetArchitecture();

  std::map<QualifiedName, Ref<Type>> types;
  std::map<QualifiedName, Ref<Type>> variables;
  std::map<QualifiedName, Ref<Type>> functions;
  std::string error;

  std::string incdirs;
  if (char* value = getenv("BN_INCLUDE_DIR")) {
    incdirs = value;
  }

  BN_INFO("Include dir: {}", incdirs);

  bool is_ok = Platform->ParseTypesFromSourceFile(
      /* File           */ jni_file.string(),
      /* out: types     */ types,
      /* out: variables */ variables,
      /* out: functions */ functions,
      /* out: erro      */ error,
      /* Include dirs   */ {
        incdirs
      }
  );

  if (!is_ok) {
    BN_ERR("JNI Parsing with errors: {}", error);
    return EXIT_FAILURE;
  }

  TypeLibrary TL(Arch, "JNI");

  BN_INFO("Adding Functions (#{})", functions.size());
  for (const auto& [N, T] : functions) {
    BN_INFO("[FUNC] {}: {}", N.GetString(), T->GetString());
    TL.AddNamedObject(N, T);
  }

  BN_INFO("Adding Types (#{})", types.size());
  for (const auto& [N, T] : types) {
    BN_INFO("[TYPE] {}: {}", N.GetString(), T->GetString());
    TL.AddNamedType(N, T);
  }

  TL.AddPlatform(Platform);
  TL.Finalize();
  TL.WriteToFile(argv[2]);
  BN_INFO("Typelib written to {}", std::filesystem::absolute(argv[2]).string());

  BNShutdown();

  return EXIT_SUCCESS;
}
