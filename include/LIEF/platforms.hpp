/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PLATFORMS_H
#define LIEF_PLATFORMS_H
#include "LIEF/platforms/android.hpp"

#if defined(__APPLE__)
  #include "TargetConditionals.h"
#endif

namespace LIEF {

enum class PLATFORMS {
  UNKNOWN = 0,
  LINUX,
  ANDROID_PLAT,
  WINDOWS,
  IOS,
  OSX,
};

constexpr PLATFORMS current_platform() {
#if defined(__ANDROID__)
  return PLATFORMS::ANDROID_PLAT;
#elif defined(__linux__)
  return PLATFORMS::LINUX;
#elif defined(_WIN64) || defined(_WIN32)
  return PLATFORMS::WINDOWS;
#elif defined(__APPLE__)
  #if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
    return PLATFORMS::IOS;
  #else
    return PLATFORMS::OSX;
  #endif
#else
  return PLATFORMS::UNKNOWN;
#endif

}


}

#endif
