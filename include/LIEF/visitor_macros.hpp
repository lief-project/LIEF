/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
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
#ifndef LIEF_VISITOR_MACROS_H_
#define LIEF_VISITOR_MACROS_H_
#include "LIEF/config.h"

// PE Support
// ==========
#if defined(LIEF_PE_SUPPORT)
  #define LIEF_PE_FORWARD(OBJ) \
    namespace PE   {           \
    class OBJ;                 \
    }

  #define LIEF_PE_VISITABLE(OBJ) \
    virtual void visit(const PE::OBJ&) {}
#else
  #define LIEF_PE_VISITABLE(OBJ)
  #define LIEF_PE_FORWARD(OBJ)
#endif


// ELF Support
// ===========
#if defined(LIEF_ELF_SUPPORT)
  #define LIEF_ELF_FORWARD(OBJ) \
    namespace ELF   {           \
    class OBJ;                 \
    }
  #define LIEF_ELF_VISITABLE(OBJ)         \
    virtual void visit(const ELF::OBJ&) {}
#else
  #define LIEF_ELF_FORWARD(OBJ)
  #define LIEF_ELF_VISITABLE(OBJ)
#endif

// MachO Support
// =============
#if defined(LIEF_MACHO_SUPPORT)
  #define LIEF_MACHO_FORWARD(OBJ) \
    namespace MachO   {           \
    class OBJ;                 \
    }
  #define LIEF_MACHO_VISITABLE(OBJ) \
    virtual void visit(const MachO::OBJ&) {}
#else
  #define LIEF_MACHO_FORWARD(OBJ)
  #define LIEF_MACHO_VISITABLE(OBJ)
#endif

#define LIEF_ABSTRACT_FORWARD(OBJ) \
  class OBJ;

#define LIEF_ABSTRACT_VISITABLE(OBJ) \
  virtual void visit(const OBJ&) {}


#endif
