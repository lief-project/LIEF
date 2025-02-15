/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
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
#include "pyPE.hpp"
#include "LIEF/PE/enums.hpp"
#include "LIEF/PE/EnumToString.hpp"
#include "enums_wrapper.hpp"

#define PY_ENUM(x) to_string(x), x

namespace LIEF::PE::py {
void init_enums(nb::module_& m) {

  enum_<PE_TYPE>(m, "PE_TYPE")
    .value(PY_ENUM(PE_TYPE::PE32))
    .value(PY_ENUM(PE_TYPE::PE32_PLUS));

  enum_<ALGORITHMS>(m, "ALGORITHMS")
    .value(PY_ENUM(ALGORITHMS::UNKNOWN))
    .value(PY_ENUM(ALGORITHMS::SHA_512))
    .value(PY_ENUM(ALGORITHMS::SHA_384))
    .value(PY_ENUM(ALGORITHMS::SHA_256))
    .value(PY_ENUM(ALGORITHMS::SHA_1))
    .value(PY_ENUM(ALGORITHMS::MD5))
    .value(PY_ENUM(ALGORITHMS::MD4))
    .value(PY_ENUM(ALGORITHMS::MD2))
    .value(PY_ENUM(ALGORITHMS::RSA))
    .value(PY_ENUM(ALGORITHMS::EC))

    .value(PY_ENUM(ALGORITHMS::MD5_RSA))
    .value(PY_ENUM(ALGORITHMS::SHA1_DSA))
    .value(PY_ENUM(ALGORITHMS::SHA1_RSA))

    .value(PY_ENUM(ALGORITHMS::SHA_256_RSA))
    .value(PY_ENUM(ALGORITHMS::SHA_384_RSA))
    .value(PY_ENUM(ALGORITHMS::SHA_512_RSA))

    .value(PY_ENUM(ALGORITHMS::SHA1_ECDSA))
    .value(PY_ENUM(ALGORITHMS::SHA_256_ECDSA))
    .value(PY_ENUM(ALGORITHMS::SHA_384_ECDSA))
    .value(PY_ENUM(ALGORITHMS::SHA_512_ECDSA));
}
}
