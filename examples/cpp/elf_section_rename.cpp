/* Copyright 2017 - 2022 R. Thomas
 * Copyright 2017 - 2022 Quarkslab
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
#include <iostream>
#include <memory>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>

#include <LIEF/ELF.hpp>

//
// Rename the first section name.
// Ex: ./tools/ELFSectionRename /bin/ls ./lsRename
//
// $ readelf -S /bin/ls
//
//  [Nr] Nom               Type             Adresse           Décalage
//       Taille            TaillEntrée      Fanion Lien  Info  Alignement
//  [ 0]                   NULL             0000000000000000  00000000
//       0000000000000000  0000000000000000           0     0     0
//  [ 1] .interp           PROGBITS         0000000000400238  00000238
//       000000000000001c  0000000000000000   A       0     0     1
//  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
//       0000000000000020  0000000000000000   A       0     0     4
//
// $ readelf -S ./lsRename
//
//  En-têtes de section:
//  [Nr] Nom               Type             Adresse           Décalage
//       Taille            TaillEntrée      Fanion Lien  Info  Alignement
//  [ 0] toto              NULL             0000000000000000  00000000
//       0000000000000000  0000000000000000           0     0     0
//  [ 1] .interp           PROGBITS         0000000000400238  00000238
//       000000000000001c  0000000000000000   A       0     0     1
//  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
//       0000000000000020  0000000000000000   A       0     0     4
//  ....
//
//
//
int main(int argc, char **argv) {
  std::cout << "ELF Section rename" << '\n';
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <Original Binary> <Output Binary>" << '\n';
    return -1;
  }

  std::unique_ptr<LIEF::ELF::Binary> binary{LIEF::ELF::Parser::parse(argv[1])};

  LIEF::ELF::Section& section = binary->sections()[0];
  section.name("toto");
  binary->write(argv[2]);

  return 0;


}
