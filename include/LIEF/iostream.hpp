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
#ifndef LIEF_OSTREAM_H_
#define LIEF_OSTREAM_H_
#include <istream>
#include <streambuf>
#include <cstdint>
#include <vector>

namespace LIEF {
class vector_iostream {
  public:

  using pos_type = std::streampos;
  using off_type = std::streamoff;

  vector_iostream(void);
  void reserve(size_t size);

  vector_iostream& put(uint8_t c);
  vector_iostream& write(const uint8_t* s, std::streamsize n);
  vector_iostream& write(const std::vector<uint8_t>& s);
  vector_iostream& write(std::vector<uint8_t>&& s);

  vector_iostream& get(std::vector<uint8_t>& c);

  vector_iostream& flush();

  // seeks:
  pos_type tellp(void);
  vector_iostream& seekp(pos_type p);
  vector_iostream& seekp(vector_iostream::off_type p, std::ios_base::seekdir dir);

  const std::vector<uint8_t>& raw(void) const;

  private:
  pos_type             current_pos_;
  std::vector<uint8_t> raw_;
};


// From https://stackoverflow.com/questions/27336335/c-cout-with-prefix
class prefixbuf : public std::streambuf {
  public:
  prefixbuf(std::string const& prefix, std::streambuf* sbuf);

  private:
  std::string     prefix;
  std::streambuf* sbuf;
  bool            need_prefix;

  int sync(void);
  int overflow(int c);
};

class oprefixstream : private virtual prefixbuf, public std::ostream {
  public:
  oprefixstream(std::string const& prefix, std::ostream& out);
};

}
#endif
