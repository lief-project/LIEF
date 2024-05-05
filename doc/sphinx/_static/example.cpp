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
#include <iostream>
#include <string>

class MyClass {
  public:
    MyClass(void) : message_{"hello"} {};
    MyClass(const std::string& message) : message_{message} {};
    void say_hello(void) { std::cout << this->message_<< '\n'; }

  private:
    std::string message_;
};


int main(void) {
  MyClass a{"Bonjour"};
  a.say_hello();
}
