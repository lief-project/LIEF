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
#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#include <LIEF/iterators.hpp>

using namespace LIEF;
using it_const_ref_t = const_ref_iterator<std::vector<std::string>>;
using it_ref_local_t = ref_iterator<std::vector<std::string>>;
using it_ref_t       = ref_iterator<std::vector<std::string>&>;

using it_const_ref_ptr_t = const_ref_iterator<std::vector<std::string*>>;
using it_ref_ptr_t       = ref_iterator<std::vector<std::string*>>;

using it_filter_ref          = filter_iterator<std::vector<std::string>&>;
using it_filter_ref_local_t  = filter_iterator<std::vector<std::string>>;
using it_filter_ref_ptr      = filter_iterator<std::vector<std::string*>>;

using it_filter_const_ref       = const_filter_iterator<const std::vector<std::string>&>;
using it_filter_const_ref_local = const_filter_iterator<std::vector<std::string>>;
using it_filter_const_ref_ptr   = const_filter_iterator<std::vector<std::string*>>;

struct Dummy {
  Dummy(void) : s_{"dummy"} {}
  Dummy(const Dummy&) = delete;
  Dummy& operator=(const Dummy&) = delete;
  std::string s_;
};

using it_ref_dummies_t       = ref_iterator<std::vector<Dummy>&>;

struct Foo {
  Foo(void) : dummies_(10) {
    bar.push_back("1");
    bar.push_back("2");
    bar.push_back("3");
    bar.push_back("4");
    bar.push_back("5");
    bar.push_back("6");
    bar.push_back("6");
    bar.push_back("6");

    bar_ptr.push_back(new std::string{"1"});
    bar_ptr.push_back(new std::string{"2"});
    bar_ptr.push_back(new std::string{"3"});
    bar_ptr.push_back(new std::string{"4"});
    bar_ptr.push_back(new std::string{"5"});
    bar_ptr.push_back(new std::string{"6"});
    bar_ptr.push_back(new std::string{"6"});
  }

  ~Foo(void) {
    for (std::string* ptr : this->bar_ptr) {
      delete ptr;
    }
  }

  it_const_ref_t get_bar(void) const {
    return {this->bar};
  }


  it_ref_t get_bar(void) {
    return {this->bar};
  }

  it_filter_ref filter_always_true(void) {
    return {this->bar, [] (const std::string& v) { return true; }};
  }

  it_filter_ref get_bar_filter(void) {
    return {this->bar, [] (const std::string& v) { return v == "6" || v == "1" || v == "foo"; }};
  }


  it_filter_ref get_bar_filter_empty(void) {
    return {this->bar, [] (const std::string& v) { return v == "foo"; }};
  }


  it_filter_const_ref get_bar_filter(void) const {
    return {this->bar, [] (const std::string& v) { return v == "6" || v == "1" || v == "foo"; }};
  }


  it_filter_ref_ptr get_bar_ptr_filter(void) {
    return {this->bar_ptr, [] (const std::string* v) { return *v == "6"; }};
  }

  it_filter_const_ref_ptr get_bar_ptr_filter(void) const {
    return {this->bar_ptr, [] (const std::string* v) { return *v == "6"; }};
  }


  it_ref_local_t get_bar_local(void) {
    std::vector<std::string> local = {"a", "b", "c"};
    return {local};
  }


  it_filter_const_ref_local get_bar_const_filter_local(void) const {
    std::vector<std::string> local = {"a", "b", "c", "a", "a"};
    return {local, [] (const std::string& v) { return v == "a"; }};
  }



  it_ref_dummies_t get_dummies(void) {
    return {this->dummies_};
  }

  it_const_ref_ptr_t get_bar_ptr(void) const {
    return {bar_ptr};
  }

  it_ref_ptr_t get_bar_ptr(void) {
    return {bar_ptr};
  }

  std::vector<Dummy> dummies_;
  std::vector<std::string> bar;
  std::vector<std::string*> bar_ptr;
};


TEST_CASE("Test const ref iterators", "[lief][iterators][const_ref]") {

  const Foo foo;

  SECTION("operator++") {
    it_const_ref_t bars = foo.get_bar();
    REQUIRE(*(bars++) == "1");
    REQUIRE(*bars == "2");
  }


  SECTION("operator++(int)") {
    it_const_ref_t bars = foo.get_bar();
    REQUIRE(*(++bars) == "2");
    REQUIRE(*(++bars) == "3");
    REQUIRE(*(++bars) == "4");
  }


  SECTION("operator--") {
    it_const_ref_t bars = foo.get_bar();
    ++bars;
    REQUIRE(*(bars--) == "2");
    REQUIRE(*bars == "1");
  }


  SECTION("operator--(int)") {
    it_const_ref_t bars = foo.get_bar();

    ++bars;
    REQUIRE(*(--bars) == "1");
    REQUIRE(*bars == "1");
  }


  SECTION("operator+=") {
    it_const_ref_t bars = foo.get_bar();
    bars += 2;
    REQUIRE(*bars == "3");
  }


  SECTION("operator-=") {
    it_const_ref_t bars = foo.get_bar();
    bars += 4;
    REQUIRE(*bars == "5");

    bars -= 2;
    REQUIRE(*bars == "3");
  }

  SECTION("operator[]") {
    it_const_ref_t bars = foo.get_bar();
    REQUIRE(bars[4] == "5");
  }


  SECTION("operator+") {
    it_const_ref_t bars = foo.get_bar();
    REQUIRE(*(bars + 5) == "6");
  }


  SECTION("operator-") {
    it_const_ref_t bars = foo.get_bar();
    bars += 4;
    REQUIRE(*(bars - 1) == "4");
  }


  SECTION("Comparaisons") {
    it_const_ref_t bars_lhs = foo.get_bar();
    it_const_ref_t bars_rhs = foo.get_bar();
    REQUIRE(bars_lhs == bars_rhs);
    REQUIRE(std::begin(bars_lhs) == std::begin(bars_rhs));
    REQUIRE(std::end(bars_lhs) == std::end(bars_rhs));
    REQUIRE(std::end(bars_lhs) != std::begin(bars_rhs));

    REQUIRE((bars_lhs + 5) == (bars_rhs + 5));
    REQUIRE((bars_lhs + 5) != (bars_rhs + 6));

    it_const_ref_t it1 = bars_lhs + 5;
    it_const_ref_t it2 = bars_rhs + 4;

    REQUIRE(it1 != it2);
    REQUIRE((it1 - 1) == it2);
    REQUIRE((it1 - it2) == 1);

    REQUIRE(it1 > it2);
    REQUIRE(it1 >= it1);


    REQUIRE(it2 < it1);
    REQUIRE(it2 <= it2);
  }


  SECTION("Internal management") {
    it_const_ref_t bars = foo.get_bar();
    it_const_ref_ptr_t bars_ptr = foo.get_bar_ptr();

    REQUIRE(bars.size() == foo.bar.size());
    REQUIRE(bars_ptr.size() == foo.bar_ptr.size());
    REQUIRE(*bars_ptr == "1");
    REQUIRE(std::string(bars_ptr->c_str()) == "1");
    REQUIRE(bars_ptr[2] == "3");

    REQUIRE(std::string(bars->c_str()) == "1");
    REQUIRE(std::string(bars_ptr->c_str()) == "1");
    size_t count = std::count_if(
      std::begin(bars),
      std::end(bars),
      [] (const std::string& s) {
        return s == "6";
      });

    REQUIRE(count == 3);

    it_const_ref_t bar_operator_equal{bars};
    bar_operator_equal += 2;
    //bar_operator_equal.operator=(bars);
    //REQUIRE(bar_operator_equal == bars);

  }
}

TEST_CASE("Test ref iterators", "[lief][iterators][ref]") {
  Foo foo;

  SECTION("operator++") {
    it_ref_t bars = foo.get_bar();
    REQUIRE(*(bars++) == "1");
    REQUIRE(*bars == "2");
  }

  SECTION("operator++(int)") {
    it_ref_t bars = foo.get_bar();
    REQUIRE(*(++bars) == "2");
    REQUIRE(*(++bars) == "3");
    REQUIRE(*(++bars) == "4");
  }


  SECTION("operator--") {
    it_ref_t bars = foo.get_bar();
    ++bars;
    REQUIRE(*(bars--) == "2");
    REQUIRE(*bars == "1");
  }


  SECTION("operator--(int)") {
    it_ref_t bars = foo.get_bar();

    ++bars;
    REQUIRE(*(--bars) == "1");
    REQUIRE(*bars == "1");
  }


  SECTION("operator+=") {
    it_ref_t bars = foo.get_bar();
    bars += 2;
    REQUIRE(*bars == "3");
  }


  SECTION("operator-=") {
    it_ref_t bars = foo.get_bar();
    bars += 4;
    REQUIRE(*bars == "5");

    bars -= 2;
    REQUIRE(*bars == "3");
  }

  SECTION("operator[]") {
    it_ref_t bars = foo.get_bar();
    REQUIRE(bars[4] == "5");
  }


  SECTION("operator+") {
    it_ref_t bars = foo.get_bar();
    REQUIRE(*(bars + 5) == "6");
  }


  SECTION("operator-") {
    it_ref_t bars = foo.get_bar();
    bars += 4;
    REQUIRE(*(bars - 1) == "4");
  }


  SECTION("Comparaisons") {
    it_ref_t bars_lhs = foo.get_bar();
    it_ref_t bars_rhs = foo.get_bar();
    REQUIRE(bars_lhs == bars_rhs);
    REQUIRE(std::begin(bars_lhs) == std::begin(bars_lhs));
    REQUIRE(std::end(bars_lhs) == std::end(bars_lhs));

    REQUIRE(std::begin(bars_lhs) == std::begin(bars_rhs));
    REQUIRE(std::end(bars_lhs) == std::end(bars_rhs));
    REQUIRE(std::end(bars_lhs) != std::begin(bars_rhs));

    REQUIRE((bars_lhs + 5) == (bars_rhs + 5));
    REQUIRE((bars_lhs + 5) != (bars_rhs + 6));

    it_ref_t it1 = bars_lhs + 5;
    it_ref_t it2 = bars_rhs + 4;

    REQUIRE(it1 != it2);
    REQUIRE((it1 - 1) == it2);
    REQUIRE((it1 - it2) == 1);

    REQUIRE(it1 > it2);
    REQUIRE(it1 >= it1);


    REQUIRE(it2 < it1);
    REQUIRE(it2 <= it2);
  }


  SECTION("Internal management") {
    it_ref_t bars = foo.get_bar();
    it_ref_ptr_t bars_ptr = foo.get_bar_ptr();

    REQUIRE(bars.size() == foo.bar.size());
    REQUIRE(bars_ptr.size() == foo.bar_ptr.size());
    REQUIRE(*bars_ptr == "1");
    REQUIRE(std::string(bars_ptr->c_str()) == "1");
    REQUIRE(bars_ptr[2] == "3");

    REQUIRE(std::string(bars->c_str()) == "1");
    REQUIRE(std::string(bars_ptr->c_str()) == "1");
    size_t count = std::count_if(
      std::begin(bars),
      std::end(bars),
      [] (const std::string& s) {
        return s == "6";
      });

    REQUIRE(count == 3);

    it_ref_t bar_operator_equal{bars};
    bar_operator_equal += 2;
    bar_operator_equal.operator=(bars);
    REQUIRE(bar_operator_equal == bars);

    std::string& first_one_ptr = *bars_ptr;
    first_one_ptr = "123456";
    REQUIRE(foo.get_bar_ptr()[0] == "123456");


    *foo.get_bar() = "123456";
    CHECK(*foo.get_bar() == "123456");
    auto dummies = foo.get_dummies();
    Dummy& d = dummies[0];
    d.s_ = "zigzag";

    CHECK(foo.get_dummies()->s_ == "zigzag");


    it_ref_local_t local = foo.get_bar_local();
    CHECK(*local == "a");
    CHECK(std::begin(local) == std::begin(local));
    CHECK(std::end(local) == std::end(local));

  }
}


TEST_CASE("Test filter ref iterators", "[lief][iterators][filter][ref]") {
  Foo foo;

  SECTION("Always true") {
    it_filter_ref true_list = foo.filter_always_true();
    CHECK(true_list.size() == 8);
  }

  SECTION("operator++") {

    it_filter_ref bar_filtred         = foo.get_bar_filter();
    it_filter_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    CHECK(std::begin(bar_filtred) == std::begin(bar_filtred));

    CHECK(*bar_filtred     == "1");
    CHECK(*(++bar_filtred) == "6");
    CHECK(*(bar_filtred++) == "6");
    CHECK(*(++bar_filtred) == "6");
    CHECK(*(bar_filtred++) == "6");

    CHECK(bar_filtred == std::end(bar_filtred));

  }

  SECTION("size()") {

    it_filter_ref bar_filtred         = foo.get_bar_filter();
    it_filter_ref bar_filtred_empty   = foo.get_bar_filter_empty();
    it_filter_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    CHECK(bar_filtred.size() == 4);
    CHECK(bar_filtred_empty.size() == 0);
    CHECK(bar_ptr_filtred.size() == 2);
  }


  SECTION("operator[]") {

    it_filter_ref bar_filtred         = foo.get_bar_filter();
    it_filter_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    CHECK(bar_filtred[0] == "1");
  }


  SECTION("Internal management") {
    it_filter_ref bar_filtred         = foo.get_bar_filter();
    it_filter_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    bar_ptr_filtred[1] = "7";
    bar_filtred[0] = "foo";

    CHECK(foo.get_bar_filter()[0] == "foo");
    CHECK(foo.get_bar_ptr_filter().size() == 1);
  }

}

TEST_CASE("Test const filter ref iterators", "[lief][iterators][filter][const_ref]") {
  const Foo foo;

  SECTION("operator++") {

    it_filter_const_ref     bar_filtred     = foo.get_bar_filter();
    it_filter_const_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    CHECK(std::begin(bar_filtred) == std::begin(bar_filtred));

    CHECK(*bar_filtred     == "1");
    CHECK(*(++bar_filtred) == "6");
    CHECK(*(bar_filtred++) == "6");
    CHECK(*(++bar_filtred) == "6");
    CHECK(*(bar_filtred++) == "6");

    CHECK(bar_filtred == std::end(bar_filtred));

  }

  SECTION("size()") {

    it_filter_const_ref     bar_filtred     = foo.get_bar_filter();
    it_filter_const_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    CHECK(bar_filtred.size() == 4);
    CHECK(bar_ptr_filtred.size() == 2);
  }


  SECTION("operator[]") {

    it_filter_const_ref     bar_filtred     = foo.get_bar_filter();
    it_filter_const_ref_ptr bar_ptr_filtred = foo.get_bar_ptr_filter();

    CHECK(bar_filtred[1] == "6");
    CHECK(bar_filtred[0] == "1");

    CHECK(bar_ptr_filtred[1] == "6");
    CHECK(bar_ptr_filtred[0] == "6");
  }


  SECTION("local") {
    it_filter_const_ref_local bar_ptr_filtred = foo.get_bar_const_filter_local();
    CHECK(bar_ptr_filtred.size() == 3);

  }

}
