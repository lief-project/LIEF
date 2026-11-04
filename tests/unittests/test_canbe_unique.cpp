/* Copyright 2026 R. Thomas
 * Copyright 2026 Quarkslab
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
#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <utility>

#include "LIEF/canbe_unique.hpp"

using LIEF::details::canbe_unique;

struct Counted {
  static inline int alive = 0;

  explicit Counted(int value) :
    value(value) {
    ++alive;
  }

  Counted(const Counted&) = delete;
  Counted& operator=(const Counted&) = delete;

  ~Counted() {
    --alive;
  }

  int value = 0;
};

struct Node {
  static inline const Node* observed = nullptr;

  ~Node() {
    observed = holder->get();
  }

  canbe_unique<Node>* holder = nullptr;
};

struct List {
  explicit List(int value) :
    value(value) {
    ++Counted::alive;
  }

  ~List() {
    --Counted::alive;
  }

  int value = 0;
  canbe_unique<List> next;
};

using cu_t = canbe_unique<Counted>;


TEST_CASE("canbe_unique: ownership", "[canbe_unique]") {
  Counted::alive = 0;

  SECTION("borrowed") {
    Counted obj(1);
    {
      cu_t ptr(obj);
      CHECK(ptr.get() == &obj);
      CHECK(ptr->value == 1);
      CHECK_FALSE(ptr.is_owned());
      CHECK(ptr.take_ownership() == nullptr);
      CHECK(ptr.get() == &obj);
    }
    CHECK(Counted::alive == 1);
  }

  SECTION("const borrowed") {
    const Counted obj(1);
    const cu_t ptr(obj);
    CHECK(ptr.get() == &obj);
    CHECK((*ptr).value == 1);
    CHECK_FALSE(ptr.is_owned());
  }

  SECTION("owned") {
    {
      cu_t ptr(std::make_unique<Counted>(1));
      CHECK(ptr.is_owned());
      CHECK(Counted::alive == 1);
    }
    CHECK(Counted::alive == 0);
  }

  SECTION("take_ownership") {
    cu_t ptr(std::make_unique<Counted>(1));
    std::unique_ptr<Counted> owned = ptr.take_ownership();
    REQUIRE(owned != nullptr);
    CHECK(owned->value == 1);
    CHECK(ptr == nullptr);
    CHECK_FALSE(ptr.is_owned());
    CHECK(ptr.take_ownership() == nullptr);
    CHECK(Counted::alive == 1);
  }

  SECTION("reset") {
    Counted obj(1);
    cu_t borrowed(obj);
    borrowed = nullptr;
    CHECK(borrowed == nullptr);
    CHECK(Counted::alive == 1);

    cu_t owned(std::make_unique<Counted>(2));
    owned.reset();
    CHECK(owned == nullptr);
    CHECK_FALSE(owned.is_owned());
    CHECK(owned.take_ownership() == nullptr);
    CHECK(Counted::alive == 1);
  }

  SECTION("reset clears the pointer before the deletion") {
    canbe_unique<Node> ptr(std::make_unique<Node>());
    ptr->holder = &ptr;
    Node::observed = ptr.get();
    ptr.reset();
    CHECK(Node::observed == nullptr);
  }

  SECTION("comparisons") {
    Counted obj(1);
    cu_t ptr(obj);
    const cu_t empty;
    CHECK(ptr != nullptr);
    CHECK(nullptr != ptr);
    CHECK_FALSE(ptr == nullptr);
    CHECK(empty == nullptr);
    CHECK(nullptr == empty);
    CHECK_FALSE(empty != nullptr);
    CHECK(static_cast<bool>(ptr));
    CHECK_FALSE(empty);
  }

  CHECK(Counted::alive == 0);
}

TEST_CASE("canbe_unique: move", "[canbe_unique]") {
  // NOLINTBEGIN(bugprone-use-after-move)
  Counted::alive = 0;
  Counted borrowed_a(1);
  Counted borrowed_b(2);

  SECTION("construction") {
    cu_t owned(std::make_unique<Counted>(3));
    cu_t moved(std::move(owned));
    CHECK(owned == nullptr);
    CHECK(owned.take_ownership() == nullptr);
    CHECK(moved.is_owned());
    CHECK(moved->value == 3);

    cu_t borrowed(borrowed_a);
    cu_t moved_borrowed(std::move(borrowed));
    CHECK(borrowed == nullptr);
    CHECK(moved_borrowed.get() == &borrowed_a);
    CHECK(moved_borrowed.take_ownership() == nullptr);
  }

  SECTION("owned <- owned") {
    cu_t dst(std::make_unique<Counted>(3));
    cu_t src(std::make_unique<Counted>(4));
    dst = std::move(src);
    CHECK(Counted::alive == 3);
    CHECK(src == nullptr);
    CHECK(dst->value == 4);
  }

  SECTION("owned <- borrowed") {
    {
      cu_t dst(std::make_unique<Counted>(3));
      cu_t src(borrowed_a);
      dst = std::move(src);
      CHECK(Counted::alive == 2);
      CHECK(dst.get() == &borrowed_a);
      CHECK(dst.take_ownership() == nullptr);
      CHECK(src == nullptr);
    }
    CHECK(borrowed_a.value == 1);
  }

  SECTION("borrowed <- owned") {
    {
      cu_t dst(borrowed_a);
      cu_t src(std::make_unique<Counted>(3));
      dst = std::move(src);
      CHECK(dst.is_owned());
      CHECK(dst->value == 3);
      CHECK(src == nullptr);
    }
    CHECK(Counted::alive == 2);
    CHECK(borrowed_a.value == 1);
  }

  SECTION("borrowed <- borrowed") {
    cu_t dst(borrowed_a);
    cu_t src(borrowed_b);
    dst = std::move(src);
    CHECK(dst.get() == &borrowed_b);
    CHECK(src == nullptr);
  }

  SECTION("self") {
    cu_t ptr(std::make_unique<Counted>(3));
    cu_t& alias = ptr;
    ptr = std::move(alias);
    REQUIRE(ptr != nullptr);
    CHECK(ptr->value == 3);
    CHECK(Counted::alive == 3);
  }

  SECTION("from an object owned by the target") {
    {
      canbe_unique<List> head(std::make_unique<List>(1));
      head->next = std::make_unique<List>(2);
      head = std::move(head->next);
      REQUIRE(head != nullptr);
      CHECK(head->value == 2);
      CHECK(head->next == nullptr);
      CHECK(Counted::alive == 3);
    }
    CHECK(Counted::alive == 2);
  }

  CHECK(Counted::alive == 2);
  // NOLINTEND(bugprone-use-after-move)
}
