#ifndef PY_LIEF_RANDOM_ACCESS_IT_H
#define PY_LIEF_RANDOM_ACCESS_IT_H

#include <nanobind/nanobind.h>
#include <nanobind/make_iterator.h>

NAMESPACE_BEGIN(NB_NAMESPACE)
namespace detail {
template<class Element>
class TypedRandomIterator : public nanobind::iterator {
  public:
  static constexpr auto Name = const_name("collections.abc.Sequence[") + make_caster<Element>::Name + const_name("]");
  TypedRandomIterator(nanobind::iterator&& it) :
    nanobind::iterator::iterator(std::move(it))
  {}
};

template <typename Access, rv_policy Policy, typename Iterator,
          typename Sentinel, typename ValueType, typename... Extra>
struct random_iterator_state {
    Iterator it;
    Iterator begin;
    Sentinel end;
    bool first_or_done;
};

template <typename Access, rv_policy Policy, typename Iterator,
          typename Sentinel, typename ValueType, typename... Extra>
iterator make_rnd_iterator_impl(handle scope, const char *name,
                            Iterator &&first, Sentinel &&last,
                            Extra &&...extra) {
    using State = random_iterator_state<Access, Policy, Iterator, Sentinel, ValueType, Extra...>;

    if (!type<State>().is_valid()) {
        class_<State>(scope, name)
            .def("__iter__", [](handle h) { return h; })
            .def("__len__", [](State &s) { return std::distance(s.begin, s.end); })
            .def("__getitem__",
                [] (State& s, Py_ssize_t i) -> ValueType {
                  const size_t size = std::distance(s.begin, s.end);
                  if (i < 0) {
                    i += static_cast<Py_ssize_t>(size);
                  }
                  if (i < 0 || static_cast<size_t>(i) >= size) {
                    throw nanobind::index_error();
                  }
                  Iterator it = s.begin + i;
                  return Access()(it);
                }, std::forward<Extra>(extra)..., Policy)

            .def("__next__",
                 [](State &s) -> ValueType {
                     if (!s.first_or_done)
                         ++s.it;
                     else
                         s.first_or_done = false;

                     if (s.it == s.end) {
                         s.first_or_done = true;
                         throw stop_iteration();
                     }

                     return Access()(s.it);
                 },
                 std::forward<Extra>(extra)...,
                 Policy);
    }
    auto begin = first;
    return borrow<iterator>(cast(State{ std::forward<Iterator>(first),
                                        std::move(begin),
                                        std::forward<Sentinel>(last), true }));
}
}


template <rv_policy Policy = rv_policy::reference_internal,
          typename Iterator,
          typename Sentinel,
          typename ValueType = typename detail::iterator_access<Iterator>::result_type,
          typename... Extra>
detail::TypedRandomIterator<ValueType> make_random_access_iterator(handle scope, const char *name, Iterator &&first, Sentinel &&last, Extra &&...extra) {
    return detail::make_rnd_iterator_impl<detail::iterator_access<Iterator>, Policy,
                                      Iterator, Sentinel, ValueType, Extra...>(
        scope, name, std::forward<Iterator>(first),
        std::forward<Sentinel>(last), std::forward<Extra>(extra)...);
}

template <rv_policy Policy = rv_policy::reference_internal,
          typename Type,
          typename ValueType = typename detail::iterator_access<typename Type::IteratorTy>::result_type,
          typename... Extra>
detail::TypedRandomIterator<ValueType> make_random_access_iterator(
    handle scope, const char *name, Type &value, Extra &&...extra)
{
    return make_random_access_iterator<Policy>(
      scope, name, std::begin(value), std::end(value),
      std::forward<Extra>(extra)...
    );
}

NAMESPACE_END(NB_NAMESPACE)

#endif
