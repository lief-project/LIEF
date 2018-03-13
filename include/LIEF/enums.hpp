#ifndef LIEF_ENUMS_H_
#define LIEF_ENUMS_H_
#include <type_traits>

#define _LIEF_EN(N) class N : size_t
#define _LIEF_EN_2(N, TYPE) class N : TYPE
#define _LIEF_EI(X) X

#define ENABLE_BITMASK_OPERATORS(X)  \
template<>                           \
struct EnableBitMaskOperators<X>     \
{                                    \
  static const bool bit_mask_enabled = true;   \
};

template<typename Enum>
struct EnableBitMaskOperators
{
  static const bool bit_mask_enabled = false;
};

template<typename Enum>
typename std::enable_if<EnableBitMaskOperators<Enum>::bit_mask_enabled, Enum>::type
operator |(Enum lhs, Enum rhs)
{
    using underlying = typename std::underlying_type<Enum>::type;
    return static_cast<Enum> (
        static_cast<underlying>(lhs) |
        static_cast<underlying>(rhs)
    );
}

template<typename Enum>
typename std::enable_if<EnableBitMaskOperators<Enum>::bit_mask_enabled, Enum>::type
operator &(Enum lhs, Enum rhs)
{
    using underlying = typename std::underlying_type<Enum>::type;
    return static_cast<Enum> (
        static_cast<underlying>(lhs) &
        static_cast<underlying>(rhs)
    );
}

template<typename Enum>
typename std::enable_if<EnableBitMaskOperators<Enum>::bit_mask_enabled, Enum>::type
operator ~(Enum e)
{
    using underlying = typename std::underlying_type<Enum>::type;
    return static_cast<Enum>(~static_cast<underlying>(e));
}

template<typename Enum>
typename std::enable_if<EnableBitMaskOperators<Enum>::bit_mask_enabled, typename std::add_lvalue_reference<Enum>::type>::type
operator |=(Enum& lhs, Enum rhs)
{
    using underlying = typename std::underlying_type<Enum>::type;
    lhs = static_cast<Enum>(static_cast<underlying>(lhs) | static_cast<underlying>(rhs));
    return lhs;
}

template<typename Enum>
typename std::enable_if<EnableBitMaskOperators<Enum>::bit_mask_enabled, typename std::add_lvalue_reference<Enum>::type>::type
operator &=(Enum& lhs, Enum rhs)
{
    using underlying = typename std::underlying_type<Enum>::type;
    lhs = static_cast<Enum>(static_cast<underlying>(lhs) & static_cast<underlying>(rhs));
    return lhs;
}

#endif
