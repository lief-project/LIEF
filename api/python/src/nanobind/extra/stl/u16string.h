#pragma once

#include <nanobind/nanobind.h>
#include <string>

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)

template <> struct type_caster<std::u16string> {
    using ssize_t = Py_ssize_t;
    using CharT = typename std::u16string::value_type;
    NB_TYPE_CASTER(std::u16string, const_name("str"));

    bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
        Py_ssize_t size;
        const object Nbytes = steal(PyUnicode_AsUTF16String(src.ptr()));
        if (!Nbytes) {
          PyErr_Clear();
          return false;
        }
        const auto *buffer
            = reinterpret_cast<const CharT *>(PyBytes_AsString(Nbytes.ptr()));

        size_t length = (size_t) PyBytes_Size(Nbytes.ptr()) / sizeof(CharT);

        // Skip BOM
        buffer++;
        length--;
        value = std::u16string(buffer, length);
        return true;
    }

    static handle from_cpp(const std::u16string &value, rv_policy,
                           cleanup_list *) noexcept {
        const auto *buffer = reinterpret_cast<const char *>(value.data());
        auto nbytes = ssize_t(value.size() * sizeof(CharT));
        return PyUnicode_DecodeUTF16(buffer, nbytes, nullptr, nullptr);
    }
};

NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)
