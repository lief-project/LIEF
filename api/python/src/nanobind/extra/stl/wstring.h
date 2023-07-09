#pragma once

#include <nanobind/nanobind.h>
#include <string>

NAMESPACE_BEGIN(NB_NAMESPACE)
NAMESPACE_BEGIN(detail)

template <> struct type_caster<std::wstring> {
    NB_TYPE_CASTER(std::wstring, const_name("str"));

    bool from_python(handle src, uint8_t, cleanup_list *) noexcept {
        Py_ssize_t size;
        const wchar_t *str = PyUnicode_AsWideCharString(src.ptr(), &size);
        if (str == nullptr) {
            PyErr_Clear();
            return false;
        }
        value = std::wstring(str, (size_t) size);
        return true;
    }

    static handle from_cpp(const std::wstring &value, rv_policy,
                           cleanup_list *) noexcept {
        return PyUnicode_FromWideChar(value.c_str(), value.size());
    }
};

NAMESPACE_END(detail)
NAMESPACE_END(NB_NAMESPACE)
