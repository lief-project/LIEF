#ifndef PY_LIEF_MEMORY_VIEW_H
#define PY_LIEF_MEMORY_VIEW_H

#include <nanobind/nanobind.h>

NAMESPACE_BEGIN(NB_NAMESPACE)

/* The current version of nanobind does not memoryview helper compared to
 * pybind11. So here is a minimal API needed by LIEF
 *
 * Tracked by the discussion: https://github.com/wjakob/nanobind/discussions/233
 */
class memoryview : public object {
  using ssize_t = Py_ssize_t;
public:
    NB_OBJECT(memoryview, object, "memoryview", PyMemoryView_Check)

    memoryview(const object &o)
        : object(check_(o) ? o.inc_ref().ptr() :
                             PyMemoryView_FromObject(o.ptr()), detail::steal_t{}) {
        if (!m_ptr)
            detail::raise_python_error();
    }

    memoryview(object &&o)
        : object(check_(o) ? o.release().ptr() :
                             PyMemoryView_FromObject(o.ptr()), detail::steal_t{}) {

        if (!m_ptr)
            detail::raise_python_error();
    }

    static memoryview from_memory(void *mem, ssize_t size, bool readonly = false) {
        PyObject *ptr = PyMemoryView_FromMemory(
            reinterpret_cast<char *>(mem), size, (readonly) ? PyBUF_READ : PyBUF_WRITE);
        if (!ptr) {
          detail::fail("Could not allocate memoryview object!");
        }
        return memoryview(object(ptr, detail::steal_t{}));
    }

    static memoryview from_memory(const void *mem, ssize_t size) {
        return memoryview::from_memory(const_cast<void *>(mem), size, true);
    }

    const uint8_t* data() const {
#if defined(Py_LIMITED_API)
        Py_buffer view;
        if (PyObject_GetBuffer(ptr(), &view, PyBUF_SIMPLE) != 0) {
            detail::raise_python_error();
        }

        auto* buf_ptr = static_cast<const uint8_t*>(view.buf);

        PyBuffer_Release(&view);
        return buf_ptr;
#else
        return (const uint8_t*)PyMemoryView_GET_BUFFER(this->ptr())->buf;
#endif
    }

    size_t size() const {
#if defined(Py_LIMITED_API)
        Py_buffer view;
        if (PyObject_GetBuffer(ptr(), &view, PyBUF_SIMPLE) != 0) {
            detail::raise_python_error();
        }

        size_t len = static_cast<size_t>(view.len);

        PyBuffer_Release(&view);
        return len;
#else
        return PyMemoryView_GET_BUFFER(ptr())->len;
#endif
    }
};

NAMESPACE_END(NB_NAMESPACE)

#endif
