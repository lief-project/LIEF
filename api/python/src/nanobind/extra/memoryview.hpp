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
};

NAMESPACE_END(NB_NAMESPACE)

#endif
