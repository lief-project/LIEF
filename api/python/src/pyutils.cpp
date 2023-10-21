#include "pyutils.hpp"

namespace LIEF::py {
result<std::string> path_to_str(nb::object pathlike) {
  PyObject* buf = PyOS_FSPath(pathlike.ptr());
  if (!buf) {
    PyErr_Clear();
    return make_error_code(lief_errors::conversion_error);
  }

  PyObject* native = nullptr;
  std::string path_str;
  if (PyUnicode_FSConverter(buf, &native) != 0) {
    if (char* c_str = PyBytes_AsString(native)) {
      path_str = c_str;
    }
  }
  Py_XDECREF(native);
  Py_DECREF(buf);
  if (PyErr_Occurred()) {
    PyErr_Clear();
    return make_error_code(lief_errors::conversion_error);
  }
  return path_str;
}
}
