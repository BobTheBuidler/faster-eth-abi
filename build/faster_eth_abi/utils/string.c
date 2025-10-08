#include <Python.h>

PyMODINIT_FUNC
PyInit_string(void)
{
    PyObject *tmp;
    if (!(tmp = PyImport_ImportModule("e51aa50b7437b847861f__mypyc"))) return NULL;
    PyObject *capsule = PyObject_GetAttrString(tmp, "init_faster_eth_abi___utils___string");
    Py_DECREF(tmp);
    if (capsule == NULL) return NULL;
    void *init_func = PyCapsule_GetPointer(capsule, "e51aa50b7437b847861f__mypyc.init_faster_eth_abi___utils___string");
    Py_DECREF(capsule);
    if (!init_func) {
        return NULL;
    }
    return ((PyObject *(*)(void))init_func)();
}

// distutils sometimes spuriously tells cl to export CPyInit___init__,
// so provide that so it chills out
PyMODINIT_FUNC PyInit___init__(void) { return PyInit_string(); }
