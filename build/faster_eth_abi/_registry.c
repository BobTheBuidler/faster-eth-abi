#include <Python.h>

PyMODINIT_FUNC
PyInit__registry(void)
{
    PyObject *tmp;
    if (!(tmp = PyImport_ImportModule("fbb93ef20beda8d9a0f4__mypyc"))) return NULL;
    PyObject *capsule = PyObject_GetAttrString(tmp, "init_faster_eth_abi____registry");
    Py_DECREF(tmp);
    if (capsule == NULL) return NULL;
    void *init_func = PyCapsule_GetPointer(capsule, "fbb93ef20beda8d9a0f4__mypyc.init_faster_eth_abi____registry");
    Py_DECREF(capsule);
    if (!init_func) {
        return NULL;
    }
    return ((PyObject *(*)(void))init_func)();
}

// distutils sometimes spuriously tells cl to export CPyInit___init__,
// so provide that so it chills out
PyMODINIT_FUNC PyInit___init__(void) { return PyInit__registry(); }
