#include <Python.h>

PyMODINIT_FUNC
PyInit__decoding(void)
{
    PyObject *tmp;
    if (!(tmp = PyImport_ImportModule("29859a9e7da9d19bb98c__mypyc"))) return NULL;
    PyObject *capsule = PyObject_GetAttrString(tmp, "init_faster_eth_abi____decoding");
    Py_DECREF(tmp);
    if (capsule == NULL) return NULL;
    void *init_func = PyCapsule_GetPointer(capsule, "29859a9e7da9d19bb98c__mypyc.init_faster_eth_abi____decoding");
    Py_DECREF(capsule);
    if (!init_func) {
        return NULL;
    }
    return ((PyObject *(*)(void))init_func)();
}

// distutils sometimes spuriously tells cl to export CPyInit___init__,
// so provide that so it chills out
PyMODINIT_FUNC PyInit___init__(void) { return PyInit__decoding(); }
