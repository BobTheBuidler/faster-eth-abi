#ifndef DIFFCHECK_PLACEHOLDER
#define DIFFCHECK_PLACEHOLDER 0
#endif
#include "init.c"
#include "getargs.c"
#include "getargsfast.c"
#include "int_ops.c"
#include "float_ops.c"
#include "str_ops.c"
#include "bytes_ops.c"
#include "list_ops.c"
#include "dict_ops.c"
#include "set_ops.c"
#include "tuple_ops.c"
#include "exc_ops.c"
#include "misc_ops.c"
#include "generic_ops.c"
#include "pythonsupport.c"
#include "__native_faster_eth_abi.h"
#include "__native_internal_faster_eth_abi.h"
static PyMethodDef _codecmodule_methods[] = {
    {"encode_c", (PyCFunction)CPyPy__codec___encode_c, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_c(self, types, args)\n--\n\n") /* docstring */},
    {"decode_c", (PyCFunction)CPyPy__codec___decode_c, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decode_c(self, types, data, strict=True)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi____codec(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi____codec__internal, "__name__");
    CPyStatic__codec___globals = PyModule_GetDict(CPyModule_faster_eth_abi____codec__internal);
    if (unlikely(CPyStatic__codec___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef__codec_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi____codec__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef _codecmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi._codec",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    _codecmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi____codec(void)
{
    if (CPyModule_faster_eth_abi____codec__internal) {
        Py_INCREF(CPyModule_faster_eth_abi____codec__internal);
        return CPyModule_faster_eth_abi____codec__internal;
    }
    CPyModule_faster_eth_abi____codec__internal = PyModule_Create(&_codecmodule);
    if (unlikely(CPyModule_faster_eth_abi____codec__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi____codec(CPyModule_faster_eth_abi____codec__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi____codec__internal;
    fail:
    return NULL;
}

PyObject *CPyDef__codec___encode_c(PyObject *cpy_r_self, PyObject *cpy_r_types, PyObject *cpy_r_args) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject **cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'args' */
    cpy_r_r1 = CPyDef_validation___validate_list_like_param(cpy_r_args, cpy_r_r0);
    if (unlikely(cpy_r_r1 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_registry' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_self, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_tuple_encoder' */
    cpy_r_r5 = CPyObject_GetAttr(cpy_r_r3, cpy_r_r4);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    cpy_r_r6 = PySequence_Tuple(cpy_r_types);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL9;
    }
    cpy_r_r7 = PyObject_CallObject(cpy_r_r5, cpy_r_r6);
    CPy_DECREF(cpy_r_r5);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    PyObject *cpy_r_r8[1] = {cpy_r_args};
    cpy_r_r9 = (PyObject **)&cpy_r_r8;
    cpy_r_r10 = PyObject_Vectorcall(cpy_r_r7, cpy_r_r9, 1, 0);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    if (likely(PyBytes_Check(cpy_r_r10) || PyByteArray_Check(cpy_r_r10)))
        cpy_r_r11 = cpy_r_r10;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_codec.py", "encode_c", 46, CPyStatic__codec___globals, "bytes", cpy_r_r10);
        goto CPyL8;
    }
    return cpy_r_r11;
CPyL8: ;
    cpy_r_r12 = NULL;
    return cpy_r_r12;
CPyL9: ;
    CPy_DecRef(cpy_r_r5);
    goto CPyL8;
}

PyObject *CPyPy__codec___encode_c(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "types", "args", 0};
    static CPyArg_Parser parser = {"OOO:encode_c", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_types;
    PyObject *obj_args;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_types, &obj_args)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_types = obj_types;
    PyObject *arg_args = obj_args;
    PyObject *retval = CPyDef__codec___encode_c(arg_self, arg_types, arg_args);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_codec.py", "encode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
    return NULL;
}

PyObject *CPyDef__codec___decode_c(PyObject *cpy_r_self, PyObject *cpy_r_types, PyObject *cpy_r_data, char cpy_r_strict) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject **cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    if (cpy_r_strict != 2) goto CPyL2;
    cpy_r_strict = 1;
CPyL2: ;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'data' */
    cpy_r_r1 = CPyDef_validation___validate_bytes_param(cpy_r_data, cpy_r_r0);
    if (unlikely(cpy_r_r1 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL14;
    }
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_registry' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_self, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL14;
    }
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_tuple_decoder' */
    cpy_r_r5 = CPyObject_GetAttr(cpy_r_r3, cpy_r_r4);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL14;
    }
    cpy_r_r6 = PyList_New(0);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL15;
    }
    cpy_r_r7 = CPyList_Extend(cpy_r_r6, cpy_r_types);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL16;
    } else
        goto CPyL17;
CPyL7: ;
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'strict' */
    cpy_r_r9 = PyList_AsTuple(cpy_r_r6);
    CPy_DECREF_NO_IMM(cpy_r_r6);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL15;
    }
    cpy_r_r10 = cpy_r_strict ? Py_True : Py_False;
    cpy_r_r11 = CPyDict_Build(1, cpy_r_r8, cpy_r_r10);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL18;
    }
    cpy_r_r12 = PyObject_Call(cpy_r_r5, cpy_r_r9, cpy_r_r11);
    CPy_DECREF(cpy_r_r5);
    CPy_DECREF(cpy_r_r9);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL14;
    }
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'stream_class' */
    PyObject *cpy_r_r14[2] = {cpy_r_self, cpy_r_data};
    cpy_r_r15 = (PyObject **)&cpy_r_r14;
    cpy_r_r16 = PyObject_VectorcallMethod(cpy_r_r13, cpy_r_r15, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL19;
    }
    PyObject *cpy_r_r17[1] = {cpy_r_r16};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_Vectorcall(cpy_r_r12, cpy_r_r18, 1, 0);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL20;
    }
    CPy_DECREF(cpy_r_r16);
    if (likely(PyTuple_Check(cpy_r_r19)))
        cpy_r_r20 = cpy_r_r19;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_codec.py", "decode_c", 77, CPyStatic__codec___globals, "tuple", cpy_r_r19);
        goto CPyL14;
    }
    return cpy_r_r20;
CPyL14: ;
    cpy_r_r21 = NULL;
    return cpy_r_r21;
CPyL15: ;
    CPy_DecRef(cpy_r_r5);
    goto CPyL14;
CPyL16: ;
    CPy_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r6);
    goto CPyL14;
CPyL17: ;
    CPy_DECREF(cpy_r_r7);
    goto CPyL7;
CPyL18: ;
    CPy_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r9);
    goto CPyL14;
CPyL19: ;
    CPy_DecRef(cpy_r_r12);
    goto CPyL14;
CPyL20: ;
    CPy_DecRef(cpy_r_r16);
    goto CPyL14;
}

PyObject *CPyPy__codec___decode_c(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "types", "data", "strict", 0};
    static CPyArg_Parser parser = {"OOO|O:decode_c", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_types;
    PyObject *obj_data;
    PyObject *obj_strict = NULL;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_types, &obj_data, &obj_strict)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_types = obj_types;
    PyObject *arg_data;
    if (PyBytes_Check(obj_data) || PyByteArray_Check(obj_data))
        arg_data = obj_data;
    else {
        arg_data = NULL;
    }
    if (arg_data != NULL) goto __LL1;
    arg_data = obj_data;
    if (arg_data != NULL) goto __LL1;
    CPy_TypeError("union[bytes, object]", obj_data); 
    goto fail;
__LL1: ;
    char arg_strict;
    if (obj_strict == NULL) {
        arg_strict = 2;
    } else if (unlikely(!PyBool_Check(obj_strict))) {
        CPy_TypeError("bool", obj_strict); goto fail;
    } else
        arg_strict = obj_strict == Py_True;
    PyObject *retval = CPyDef__codec___decode_c(arg_self, arg_types, arg_data, arg_strict);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_codec.py", "decode_c", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
    return NULL;
}

char CPyDef__codec_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    char cpy_r_r17;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "<module>", -1, CPyStatic__codec___globals);
        goto CPyL8;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TYPE_CHECKING', 'Any', 'Iterable', 'Tuple') */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic__codec___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Decodable', 'TypeStr') */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'eth_typing' */
    cpy_r_r11 = CPyStatic__codec___globals;
    cpy_r_r12 = CPyImport_ImportFromMany(cpy_r_r10, cpy_r_r9, cpy_r_r9, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    CPyModule_eth_typing = cpy_r_r12;
    CPy_INCREF(CPyModule_eth_typing);
    CPy_DECREF(cpy_r_r12);
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('validate_bytes_param', 'validate_list_like_param') */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.utils.validation' */
    cpy_r_r15 = CPyStatic__codec___globals;
    cpy_r_r16 = CPyImport_ImportFromMany(cpy_r_r14, cpy_r_r13, cpy_r_r13, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_codec.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__codec___globals);
        goto CPyL8;
    }
    CPyModule_faster_eth_abi___utils___validation = cpy_r_r16;
    CPy_INCREF(CPyModule_faster_eth_abi___utils___validation);
    CPy_DECREF(cpy_r_r16);
    return 1;
CPyL8: ;
    cpy_r_r17 = 2;
    return cpy_r_r17;
}
static PyMethodDef _decodingmodule_methods[] = {
    {"decode_uint_256", (PyCFunction)CPyPy__decoding___decode_uint_256, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decode_uint_256(stream)\n--\n\n") /* docstring */},
    {"get_value_byte_size", (PyCFunction)CPyPy__decoding___get_value_byte_size, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_value_byte_size(decoder)\n--\n\n") /* docstring */},
    {"decode_head_tail", (PyCFunction)CPyPy__decoding___decode_head_tail, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decode_head_tail(self, stream)\n--\n\n") /* docstring */},
    {"decode_tuple", (PyCFunction)CPyPy__decoding___decode_tuple, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decode_tuple(self, stream)\n--\n\n") /* docstring */},
    {"validate_pointers_tuple", (PyCFunction)CPyPy__decoding___validate_pointers_tuple, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate_pointers_tuple(self, stream)\n--\n\n") /* docstring */},
    {"validate_pointers_array", (PyCFunction)CPyPy__decoding___validate_pointers_array, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate_pointers_array(self, stream, array_size)\n--\n\n") /* docstring */},
    {"decode_sized_array", (PyCFunction)CPyPy__decoding___decode_sized_array, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decode_sized_array(self, stream)\n--\n\n") /* docstring */},
    {"decode_dynamic_array", (PyCFunction)CPyPy__decoding___decode_dynamic_array, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decode_dynamic_array(self, stream)\n--\n\n") /* docstring */},
    {"read_fixed_byte_size_data_from_stream", (PyCFunction)CPyPy__decoding___read_fixed_byte_size_data_from_stream, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("read_fixed_byte_size_data_from_stream(self, stream)\n--\n\n") /* docstring */},
    {"split_data_and_padding_fixed_byte_size", (PyCFunction)CPyPy__decoding___split_data_and_padding_fixed_byte_size, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("split_data_and_padding_fixed_byte_size(self, raw_data)\n--\n\n") /* docstring */},
    {"validate_padding_bytes_fixed_byte_size", (PyCFunction)CPyPy__decoding___validate_padding_bytes_fixed_byte_size, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate_padding_bytes_fixed_byte_size(self, value, padding_bytes)\n--\n\n") /* docstring */},
    {"decoder_fn_boolean", (PyCFunction)CPyPy__decoding___decoder_fn_boolean, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("decoder_fn_boolean(data)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi____decoding(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi____decoding__internal, "__name__");
    CPyStatic__decoding___globals = PyModule_GetDict(CPyModule_faster_eth_abi____decoding__internal);
    if (unlikely(CPyStatic__decoding___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef__decoding_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi____decoding__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef _decodingmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi._decoding",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    _decodingmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi____decoding(void)
{
    if (CPyModule_faster_eth_abi____decoding__internal) {
        Py_INCREF(CPyModule_faster_eth_abi____decoding__internal);
        return CPyModule_faster_eth_abi____decoding__internal;
    }
    CPyModule_faster_eth_abi____decoding__internal = PyModule_Create(&_decodingmodule);
    if (unlikely(CPyModule_faster_eth_abi____decoding__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi____decoding(CPyModule_faster_eth_abi____decoding__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi____decoding__internal;
    fail:
    return NULL;
}

CPyTagged CPyDef__decoding___decode_uint_256(PyObject *cpy_r_stream) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject **cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    CPyPtr cpy_r_r6;
    int64_t cpy_r_r7;
    CPyTagged cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject **cpy_r_r14;
    PyObject *cpy_r_r15;
    CPyTagged cpy_r_r16;
    PyObject *cpy_r_r17;
    CPyPtr cpy_r_r18;
    int64_t cpy_r_r19;
    CPyTagged cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject **cpy_r_r28;
    PyObject *cpy_r_r29;
    CPyTagged cpy_r_r30;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'read' */
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 32 */
    PyObject *cpy_r_r2[2] = {cpy_r_stream, cpy_r_r1};
    cpy_r_r3 = (PyObject **)&cpy_r_r2;
    cpy_r_r4 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r3, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    if (likely(PyBytes_Check(cpy_r_r4) || PyByteArray_Check(cpy_r_r4)))
        cpy_r_r5 = cpy_r_r4;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", 41, CPyStatic__decoding___globals, "bytes", cpy_r_r4);
        goto CPyL13;
    }
    CPy_INCREF(cpy_r_r5);
    cpy_r_r6 = (CPyPtr)&((PyVarObject *)cpy_r_r5)->ob_size;
    cpy_r_r7 = *(int64_t *)cpy_r_r6;
    CPy_DECREF(cpy_r_r5);
    cpy_r_r8 = cpy_r_r7 << 1;
    cpy_r_r9 = cpy_r_r8 == 64;
    if (!cpy_r_r9) goto CPyL7;
    cpy_r_r10 = CPyStatic__decoding___globals;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'big_endian_to_int' */
    cpy_r_r12 = CPyDict_GetItem(cpy_r_r10, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    PyObject *cpy_r_r13[1] = {cpy_r_r5};
    cpy_r_r14 = (PyObject **)&cpy_r_r13;
    cpy_r_r15 = PyObject_Vectorcall(cpy_r_r12, cpy_r_r14, 1, 0);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    CPy_DECREF(cpy_r_r5);
    if (likely(PyLong_Check(cpy_r_r15)))
        cpy_r_r16 = CPyTagged_FromObject(cpy_r_r15);
    else {
        CPy_TypeError("int", cpy_r_r15); cpy_r_r16 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r15);
    if (unlikely(cpy_r_r16 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    return cpy_r_r16;
CPyL7: ;
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Tried to read 32 bytes, only got ' */
    cpy_r_r18 = (CPyPtr)&((PyVarObject *)cpy_r_r5)->ob_size;
    cpy_r_r19 = *(int64_t *)cpy_r_r18;
    CPy_DECREF(cpy_r_r5);
    cpy_r_r20 = cpy_r_r19 << 1;
    cpy_r_r21 = CPyTagged_Str(cpy_r_r20);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' bytes.' */
    cpy_r_r23 = CPyStr_Build(3, cpy_r_r17, cpy_r_r21, cpy_r_r22);
    CPy_DECREF(cpy_r_r21);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    cpy_r_r24 = CPyStatic__decoding___globals;
    cpy_r_r25 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'InsufficientDataBytes' */
    cpy_r_r26 = CPyDict_GetItem(cpy_r_r24, cpy_r_r25);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL15;
    }
    PyObject *cpy_r_r27[1] = {cpy_r_r23};
    cpy_r_r28 = (PyObject **)&cpy_r_r27;
    cpy_r_r29 = PyObject_Vectorcall(cpy_r_r26, cpy_r_r28, 1, 0);
    CPy_DECREF(cpy_r_r26);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL15;
    }
    CPy_DECREF(cpy_r_r23);
    CPy_Raise(cpy_r_r29);
    CPy_DECREF(cpy_r_r29);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    CPy_Unreachable();
CPyL13: ;
    cpy_r_r30 = CPY_INT_TAG;
    return cpy_r_r30;
CPyL14: ;
    CPy_DecRef(cpy_r_r5);
    goto CPyL13;
CPyL15: ;
    CPy_DecRef(cpy_r_r23);
    goto CPyL13;
}

PyObject *CPyPy__decoding___decode_uint_256(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"stream", 0};
    static CPyArg_Parser parser = {"O:decode_uint_256", kwlist, 0};
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_stream = obj_stream;
    CPyTagged retval = CPyDef__decoding___decode_uint_256(arg_stream);
    if (retval == CPY_INT_TAG) {
        return NULL;
    }
    PyObject *retbox = CPyTagged_StealAsObject(retval);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

CPyTagged CPyDef__decoding___get_value_byte_size(PyObject *cpy_r_decoder) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    CPyTagged cpy_r_r2;
    CPyTagged cpy_r_r3;
    CPyTagged cpy_r_r4;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'value_bit_size' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r_decoder, cpy_r_r0);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "get_value_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL4;
    }
    if (likely(PyLong_Check(cpy_r_r1)))
        cpy_r_r2 = CPyTagged_FromObject(cpy_r_r1);
    else {
        CPy_TypeError("int", cpy_r_r1); cpy_r_r2 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r1);
    if (unlikely(cpy_r_r2 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "get_value_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL4;
    }
    cpy_r_r3 = CPyTagged_Rshift(cpy_r_r2, 6);
    CPyTagged_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r3 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "get_value_byte_size", -1, CPyStatic__decoding___globals);
        goto CPyL4;
    }
    return cpy_r_r3;
CPyL4: ;
    cpy_r_r4 = CPY_INT_TAG;
    return cpy_r_r4;
}

PyObject *CPyPy__decoding___get_value_byte_size(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"decoder", 0};
    static CPyArg_Parser parser = {"O:get_value_byte_size", kwlist, 0};
    PyObject *obj_decoder;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_decoder)) {
        return NULL;
    }
    PyObject *arg_decoder = obj_decoder;
    CPyTagged retval = CPyDef__decoding___get_value_byte_size(arg_decoder);
    if (retval == CPY_INT_TAG) {
        return NULL;
    }
    PyObject *retbox = CPyTagged_StealAsObject(retval);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "get_value_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

PyObject *CPyDef__decoding___decode_head_tail(PyObject *cpy_r_self, PyObject *cpy_r_stream) {
    CPyTagged cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_tail_decoder;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject **cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_value;
    PyObject *cpy_r_r20;
    PyObject **cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    cpy_r_r0 = CPyDef__decoding___decode_uint_256(cpy_r_stream);
    if (unlikely(cpy_r_r0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'push_frame' */
    cpy_r_r2 = CPyTagged_StealAsObject(cpy_r_r0);
    PyObject *cpy_r_r3[2] = {cpy_r_stream, cpy_r_r2};
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r4, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL12;
    } else
        goto CPyL13;
CPyL2: ;
    CPy_DECREF(cpy_r_r2);
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'tail_decoder' */
    cpy_r_r7 = CPyObject_GetAttr(cpy_r_self, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    cpy_r_tail_decoder = cpy_r_r7;
    cpy_r_r8 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r9 = cpy_r_tail_decoder == cpy_r_r8;
    if (cpy_r_r9) {
        goto CPyL14;
    } else
        goto CPyL8;
CPyL4: ;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '`tail_decoder` is None' */
    cpy_r_r11 = CPyModule_builtins;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'AssertionError' */
    cpy_r_r13 = CPyObject_GetAttr(cpy_r_r11, cpy_r_r12);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    PyObject *cpy_r_r14[1] = {cpy_r_r10};
    cpy_r_r15 = (PyObject **)&cpy_r_r14;
    cpy_r_r16 = PyObject_Vectorcall(cpy_r_r13, cpy_r_r15, 1, 0);
    CPy_DECREF(cpy_r_r13);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    CPy_Raise(cpy_r_r16);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    CPy_Unreachable();
CPyL8: ;
    PyObject *cpy_r_r17[1] = {cpy_r_stream};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_Vectorcall(cpy_r_tail_decoder, cpy_r_r18, 1, 0);
    CPy_DECREF(cpy_r_tail_decoder);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    cpy_r_value = cpy_r_r19;
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'pop_frame' */
    PyObject *cpy_r_r21[1] = {cpy_r_stream};
    cpy_r_r22 = (PyObject **)&cpy_r_r21;
    cpy_r_r23 = PyObject_VectorcallMethod(cpy_r_r20, cpy_r_r22, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL15;
    } else
        goto CPyL16;
CPyL10: ;
    return cpy_r_value;
CPyL11: ;
    cpy_r_r24 = NULL;
    return cpy_r_r24;
CPyL12: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL11;
CPyL13: ;
    CPy_DECREF(cpy_r_r5);
    goto CPyL2;
CPyL14: ;
    CPy_DECREF(cpy_r_tail_decoder);
    goto CPyL4;
CPyL15: ;
    CPy_DecRef(cpy_r_value);
    goto CPyL11;
CPyL16: ;
    CPy_DECREF(cpy_r_r23);
    goto CPyL10;
}

PyObject *CPyPy__decoding___decode_head_tail(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", 0};
    static CPyArg_Parser parser = {"OO:decode_head_tail", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    PyObject *retval = CPyDef__decoding___decode_head_tail(arg_self, arg_stream);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_head_tail", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

PyObject *CPyDef__decoding___decode_tuple(PyObject *cpy_r_self, PyObject *cpy_r_stream) {
    char cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    CPyPtr cpy_r_r4;
    int64_t cpy_r_r5;
    PyObject *cpy_r_r6;
    CPyPtr cpy_r_r7;
    int64_t cpy_r_r8;
    int64_t cpy_r_r9;
    char cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject **cpy_r_r13;
    PyObject *cpy_r_r14;
    int64_t cpy_r_r15;
    PyObject *cpy_r_r16;
    cpy_r_r0 = CPyDef__decoding___validate_pointers_tuple(cpy_r_self, cpy_r_stream);
    if (unlikely(cpy_r_r0 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL10;
    }
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decoders' */
    cpy_r_r2 = CPyObject_GetAttr(cpy_r_self, cpy_r_r1);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL10;
    }
    if (likely(PyTuple_Check(cpy_r_r2)))
        cpy_r_r3 = cpy_r_r2;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "decode_tuple", 72, CPyStatic__decoding___globals, "tuple", cpy_r_r2);
        goto CPyL10;
    }
    cpy_r_r4 = (CPyPtr)&((PyVarObject *)cpy_r_r3)->ob_size;
    cpy_r_r5 = *(int64_t *)cpy_r_r4;
    cpy_r_r6 = PyTuple_New(cpy_r_r5);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL11;
    }
    cpy_r_r7 = (CPyPtr)&((PyVarObject *)cpy_r_r3)->ob_size;
    cpy_r_r8 = *(int64_t *)cpy_r_r7;
    cpy_r_r9 = 0;
CPyL5: ;
    cpy_r_r10 = cpy_r_r9 < cpy_r_r8;
    if (!cpy_r_r10) goto CPyL12;
    cpy_r_r11 = CPySequenceTuple_GetItemUnsafe(cpy_r_r3, cpy_r_r9);
    PyObject *cpy_r_r12[1] = {cpy_r_stream};
    cpy_r_r13 = (PyObject **)&cpy_r_r12;
    cpy_r_r14 = PyObject_Vectorcall(cpy_r_r11, cpy_r_r13, 1, 0);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r14 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    CPySequenceTuple_SetItemUnsafe(cpy_r_r6, cpy_r_r9, cpy_r_r14);
    cpy_r_r15 = cpy_r_r9 + 1;
    cpy_r_r9 = cpy_r_r15;
    goto CPyL5;
CPyL9: ;
    return cpy_r_r6;
CPyL10: ;
    cpy_r_r16 = NULL;
    return cpy_r_r16;
CPyL11: ;
    CPy_DecRef(cpy_r_r3);
    goto CPyL10;
CPyL12: ;
    CPy_DECREF(cpy_r_r3);
    goto CPyL9;
CPyL13: ;
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r6);
    goto CPyL10;
}

PyObject *CPyPy__decoding___decode_tuple(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", 0};
    static CPyArg_Parser parser = {"OO:decode_tuple", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    PyObject *retval = CPyDef__decoding___decode_tuple(arg_self, arg_stream);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

char CPyDef__decoding___validate_pointers_tuple(PyObject *cpy_r_self, PyObject *cpy_r_stream) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    CPyTagged cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    CPyPtr cpy_r_r11;
    int64_t cpy_r_r12;
    int64_t cpy_r_r13;
    char cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_decoder;
    PyObject **cpy_r_r17;
    PyObject *cpy_r_r18;
    int64_t cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    CPyTagged cpy_r_r24;
    CPyTagged cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject **cpy_r_r28;
    PyObject *cpy_r_r29;
    CPyTagged cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    CPyPtr cpy_r_r34;
    int64_t cpy_r_r35;
    int64_t cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    CPyPtr cpy_r_r40;
    int64_t cpy_r_r41;
    int64_t cpy_r_r42;
    char cpy_r_r43;
    char cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject *cpy_r_r46;
    char cpy_r_r47;
    PyObject **cpy_r_r49;
    PyObject *cpy_r_r50;
    CPyTagged cpy_r_r51;
    CPyTagged cpy_r_r52;
    int64_t cpy_r_r53;
    char cpy_r_r54;
    int64_t cpy_r_r55;
    char cpy_r_r56;
    char cpy_r_r57;
    char cpy_r_r58;
    int64_t cpy_r_r59;
    char cpy_r_r60;
    int64_t cpy_r_r61;
    char cpy_r_r62;
    char cpy_r_r63;
    char cpy_r_r64;
    char cpy_r_r65;
    char cpy_r_r66;
    PyObject *cpy_r_r67;
    PyObject *cpy_r_r68;
    PyObject **cpy_r_r70;
    PyObject *cpy_r_r71;
    CPyTagged cpy_r_r72;
    CPyTagged cpy_r_r73;
    PyObject *cpy_r_r74;
    PyObject *cpy_r_r75;
    PyObject *cpy_r_r76;
    PyObject *cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    PyObject **cpy_r_r81;
    PyObject *cpy_r_r82;
    int64_t cpy_r_r83;
    int64_t cpy_r_r84;
    PyObject *cpy_r_r85;
    PyObject *cpy_r_r86;
    PyObject **cpy_r_r88;
    PyObject *cpy_r_r89;
    char cpy_r_r90;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'tell' */
    PyObject *cpy_r_r1[1] = {cpy_r_stream};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    if (likely(PyLong_Check(cpy_r_r3)))
        cpy_r_r4 = CPyTagged_FromObject(cpy_r_r3);
    else {
        CPy_TypeError("int", cpy_r_r3); cpy_r_r4 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r4 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_no_head_tail' */
    cpy_r_r6 = CPyObject_GetAttr(cpy_r_self, cpy_r_r5);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL48;
    }
    if (unlikely(!PyBool_Check(cpy_r_r6))) {
        CPy_TypeError("bool", cpy_r_r6); cpy_r_r7 = 2;
    } else
        cpy_r_r7 = cpy_r_r6 == Py_True;
    CPy_DECREF(cpy_r_r6);
    if (unlikely(cpy_r_r7 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL48;
    }
    if (!cpy_r_r7) goto CPyL11;
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decoders' */
    cpy_r_r9 = CPyObject_GetAttr(cpy_r_self, cpy_r_r8);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL48;
    }
    if (likely(PyTuple_Check(cpy_r_r9)))
        cpy_r_r10 = cpy_r_r9;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", 84, CPyStatic__decoding___globals, "tuple", cpy_r_r9);
        goto CPyL48;
    }
    cpy_r_r11 = (CPyPtr)&((PyVarObject *)cpy_r_r10)->ob_size;
    cpy_r_r12 = *(int64_t *)cpy_r_r11;
    cpy_r_r13 = 0;
CPyL8: ;
    cpy_r_r14 = cpy_r_r13 < cpy_r_r12;
    if (!cpy_r_r14) goto CPyL49;
    cpy_r_r15 = CPySequenceTuple_GetItemUnsafe(cpy_r_r10, cpy_r_r13);
    cpy_r_decoder = cpy_r_r15;
    PyObject *cpy_r_r16[1] = {cpy_r_stream};
    cpy_r_r17 = (PyObject **)&cpy_r_r16;
    cpy_r_r18 = PyObject_Vectorcall(cpy_r_decoder, cpy_r_r17, 1, 0);
    CPy_DECREF(cpy_r_decoder);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL50;
    } else
        goto CPyL51;
CPyL10: ;
    cpy_r_r19 = cpy_r_r13 + 1;
    cpy_r_r13 = cpy_r_r19;
    goto CPyL8;
CPyL11: ;
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'len_of_head' */
    cpy_r_r21 = CPyObject_GetAttr(cpy_r_self, cpy_r_r20);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL48;
    }
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 32 */
    cpy_r_r23 = PyNumber_Multiply(cpy_r_r22, cpy_r_r21);
    CPy_DECREF(cpy_r_r21);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL48;
    }
    if (likely(PyLong_Check(cpy_r_r23)))
        cpy_r_r24 = CPyTagged_FromObject(cpy_r_r23);
    else {
        CPy_TypeError("int", cpy_r_r23); cpy_r_r24 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r23);
    if (unlikely(cpy_r_r24 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL48;
    }
    cpy_r_r25 = CPyTagged_Add(cpy_r_r4, cpy_r_r24);
    CPyTagged_DECREF(cpy_r_r24);
    cpy_r_r26 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'getbuffer' */
    PyObject *cpy_r_r27[1] = {cpy_r_stream};
    cpy_r_r28 = (PyObject **)&cpy_r_r27;
    cpy_r_r29 = PyObject_VectorcallMethod(cpy_r_r26, cpy_r_r28, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL52;
    }
    cpy_r_r30 = CPyObject_Size(cpy_r_r29);
    CPy_DECREF(cpy_r_r29);
    if (unlikely(cpy_r_r30 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL52;
    }
    cpy_r_r31 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decoders' */
    cpy_r_r32 = CPyObject_GetAttr(cpy_r_self, cpy_r_r31);
    if (unlikely(cpy_r_r32 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL53;
    }
    if (likely(PyTuple_Check(cpy_r_r32)))
        cpy_r_r33 = cpy_r_r32;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", 89, CPyStatic__decoding___globals, "tuple", cpy_r_r32);
        goto CPyL53;
    }
    cpy_r_r34 = (CPyPtr)&((PyVarObject *)cpy_r_r33)->ob_size;
    cpy_r_r35 = *(int64_t *)cpy_r_r34;
    cpy_r_r36 = 0;
    cpy_r_r37 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_is_head_tail' */
    cpy_r_r38 = CPyObject_GetAttr(cpy_r_self, cpy_r_r37);
    if (unlikely(cpy_r_r38 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL54;
    }
    if (likely(PyTuple_Check(cpy_r_r38)))
        cpy_r_r39 = cpy_r_r38;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", 89, CPyStatic__decoding___globals, "tuple", cpy_r_r38);
        goto CPyL54;
    }
    cpy_r_r40 = (CPyPtr)&((PyVarObject *)cpy_r_r39)->ob_size;
    cpy_r_r41 = *(int64_t *)cpy_r_r40;
    cpy_r_r42 = 0;
CPyL21: ;
    cpy_r_r43 = cpy_r_r36 < cpy_r_r35;
    if (!cpy_r_r43) goto CPyL55;
    cpy_r_r44 = cpy_r_r42 < cpy_r_r41;
    if (!cpy_r_r44) goto CPyL55;
    cpy_r_r45 = CPySequenceTuple_GetItemUnsafe(cpy_r_r33, cpy_r_r36);
    cpy_r_decoder = cpy_r_r45;
    cpy_r_r46 = CPySequenceTuple_GetItemUnsafe(cpy_r_r39, cpy_r_r42);
    if (unlikely(!PyBool_Check(cpy_r_r46))) {
        CPy_TypeError("bool", cpy_r_r46); cpy_r_r47 = 2;
    } else
        cpy_r_r47 = cpy_r_r46 == Py_True;
    CPy_DECREF(cpy_r_r46);
    if (unlikely(cpy_r_r47 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL56;
    }
    if (cpy_r_r47) goto CPyL57;
    PyObject *cpy_r_r48[1] = {cpy_r_stream};
    cpy_r_r49 = (PyObject **)&cpy_r_r48;
    cpy_r_r50 = PyObject_Vectorcall(cpy_r_decoder, cpy_r_r49, 1, 0);
    CPy_DECREF(cpy_r_decoder);
    if (unlikely(cpy_r_r50 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL58;
    } else
        goto CPyL59;
CPyL26: ;
    cpy_r_r51 = CPyDef__decoding___decode_uint_256(cpy_r_stream);
    if (unlikely(cpy_r_r51 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL58;
    }
    cpy_r_r52 = CPyTagged_Add(cpy_r_r4, cpy_r_r51);
    CPyTagged_DECREF(cpy_r_r51);
    cpy_r_r53 = cpy_r_r52 & 1;
    cpy_r_r54 = cpy_r_r53 != 0;
    if (cpy_r_r54) goto CPyL29;
    cpy_r_r55 = cpy_r_r25 & 1;
    cpy_r_r56 = cpy_r_r55 != 0;
    if (!cpy_r_r56) goto CPyL30;
CPyL29: ;
    cpy_r_r57 = CPyTagged_IsLt_(cpy_r_r52, cpy_r_r25);
    if (cpy_r_r57) {
        goto CPyL60;
    } else
        goto CPyL31;
CPyL30: ;
    cpy_r_r58 = (Py_ssize_t)cpy_r_r52 < (Py_ssize_t)cpy_r_r25;
    if (cpy_r_r58) goto CPyL60;
CPyL31: ;
    cpy_r_r59 = cpy_r_r52 & 1;
    cpy_r_r60 = cpy_r_r59 != 0;
    if (cpy_r_r60) goto CPyL33;
    cpy_r_r61 = cpy_r_r30 & 1;
    cpy_r_r62 = cpy_r_r61 != 0;
    if (!cpy_r_r62) goto CPyL34;
CPyL33: ;
    cpy_r_r63 = CPyTagged_IsLt_(cpy_r_r52, cpy_r_r30);
    cpy_r_r64 = cpy_r_r63 ^ 1;
    cpy_r_r65 = cpy_r_r64;
    goto CPyL35;
CPyL34: ;
    cpy_r_r66 = (Py_ssize_t)cpy_r_r52 >= (Py_ssize_t)cpy_r_r30;
    cpy_r_r65 = cpy_r_r66;
CPyL35: ;
    CPyTagged_DECREF(cpy_r_r52);
    if (cpy_r_r65) {
        goto CPyL61;
    } else
        goto CPyL44;
CPyL36: ;
    cpy_r_r67 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Invalid pointer in tuple at location ' */
    cpy_r_r68 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'tell' */
    PyObject *cpy_r_r69[1] = {cpy_r_stream};
    cpy_r_r70 = (PyObject **)&cpy_r_r69;
    cpy_r_r71 = PyObject_VectorcallMethod(cpy_r_r68, cpy_r_r70, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r71 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    if (likely(PyLong_Check(cpy_r_r71)))
        cpy_r_r72 = CPyTagged_FromObject(cpy_r_r71);
    else {
        CPy_TypeError("int", cpy_r_r71); cpy_r_r72 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r71);
    if (unlikely(cpy_r_r72 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    cpy_r_r73 = CPyTagged_Subtract(cpy_r_r72, 64);
    CPyTagged_DECREF(cpy_r_r72);
    cpy_r_r74 = CPyTagged_Str(cpy_r_r73);
    CPyTagged_DECREF(cpy_r_r73);
    if (unlikely(cpy_r_r74 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    cpy_r_r75 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' in payload' */
    cpy_r_r76 = CPyStr_Build(3, cpy_r_r67, cpy_r_r74, cpy_r_r75);
    CPy_DECREF(cpy_r_r74);
    if (unlikely(cpy_r_r76 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    cpy_r_r77 = CPyStatic__decoding___globals;
    cpy_r_r78 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'InvalidPointer' */
    cpy_r_r79 = CPyDict_GetItem(cpy_r_r77, cpy_r_r78);
    if (unlikely(cpy_r_r79 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL62;
    }
    PyObject *cpy_r_r80[1] = {cpy_r_r76};
    cpy_r_r81 = (PyObject **)&cpy_r_r80;
    cpy_r_r82 = PyObject_Vectorcall(cpy_r_r79, cpy_r_r81, 1, 0);
    CPy_DECREF(cpy_r_r79);
    if (unlikely(cpy_r_r82 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL62;
    }
    CPy_DECREF(cpy_r_r76);
    CPy_Raise(cpy_r_r82);
    CPy_DECREF(cpy_r_r82);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL47;
    }
    CPy_Unreachable();
CPyL44: ;
    cpy_r_r83 = cpy_r_r36 + 1;
    cpy_r_r36 = cpy_r_r83;
    cpy_r_r84 = cpy_r_r42 + 1;
    cpy_r_r42 = cpy_r_r84;
    goto CPyL21;
CPyL45: ;
    cpy_r_r85 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'seek' */
    cpy_r_r86 = CPyTagged_StealAsObject(cpy_r_r4);
    PyObject *cpy_r_r87[2] = {cpy_r_stream, cpy_r_r86};
    cpy_r_r88 = (PyObject **)&cpy_r_r87;
    cpy_r_r89 = PyObject_VectorcallMethod(cpy_r_r85, cpy_r_r88, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r89 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL63;
    } else
        goto CPyL64;
CPyL46: ;
    CPy_DECREF(cpy_r_r86);
    return 1;
CPyL47: ;
    cpy_r_r90 = 2;
    return cpy_r_r90;
CPyL48: ;
    CPyTagged_DecRef(cpy_r_r4);
    goto CPyL47;
CPyL49: ;
    CPy_DECREF(cpy_r_r10);
    goto CPyL45;
CPyL50: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r10);
    goto CPyL47;
CPyL51: ;
    CPy_DECREF(cpy_r_r18);
    goto CPyL10;
CPyL52: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r25);
    goto CPyL47;
CPyL53: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r25);
    CPyTagged_DecRef(cpy_r_r30);
    goto CPyL47;
CPyL54: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r25);
    CPyTagged_DecRef(cpy_r_r30);
    CPy_DecRef(cpy_r_r33);
    goto CPyL47;
CPyL55: ;
    CPyTagged_DECREF(cpy_r_r25);
    CPyTagged_DECREF(cpy_r_r30);
    CPy_DECREF(cpy_r_r33);
    CPy_DECREF(cpy_r_r39);
    goto CPyL45;
CPyL56: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_decoder);
    CPyTagged_DecRef(cpy_r_r25);
    CPyTagged_DecRef(cpy_r_r30);
    CPy_DecRef(cpy_r_r33);
    CPy_DecRef(cpy_r_r39);
    goto CPyL47;
CPyL57: ;
    CPy_DECREF(cpy_r_decoder);
    goto CPyL26;
CPyL58: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r25);
    CPyTagged_DecRef(cpy_r_r30);
    CPy_DecRef(cpy_r_r33);
    CPy_DecRef(cpy_r_r39);
    goto CPyL47;
CPyL59: ;
    CPy_DECREF(cpy_r_r50);
    goto CPyL44;
CPyL60: ;
    CPyTagged_DECREF(cpy_r_r4);
    CPyTagged_DECREF(cpy_r_r25);
    CPyTagged_DECREF(cpy_r_r30);
    CPy_DECREF(cpy_r_r33);
    CPy_DECREF(cpy_r_r39);
    CPyTagged_DECREF(cpy_r_r52);
    goto CPyL36;
CPyL61: ;
    CPyTagged_DECREF(cpy_r_r4);
    CPyTagged_DECREF(cpy_r_r25);
    CPyTagged_DECREF(cpy_r_r30);
    CPy_DECREF(cpy_r_r33);
    CPy_DECREF(cpy_r_r39);
    goto CPyL36;
CPyL62: ;
    CPy_DecRef(cpy_r_r76);
    goto CPyL47;
CPyL63: ;
    CPy_DecRef(cpy_r_r86);
    goto CPyL47;
CPyL64: ;
    CPy_DECREF(cpy_r_r89);
    goto CPyL46;
}

PyObject *CPyPy__decoding___validate_pointers_tuple(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", 0};
    static CPyArg_Parser parser = {"OO:validate_pointers_tuple", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    char retval = CPyDef__decoding___validate_pointers_tuple(arg_self, arg_stream);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

char CPyDef__decoding___validate_pointers_array(PyObject *cpy_r_self, PyObject *cpy_r_stream, CPyTagged cpy_r_array_size) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    CPyTagged cpy_r_r4;
    CPyTagged cpy_r_r5;
    CPyTagged cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject **cpy_r_r9;
    PyObject *cpy_r_r10;
    CPyTagged cpy_r_r11;
    CPyTagged cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r__;
    int64_t cpy_r_r14;
    char cpy_r_r15;
    int64_t cpy_r_r16;
    char cpy_r_r17;
    char cpy_r_r18;
    char cpy_r_r19;
    CPyTagged cpy_r_r20;
    CPyTagged cpy_r_r21;
    int64_t cpy_r_r22;
    char cpy_r_r23;
    int64_t cpy_r_r24;
    char cpy_r_r25;
    char cpy_r_r26;
    char cpy_r_r27;
    int64_t cpy_r_r28;
    char cpy_r_r29;
    int64_t cpy_r_r30;
    char cpy_r_r31;
    char cpy_r_r32;
    char cpy_r_r33;
    char cpy_r_r34;
    char cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject **cpy_r_r39;
    PyObject *cpy_r_r40;
    CPyTagged cpy_r_r41;
    CPyTagged cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject *cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject *cpy_r_r46;
    PyObject *cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject **cpy_r_r50;
    PyObject *cpy_r_r51;
    CPyTagged cpy_r_r52;
    PyObject *cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject *cpy_r_r55;
    PyObject **cpy_r_r57;
    PyObject *cpy_r_r58;
    char cpy_r_r59;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'tell' */
    PyObject *cpy_r_r1[1] = {cpy_r_stream};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    if (likely(PyLong_Check(cpy_r_r3)))
        cpy_r_r4 = CPyTagged_FromObject(cpy_r_r3);
    else {
        CPy_TypeError("int", cpy_r_r3); cpy_r_r4 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r4 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    cpy_r_r5 = CPyTagged_Multiply(64, cpy_r_array_size);
    cpy_r_r6 = CPyTagged_Add(cpy_r_r4, cpy_r_r5);
    CPyTagged_DECREF(cpy_r_r5);
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'getbuffer' */
    PyObject *cpy_r_r8[1] = {cpy_r_stream};
    cpy_r_r9 = (PyObject **)&cpy_r_r8;
    cpy_r_r10 = PyObject_VectorcallMethod(cpy_r_r7, cpy_r_r9, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL31;
    }
    cpy_r_r11 = CPyObject_Size(cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r11 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL31;
    }
    cpy_r_r12 = 0;
    CPyTagged_INCREF(cpy_r_r12);
    cpy_r_r13 = CPyTagged_StealAsObject(cpy_r_r12);
    cpy_r__ = cpy_r_r13;
    CPy_DECREF(cpy_r__);
CPyL5: ;
    cpy_r_r14 = cpy_r_r12 & 1;
    cpy_r_r15 = cpy_r_r14 != 0;
    if (cpy_r_r15) goto CPyL7;
    cpy_r_r16 = cpy_r_array_size & 1;
    cpy_r_r17 = cpy_r_r16 != 0;
    if (!cpy_r_r17) goto CPyL8;
CPyL7: ;
    cpy_r_r18 = CPyTagged_IsLt_(cpy_r_r12, cpy_r_array_size);
    if (cpy_r_r18) {
        goto CPyL9;
    } else
        goto CPyL32;
CPyL8: ;
    cpy_r_r19 = (Py_ssize_t)cpy_r_r12 < (Py_ssize_t)cpy_r_array_size;
    if (!cpy_r_r19) goto CPyL32;
CPyL9: ;
    cpy_r_r20 = CPyDef__decoding___decode_uint_256(cpy_r_stream);
    if (unlikely(cpy_r_r20 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL33;
    }
    cpy_r_r21 = CPyTagged_Add(cpy_r_r4, cpy_r_r20);
    CPyTagged_DECREF(cpy_r_r20);
    cpy_r_r22 = cpy_r_r21 & 1;
    cpy_r_r23 = cpy_r_r22 != 0;
    if (cpy_r_r23) goto CPyL12;
    cpy_r_r24 = cpy_r_r6 & 1;
    cpy_r_r25 = cpy_r_r24 != 0;
    if (!cpy_r_r25) goto CPyL13;
CPyL12: ;
    cpy_r_r26 = CPyTagged_IsLt_(cpy_r_r21, cpy_r_r6);
    if (cpy_r_r26) {
        goto CPyL34;
    } else
        goto CPyL14;
CPyL13: ;
    cpy_r_r27 = (Py_ssize_t)cpy_r_r21 < (Py_ssize_t)cpy_r_r6;
    if (cpy_r_r27) goto CPyL34;
CPyL14: ;
    cpy_r_r28 = cpy_r_r21 & 1;
    cpy_r_r29 = cpy_r_r28 != 0;
    if (cpy_r_r29) goto CPyL16;
    cpy_r_r30 = cpy_r_r11 & 1;
    cpy_r_r31 = cpy_r_r30 != 0;
    if (!cpy_r_r31) goto CPyL17;
CPyL16: ;
    cpy_r_r32 = CPyTagged_IsLt_(cpy_r_r21, cpy_r_r11);
    cpy_r_r33 = cpy_r_r32 ^ 1;
    cpy_r_r34 = cpy_r_r33;
    goto CPyL18;
CPyL17: ;
    cpy_r_r35 = (Py_ssize_t)cpy_r_r21 >= (Py_ssize_t)cpy_r_r11;
    cpy_r_r34 = cpy_r_r35;
CPyL18: ;
    CPyTagged_DECREF(cpy_r_r21);
    if (cpy_r_r34) {
        goto CPyL35;
    } else
        goto CPyL27;
CPyL19: ;
    cpy_r_r36 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Invalid pointer in array at location ' */
    cpy_r_r37 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'tell' */
    PyObject *cpy_r_r38[1] = {cpy_r_stream};
    cpy_r_r39 = (PyObject **)&cpy_r_r38;
    cpy_r_r40 = PyObject_VectorcallMethod(cpy_r_r37, cpy_r_r39, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r40 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    if (likely(PyLong_Check(cpy_r_r40)))
        cpy_r_r41 = CPyTagged_FromObject(cpy_r_r40);
    else {
        CPy_TypeError("int", cpy_r_r40); cpy_r_r41 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r40);
    if (unlikely(cpy_r_r41 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    cpy_r_r42 = CPyTagged_Subtract(cpy_r_r41, 64);
    CPyTagged_DECREF(cpy_r_r41);
    cpy_r_r43 = CPyTagged_Str(cpy_r_r42);
    CPyTagged_DECREF(cpy_r_r42);
    if (unlikely(cpy_r_r43 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    cpy_r_r44 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' in payload' */
    cpy_r_r45 = CPyStr_Build(3, cpy_r_r36, cpy_r_r43, cpy_r_r44);
    CPy_DECREF(cpy_r_r43);
    if (unlikely(cpy_r_r45 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    cpy_r_r46 = CPyStatic__decoding___globals;
    cpy_r_r47 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'InvalidPointer' */
    cpy_r_r48 = CPyDict_GetItem(cpy_r_r46, cpy_r_r47);
    if (unlikely(cpy_r_r48 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL36;
    }
    PyObject *cpy_r_r49[1] = {cpy_r_r45};
    cpy_r_r50 = (PyObject **)&cpy_r_r49;
    cpy_r_r51 = PyObject_Vectorcall(cpy_r_r48, cpy_r_r50, 1, 0);
    CPy_DECREF(cpy_r_r48);
    if (unlikely(cpy_r_r51 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL36;
    }
    CPy_DECREF(cpy_r_r45);
    CPy_Raise(cpy_r_r51);
    CPy_DECREF(cpy_r_r51);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL30;
    }
    CPy_Unreachable();
CPyL27: ;
    cpy_r_r52 = CPyTagged_Add(cpy_r_r12, 2);
    CPyTagged_DECREF(cpy_r_r12);
    CPyTagged_INCREF(cpy_r_r52);
    cpy_r_r12 = cpy_r_r52;
    cpy_r_r53 = CPyTagged_StealAsObject(cpy_r_r52);
    cpy_r__ = cpy_r_r53;
    CPy_DECREF(cpy_r__);
    goto CPyL5;
CPyL28: ;
    cpy_r_r54 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'seek' */
    cpy_r_r55 = CPyTagged_StealAsObject(cpy_r_r4);
    PyObject *cpy_r_r56[2] = {cpy_r_stream, cpy_r_r55};
    cpy_r_r57 = (PyObject **)&cpy_r_r56;
    cpy_r_r58 = PyObject_VectorcallMethod(cpy_r_r54, cpy_r_r57, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r58 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL37;
    } else
        goto CPyL38;
CPyL29: ;
    CPy_DECREF(cpy_r_r55);
    return 1;
CPyL30: ;
    cpy_r_r59 = 2;
    return cpy_r_r59;
CPyL31: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r6);
    goto CPyL30;
CPyL32: ;
    CPyTagged_DECREF(cpy_r_r6);
    CPyTagged_DECREF(cpy_r_r11);
    CPyTagged_DECREF(cpy_r_r12);
    goto CPyL28;
CPyL33: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r6);
    CPyTagged_DecRef(cpy_r_r11);
    CPyTagged_DecRef(cpy_r_r12);
    goto CPyL30;
CPyL34: ;
    CPyTagged_DECREF(cpy_r_r4);
    CPyTagged_DECREF(cpy_r_r6);
    CPyTagged_DECREF(cpy_r_r11);
    CPyTagged_DECREF(cpy_r_r12);
    CPyTagged_DECREF(cpy_r_r21);
    goto CPyL19;
CPyL35: ;
    CPyTagged_DECREF(cpy_r_r4);
    CPyTagged_DECREF(cpy_r_r6);
    CPyTagged_DECREF(cpy_r_r11);
    CPyTagged_DECREF(cpy_r_r12);
    goto CPyL19;
CPyL36: ;
    CPy_DecRef(cpy_r_r45);
    goto CPyL30;
CPyL37: ;
    CPy_DecRef(cpy_r_r55);
    goto CPyL30;
CPyL38: ;
    CPy_DECREF(cpy_r_r58);
    goto CPyL29;
}

PyObject *CPyPy__decoding___validate_pointers_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", "array_size", 0};
    static CPyArg_Parser parser = {"OOO:validate_pointers_array", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    PyObject *obj_array_size;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream, &obj_array_size)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    CPyTagged arg_array_size;
    if (likely(PyLong_Check(obj_array_size)))
        arg_array_size = CPyTagged_BorrowFromObject(obj_array_size);
    else {
        CPy_TypeError("int", obj_array_size); goto fail;
    }
    char retval = CPyDef__decoding___validate_pointers_array(arg_self, arg_stream, arg_array_size);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_pointers_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

PyObject *CPyDef__decoding___decode_sized_array(PyObject *cpy_r_self, PyObject *cpy_r_stream) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject **cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    CPyTagged cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject **cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    CPyTagged cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r__;
    int64_t cpy_r_r22;
    char cpy_r_r23;
    int64_t cpy_r_r24;
    char cpy_r_r25;
    char cpy_r_r26;
    char cpy_r_r27;
    PyObject **cpy_r_r29;
    PyObject *cpy_r_r30;
    int32_t cpy_r_r31;
    char cpy_r_r32;
    CPyTagged cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'item_decoder' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r_self, cpy_r_r0);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL20;
    }
    cpy_r_r2 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r3 = cpy_r_r1 == cpy_r_r2;
    if (cpy_r_r3) {
        goto CPyL21;
    } else
        goto CPyL6;
CPyL2: ;
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '`item_decoder` is None' */
    cpy_r_r5 = CPyModule_builtins;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'AssertionError' */
    cpy_r_r7 = CPyObject_GetAttr(cpy_r_r5, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL20;
    }
    PyObject *cpy_r_r8[1] = {cpy_r_r4};
    cpy_r_r9 = (PyObject **)&cpy_r_r8;
    cpy_r_r10 = PyObject_Vectorcall(cpy_r_r7, cpy_r_r9, 1, 0);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL20;
    }
    CPy_Raise(cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL20;
    }
    CPy_Unreachable();
CPyL6: ;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'array_size' */
    cpy_r_r12 = CPyObject_GetAttr(cpy_r_self, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL22;
    }
    if (likely(PyLong_Check(cpy_r_r12)))
        cpy_r_r13 = CPyTagged_FromObject(cpy_r_r12);
    else {
        CPy_TypeError("int", cpy_r_r12); cpy_r_r13 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r13 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL22;
    }
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'validate_pointers' */
    CPyTagged_INCREF(cpy_r_r13);
    cpy_r_r15 = CPyTagged_StealAsObject(cpy_r_r13);
    PyObject *cpy_r_r16[3] = {cpy_r_self, cpy_r_stream, cpy_r_r15};
    cpy_r_r17 = (PyObject **)&cpy_r_r16;
    cpy_r_r18 = PyObject_VectorcallMethod(cpy_r_r14, cpy_r_r17, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL23;
    } else
        goto CPyL24;
CPyL9: ;
    CPy_DECREF(cpy_r_r15);
    cpy_r_r19 = PyList_New(0);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL25;
    }
    cpy_r_r20 = 0;
    CPyTagged_INCREF(cpy_r_r20);
    cpy_r_r21 = CPyTagged_StealAsObject(cpy_r_r20);
    cpy_r__ = cpy_r_r21;
    CPy_DECREF(cpy_r__);
CPyL11: ;
    cpy_r_r22 = cpy_r_r20 & 1;
    cpy_r_r23 = cpy_r_r22 != 0;
    if (cpy_r_r23) goto CPyL13;
    cpy_r_r24 = cpy_r_r13 & 1;
    cpy_r_r25 = cpy_r_r24 != 0;
    if (!cpy_r_r25) goto CPyL14;
CPyL13: ;
    cpy_r_r26 = CPyTagged_IsLt_(cpy_r_r20, cpy_r_r13);
    if (cpy_r_r26) {
        goto CPyL15;
    } else
        goto CPyL26;
CPyL14: ;
    cpy_r_r27 = (Py_ssize_t)cpy_r_r20 < (Py_ssize_t)cpy_r_r13;
    if (!cpy_r_r27) goto CPyL26;
CPyL15: ;
    PyObject *cpy_r_r28[1] = {cpy_r_stream};
    cpy_r_r29 = (PyObject **)&cpy_r_r28;
    cpy_r_r30 = PyObject_Vectorcall(cpy_r_r1, cpy_r_r29, 1, 0);
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL27;
    }
    cpy_r_r31 = PyList_Append(cpy_r_r19, cpy_r_r30);
    CPy_DECREF(cpy_r_r30);
    cpy_r_r32 = cpy_r_r31 >= 0;
    if (unlikely(!cpy_r_r32)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL27;
    }
    cpy_r_r33 = CPyTagged_Add(cpy_r_r20, 2);
    CPyTagged_DECREF(cpy_r_r20);
    CPyTagged_INCREF(cpy_r_r33);
    cpy_r_r20 = cpy_r_r33;
    cpy_r_r34 = CPyTagged_StealAsObject(cpy_r_r33);
    cpy_r__ = cpy_r_r34;
    CPy_DECREF(cpy_r__);
    goto CPyL11;
CPyL18: ;
    cpy_r_r35 = PyList_AsTuple(cpy_r_r19);
    CPy_DECREF_NO_IMM(cpy_r_r19);
    if (unlikely(cpy_r_r35 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL20;
    }
    return cpy_r_r35;
CPyL20: ;
    cpy_r_r36 = NULL;
    return cpy_r_r36;
CPyL21: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL2;
CPyL22: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL20;
CPyL23: ;
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_r13);
    CPy_DecRef(cpy_r_r15);
    goto CPyL20;
CPyL24: ;
    CPy_DECREF(cpy_r_r18);
    goto CPyL9;
CPyL25: ;
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_r13);
    goto CPyL20;
CPyL26: ;
    CPy_DECREF(cpy_r_r1);
    CPyTagged_DECREF(cpy_r_r13);
    CPyTagged_DECREF(cpy_r_r20);
    goto CPyL18;
CPyL27: ;
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_r13);
    CPy_DecRef(cpy_r_r19);
    CPyTagged_DecRef(cpy_r_r20);
    goto CPyL20;
}

PyObject *CPyPy__decoding___decode_sized_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", 0};
    static CPyArg_Parser parser = {"OO:decode_sized_array", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    PyObject *retval = CPyDef__decoding___decode_sized_array(arg_self, arg_stream);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_sized_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

PyObject *CPyDef__decoding___decode_dynamic_array(PyObject *cpy_r_self, PyObject *cpy_r_stream) {
    CPyTagged cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject **cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject **cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    CPyTagged cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r__;
    int64_t cpy_r_r27;
    char cpy_r_r28;
    int64_t cpy_r_r29;
    char cpy_r_r30;
    char cpy_r_r31;
    char cpy_r_r32;
    PyObject **cpy_r_r34;
    PyObject *cpy_r_r35;
    int32_t cpy_r_r36;
    char cpy_r_r37;
    CPyTagged cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject *cpy_r_r40;
    PyObject *cpy_r_r41;
    tuple_T3OOO cpy_r_r42;
    tuple_T3OOO cpy_r_r43;
    PyObject *cpy_r_r44;
    tuple_T3OOO cpy_r_r45;
    PyObject *cpy_r_r46;
    PyObject **cpy_r_r48;
    PyObject *cpy_r_r49;
    char cpy_r_r50;
    PyObject *cpy_r_r51;
    cpy_r_r0 = CPyDef__decoding___decode_uint_256(cpy_r_stream);
    if (unlikely(cpy_r_r0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL35;
    }
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'push_frame' */
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 32 */
    PyObject *cpy_r_r3[2] = {cpy_r_stream, cpy_r_r2};
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r4, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL36;
    } else
        goto CPyL37;
CPyL2: ;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'item_decoder' */
    cpy_r_r7 = CPyObject_GetAttr(cpy_r_self, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL36;
    }
    cpy_r_r8 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r9 = cpy_r_r7 == cpy_r_r8;
    CPy_DECREF(cpy_r_r7);
    if (cpy_r_r9) {
        goto CPyL38;
    } else
        goto CPyL8;
CPyL4: ;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '`item_decoder` is None' */
    cpy_r_r11 = CPyModule_builtins;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'AssertionError' */
    cpy_r_r13 = CPyObject_GetAttr(cpy_r_r11, cpy_r_r12);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL35;
    }
    PyObject *cpy_r_r14[1] = {cpy_r_r10};
    cpy_r_r15 = (PyObject **)&cpy_r_r14;
    cpy_r_r16 = PyObject_Vectorcall(cpy_r_r13, cpy_r_r15, 1, 0);
    CPy_DECREF(cpy_r_r13);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL35;
    }
    CPy_Raise(cpy_r_r16);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL35;
    }
    CPy_Unreachable();
CPyL8: ;
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'validate_pointers' */
    CPyTagged_INCREF(cpy_r_r0);
    cpy_r_r18 = CPyTagged_StealAsObject(cpy_r_r0);
    PyObject *cpy_r_r19[3] = {cpy_r_self, cpy_r_stream, cpy_r_r18};
    cpy_r_r20 = (PyObject **)&cpy_r_r19;
    cpy_r_r21 = PyObject_VectorcallMethod(cpy_r_r17, cpy_r_r20, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL39;
    } else
        goto CPyL40;
CPyL9: ;
    CPy_DECREF(cpy_r_r18);
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'item_decoder' */
    cpy_r_r23 = CPyObject_GetAttr(cpy_r_self, cpy_r_r22);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL36;
    }
    cpy_r_r24 = PyList_New(0);
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL41;
    }
    cpy_r_r25 = 0;
    CPyTagged_INCREF(cpy_r_r25);
    cpy_r_r26 = CPyTagged_StealAsObject(cpy_r_r25);
    cpy_r__ = cpy_r_r26;
    CPy_DECREF(cpy_r__);
CPyL13: ;
    cpy_r_r27 = cpy_r_r25 & 1;
    cpy_r_r28 = cpy_r_r27 != 0;
    if (cpy_r_r28) goto CPyL15;
    cpy_r_r29 = cpy_r_r0 & 1;
    cpy_r_r30 = cpy_r_r29 != 0;
    if (!cpy_r_r30) goto CPyL16;
CPyL15: ;
    cpy_r_r31 = CPyTagged_IsLt_(cpy_r_r25, cpy_r_r0);
    if (cpy_r_r31) {
        goto CPyL17;
    } else
        goto CPyL42;
CPyL16: ;
    cpy_r_r32 = (Py_ssize_t)cpy_r_r25 < (Py_ssize_t)cpy_r_r0;
    if (!cpy_r_r32) goto CPyL42;
CPyL17: ;
    PyObject *cpy_r_r33[1] = {cpy_r_stream};
    cpy_r_r34 = (PyObject **)&cpy_r_r33;
    cpy_r_r35 = PyObject_Vectorcall(cpy_r_r23, cpy_r_r34, 1, 0);
    if (unlikely(cpy_r_r35 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL43;
    }
    cpy_r_r36 = PyList_Append(cpy_r_r24, cpy_r_r35);
    CPy_DECREF(cpy_r_r35);
    cpy_r_r37 = cpy_r_r36 >= 0;
    if (unlikely(!cpy_r_r37)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL43;
    }
    cpy_r_r38 = CPyTagged_Add(cpy_r_r25, 2);
    CPyTagged_DECREF(cpy_r_r25);
    CPyTagged_INCREF(cpy_r_r38);
    cpy_r_r25 = cpy_r_r38;
    cpy_r_r39 = CPyTagged_StealAsObject(cpy_r_r38);
    cpy_r__ = cpy_r_r39;
    CPy_DECREF(cpy_r__);
    goto CPyL13;
CPyL20: ;
    cpy_r_r40 = PyList_AsTuple(cpy_r_r24);
    CPy_DECREF_NO_IMM(cpy_r_r24);
    if (unlikely(cpy_r_r40 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL23;
    }
    cpy_r_r41 = cpy_r_r40;
    tuple_T3OOO __tmp2 = { NULL, NULL, NULL };
    cpy_r_r42 = __tmp2;
    cpy_r_r43 = cpy_r_r42;
    goto CPyL24;
CPyL23: ;
    cpy_r_r44 = NULL;
    cpy_r_r41 = cpy_r_r44;
    cpy_r_r45 = CPy_CatchError();
    cpy_r_r43 = cpy_r_r45;
CPyL24: ;
    cpy_r_r46 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'pop_frame' */
    PyObject *cpy_r_r47[1] = {cpy_r_stream};
    cpy_r_r48 = (PyObject **)&cpy_r_r47;
    cpy_r_r49 = PyObject_VectorcallMethod(cpy_r_r46, cpy_r_r48, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r49 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL44;
    } else
        goto CPyL45;
CPyL25: ;
    if (cpy_r_r43.f0 == NULL) {
        goto CPyL28;
    } else
        goto CPyL46;
CPyL26: ;
    CPy_Reraise();
    if (!0) {
        goto CPyL30;
    } else
        goto CPyL47;
CPyL27: ;
    CPy_Unreachable();
CPyL28: ;
    if (cpy_r_r41 == NULL) goto CPyL34;
    return cpy_r_r41;
CPyL30: ;
    if (cpy_r_r43.f0 == NULL) goto CPyL32;
    CPy_RestoreExcInfo(cpy_r_r43);
    CPy_XDECREF(cpy_r_r43.f0);
    CPy_XDECREF(cpy_r_r43.f1);
    CPy_XDECREF(cpy_r_r43.f2);
CPyL32: ;
    cpy_r_r50 = CPy_KeepPropagating();
    if (!cpy_r_r50) goto CPyL35;
    CPy_Unreachable();
CPyL34: ;
    CPy_Unreachable();
CPyL35: ;
    cpy_r_r51 = NULL;
    return cpy_r_r51;
CPyL36: ;
    CPyTagged_DecRef(cpy_r_r0);
    goto CPyL35;
CPyL37: ;
    CPy_DECREF(cpy_r_r5);
    goto CPyL2;
CPyL38: ;
    CPyTagged_DECREF(cpy_r_r0);
    goto CPyL4;
CPyL39: ;
    CPyTagged_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r18);
    goto CPyL35;
CPyL40: ;
    CPy_DECREF(cpy_r_r21);
    goto CPyL9;
CPyL41: ;
    CPyTagged_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r23);
    goto CPyL23;
CPyL42: ;
    CPyTagged_DECREF(cpy_r_r0);
    CPy_DECREF(cpy_r_r23);
    CPyTagged_DECREF(cpy_r_r25);
    goto CPyL20;
CPyL43: ;
    CPyTagged_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r23);
    CPy_DecRef(cpy_r_r24);
    CPyTagged_DecRef(cpy_r_r25);
    goto CPyL23;
CPyL44: ;
    CPy_XDecRef(cpy_r_r41);
    goto CPyL30;
CPyL45: ;
    CPy_DECREF(cpy_r_r49);
    goto CPyL25;
CPyL46: ;
    CPy_XDECREF(cpy_r_r41);
    goto CPyL26;
CPyL47: ;
    CPy_XDECREF(cpy_r_r43.f0);
    CPy_XDECREF(cpy_r_r43.f1);
    CPy_XDECREF(cpy_r_r43.f2);
    goto CPyL27;
}

PyObject *CPyPy__decoding___decode_dynamic_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", 0};
    static CPyArg_Parser parser = {"OO:decode_dynamic_array", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    PyObject *retval = CPyDef__decoding___decode_dynamic_array(arg_self, arg_stream);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "decode_dynamic_array", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

PyObject *CPyDef__decoding___read_fixed_byte_size_data_from_stream(PyObject *cpy_r_self, PyObject *cpy_r_stream) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    CPyTagged cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject **cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    CPyPtr cpy_r_r9;
    int64_t cpy_r_r10;
    CPyTagged cpy_r_r11;
    char cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    CPyPtr cpy_r_r16;
    int64_t cpy_r_r17;
    CPyTagged cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject **cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'data_byte_size' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r_self, cpy_r_r0);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    if (likely(PyLong_Check(cpy_r_r1)))
        cpy_r_r2 = CPyTagged_FromObject(cpy_r_r1);
    else {
        CPy_TypeError("int", cpy_r_r1); cpy_r_r2 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r1);
    if (unlikely(cpy_r_r2 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'read' */
    CPyTagged_INCREF(cpy_r_r2);
    cpy_r_r4 = CPyTagged_StealAsObject(cpy_r_r2);
    PyObject *cpy_r_r5[2] = {cpy_r_stream, cpy_r_r4};
    cpy_r_r6 = (PyObject **)&cpy_r_r5;
    cpy_r_r7 = PyObject_VectorcallMethod(cpy_r_r3, cpy_r_r6, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    CPy_DECREF(cpy_r_r4);
    if (likely(PyBytes_Check(cpy_r_r7) || PyByteArray_Check(cpy_r_r7)))
        cpy_r_r8 = cpy_r_r7;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", 169, CPyStatic__decoding___globals, "bytes", cpy_r_r7);
        goto CPyL15;
    }
    CPy_INCREF(cpy_r_r8);
    cpy_r_r9 = (CPyPtr)&((PyVarObject *)cpy_r_r8)->ob_size;
    cpy_r_r10 = *(int64_t *)cpy_r_r9;
    CPy_DECREF(cpy_r_r8);
    cpy_r_r11 = cpy_r_r10 << 1;
    cpy_r_r12 = cpy_r_r11 == cpy_r_r2;
    if (cpy_r_r12) {
        goto CPyL16;
    } else
        goto CPyL6;
CPyL5: ;
    return cpy_r_r8;
CPyL6: ;
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Tried to read ' */
    cpy_r_r14 = CPyTagged_Str(cpy_r_r2);
    CPyTagged_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r14 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL17;
    }
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' bytes, only got ' */
    cpy_r_r16 = (CPyPtr)&((PyVarObject *)cpy_r_r8)->ob_size;
    cpy_r_r17 = *(int64_t *)cpy_r_r16;
    CPy_DECREF(cpy_r_r8);
    cpy_r_r18 = cpy_r_r17 << 1;
    cpy_r_r19 = CPyTagged_Str(cpy_r_r18);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL18;
    }
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' bytes.' */
    cpy_r_r21 = CPyStr_Build(5, cpy_r_r13, cpy_r_r14, cpy_r_r15, cpy_r_r19, cpy_r_r20);
    CPy_DECREF(cpy_r_r14);
    CPy_DECREF(cpy_r_r19);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    cpy_r_r22 = CPyStatic__decoding___globals;
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'InsufficientDataBytes' */
    cpy_r_r24 = CPyDict_GetItem(cpy_r_r22, cpy_r_r23);
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL19;
    }
    PyObject *cpy_r_r25[1] = {cpy_r_r21};
    cpy_r_r26 = (PyObject **)&cpy_r_r25;
    cpy_r_r27 = PyObject_Vectorcall(cpy_r_r24, cpy_r_r26, 1, 0);
    CPy_DECREF(cpy_r_r24);
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL19;
    }
    CPy_DECREF(cpy_r_r21);
    CPy_Raise(cpy_r_r27);
    CPy_DECREF(cpy_r_r27);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL13;
    }
    CPy_Unreachable();
CPyL13: ;
    cpy_r_r28 = NULL;
    return cpy_r_r28;
CPyL14: ;
    CPyTagged_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r4);
    goto CPyL13;
CPyL15: ;
    CPyTagged_DecRef(cpy_r_r2);
    goto CPyL13;
CPyL16: ;
    CPyTagged_DECREF(cpy_r_r2);
    goto CPyL5;
CPyL17: ;
    CPy_DecRef(cpy_r_r8);
    goto CPyL13;
CPyL18: ;
    CPy_DecRef(cpy_r_r14);
    goto CPyL13;
CPyL19: ;
    CPy_DecRef(cpy_r_r21);
    goto CPyL13;
}

PyObject *CPyPy__decoding___read_fixed_byte_size_data_from_stream(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "stream", 0};
    static CPyArg_Parser parser = {"OO:read_fixed_byte_size_data_from_stream", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_stream;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_stream)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_stream = obj_stream;
    PyObject *retval = CPyDef__decoding___read_fixed_byte_size_data_from_stream(arg_self, arg_stream);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "read_fixed_byte_size_data_from_stream", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

tuple_T2OO CPyDef__decoding___split_data_and_padding_fixed_byte_size(PyObject *cpy_r_self, PyObject *cpy_r_raw_data) {
    CPyTagged cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    CPyTagged cpy_r_r3;
    CPyTagged cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    char cpy_r_r8;
    PyObject *cpy_r_r9;
    tuple_T2OO cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_padding_bytes;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_data;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    tuple_T2OO cpy_r_r15;
    tuple_T2OO cpy_r_r16;
    cpy_r_r0 = CPyDef__decoding___get_value_byte_size(cpy_r_self);
    if (unlikely(cpy_r_r0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL15;
    }
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'data_byte_size' */
    cpy_r_r2 = CPyObject_GetAttr(cpy_r_self, cpy_r_r1);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    if (likely(PyLong_Check(cpy_r_r2)))
        cpy_r_r3 = CPyTagged_FromObject(cpy_r_r2);
    else {
        CPy_TypeError("int", cpy_r_r2); cpy_r_r3 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r3 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    cpy_r_r4 = CPyTagged_Subtract(cpy_r_r3, cpy_r_r0);
    CPyTagged_DECREF(cpy_r_r3);
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_big_endian' */
    cpy_r_r6 = CPyObject_GetAttr(cpy_r_self, cpy_r_r5);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL17;
    }
    if (unlikely(!PyBool_Check(cpy_r_r6))) {
        CPy_TypeError("bool", cpy_r_r6); cpy_r_r7 = 2;
    } else
        cpy_r_r7 = cpy_r_r6 == Py_True;
    CPy_DECREF(cpy_r_r6);
    if (unlikely(cpy_r_r7 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL17;
    }
    if (cpy_r_r7) {
        goto CPyL18;
    } else
        goto CPyL19;
CPyL6: ;
    cpy_r_r8 = cpy_r_r4 == 0;
    if (cpy_r_r8) {
        goto CPyL20;
    } else
        goto CPyL8;
CPyL7: ;
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    CPy_INCREF(cpy_r_raw_data);
    CPy_INCREF(cpy_r_r9);
    cpy_r_r10.f0 = cpy_r_raw_data;
    cpy_r_r10.f1 = cpy_r_r9;
    return cpy_r_r10;
CPyL8: ;
    cpy_r_r11 = CPyBytes_GetSlice(cpy_r_raw_data, 0, cpy_r_r4);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL21;
    }
    cpy_r_padding_bytes = cpy_r_r11;
    cpy_r_r12 = CPyBytes_GetSlice(cpy_r_raw_data, cpy_r_r4, 9223372036854775806LL);
    CPyTagged_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL22;
    }
    cpy_r_data = cpy_r_r12;
    goto CPyL14;
CPyL11: ;
    cpy_r_r13 = CPyBytes_GetSlice(cpy_r_raw_data, 0, cpy_r_r0);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    cpy_r_data = cpy_r_r13;
    cpy_r_r14 = CPyBytes_GetSlice(cpy_r_raw_data, cpy_r_r0, 9223372036854775806LL);
    CPyTagged_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r14 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL23;
    }
    cpy_r_padding_bytes = cpy_r_r14;
CPyL14: ;
    cpy_r_r15.f0 = cpy_r_data;
    cpy_r_r15.f1 = cpy_r_padding_bytes;
    return cpy_r_r15;
CPyL15: ;
    tuple_T2OO __tmp3 = { NULL, NULL };
    cpy_r_r16 = __tmp3;
    return cpy_r_r16;
CPyL16: ;
    CPyTagged_DecRef(cpy_r_r0);
    goto CPyL15;
CPyL17: ;
    CPyTagged_DecRef(cpy_r_r0);
    CPyTagged_DecRef(cpy_r_r4);
    goto CPyL15;
CPyL18: ;
    CPyTagged_DECREF(cpy_r_r0);
    goto CPyL6;
CPyL19: ;
    CPyTagged_DECREF(cpy_r_r4);
    goto CPyL11;
CPyL20: ;
    CPyTagged_DECREF(cpy_r_r4);
    goto CPyL7;
CPyL21: ;
    CPyTagged_DecRef(cpy_r_r4);
    goto CPyL15;
CPyL22: ;
    CPy_DecRef(cpy_r_padding_bytes);
    goto CPyL15;
CPyL23: ;
    CPy_DecRef(cpy_r_data);
    goto CPyL15;
}

PyObject *CPyPy__decoding___split_data_and_padding_fixed_byte_size(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "raw_data", 0};
    static CPyArg_Parser parser = {"OO:split_data_and_padding_fixed_byte_size", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_raw_data;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_raw_data)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_raw_data;
    if (likely(PyBytes_Check(obj_raw_data) || PyByteArray_Check(obj_raw_data)))
        arg_raw_data = obj_raw_data;
    else {
        CPy_TypeError("bytes", obj_raw_data); 
        goto fail;
    }
    tuple_T2OO retval = CPyDef__decoding___split_data_and_padding_fixed_byte_size(arg_self, arg_raw_data);
    if (retval.f0 == NULL) {
        return NULL;
    }
    PyObject *retbox = PyTuple_New(2);
    if (unlikely(retbox == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp4 = retval.f0;
    PyTuple_SET_ITEM(retbox, 0, __tmp4);
    PyObject *__tmp5 = retval.f1;
    PyTuple_SET_ITEM(retbox, 1, __tmp5);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "split_data_and_padding_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

char CPyDef__decoding___validate_padding_bytes_fixed_byte_size(PyObject *cpy_r_self, PyObject *cpy_r_value, PyObject *cpy_r_padding_bytes) {
    CPyTagged cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    CPyTagged cpy_r_r3;
    CPyTagged cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    int32_t cpy_r_r9;
    char cpy_r_r10;
    char cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    CPyPtr cpy_r_r22;
    CPyPtr cpy_r_r23;
    CPyPtr cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject **cpy_r_r30;
    PyObject *cpy_r_r31;
    char cpy_r_r32;
    cpy_r_r0 = CPyDef__decoding___get_value_byte_size(cpy_r_self);
    if (unlikely(cpy_r_r0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'data_byte_size' */
    cpy_r_r2 = CPyObject_GetAttr(cpy_r_self, cpy_r_r1);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL17;
    }
    if (likely(PyLong_Check(cpy_r_r2)))
        cpy_r_r3 = CPyTagged_FromObject(cpy_r_r2);
    else {
        CPy_TypeError("int", cpy_r_r2); cpy_r_r3 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r3 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL17;
    }
    cpy_r_r4 = CPyTagged_Subtract(cpy_r_r3, cpy_r_r0);
    CPyTagged_DECREF(cpy_r_r3);
    CPyTagged_DECREF(cpy_r_r0);
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r6 = CPyTagged_StealAsObject(cpy_r_r4);
    cpy_r_r7 = PyNumber_Multiply(cpy_r_r5, cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    if (likely(PyBytes_Check(cpy_r_r7) || PyByteArray_Check(cpy_r_r7)))
        cpy_r_r8 = cpy_r_r7;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", 203, CPyStatic__decoding___globals, "bytes", cpy_r_r7);
        goto CPyL16;
    }
    cpy_r_r9 = CPyBytes_Compare(cpy_r_padding_bytes, cpy_r_r8);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r10 = cpy_r_r9 >= 0;
    if (unlikely(!cpy_r_r10)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    cpy_r_r11 = cpy_r_r9 != 1;
    if (!cpy_r_r11) goto CPyL15;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Padding bytes were not empty: ' */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{!r:{}}' */
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r17[3] = {cpy_r_r14, cpy_r_padding_bytes, cpy_r_r15};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_VectorcallMethod(cpy_r_r16, cpy_r_r18, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    if (likely(PyUnicode_Check(cpy_r_r19)))
        cpy_r_r20 = cpy_r_r19;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", 204, CPyStatic__decoding___globals, "str", cpy_r_r19);
        goto CPyL16;
    }
    cpy_r_r21 = PyList_New(2);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL18;
    }
    cpy_r_r22 = (CPyPtr)&((PyListObject *)cpy_r_r21)->ob_item;
    cpy_r_r23 = *(CPyPtr *)cpy_r_r22;
    CPy_INCREF(cpy_r_r13);
    *(PyObject * *)cpy_r_r23 = cpy_r_r13;
    cpy_r_r24 = cpy_r_r23 + 8;
    *(PyObject * *)cpy_r_r24 = cpy_r_r20;
    cpy_r_r25 = PyUnicode_Join(cpy_r_r12, cpy_r_r21);
    CPy_DECREF_NO_IMM(cpy_r_r21);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    cpy_r_r26 = CPyStatic__decoding___globals;
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NonEmptyPaddingBytes' */
    cpy_r_r28 = CPyDict_GetItem(cpy_r_r26, cpy_r_r27);
    if (unlikely(cpy_r_r28 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL19;
    }
    PyObject *cpy_r_r29[1] = {cpy_r_r25};
    cpy_r_r30 = (PyObject **)&cpy_r_r29;
    cpy_r_r31 = PyObject_Vectorcall(cpy_r_r28, cpy_r_r30, 1, 0);
    CPy_DECREF(cpy_r_r28);
    if (unlikely(cpy_r_r31 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL19;
    }
    CPy_DECREF(cpy_r_r25);
    CPy_Raise(cpy_r_r31);
    CPy_DECREF(cpy_r_r31);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    CPy_Unreachable();
CPyL15: ;
    return 1;
CPyL16: ;
    cpy_r_r32 = 2;
    return cpy_r_r32;
CPyL17: ;
    CPyTagged_DecRef(cpy_r_r0);
    goto CPyL16;
CPyL18: ;
    CPy_DecRef(cpy_r_r20);
    goto CPyL16;
CPyL19: ;
    CPy_DecRef(cpy_r_r25);
    goto CPyL16;
}

PyObject *CPyPy__decoding___validate_padding_bytes_fixed_byte_size(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"self", "value", "padding_bytes", 0};
    static CPyArg_Parser parser = {"OOO:validate_padding_bytes_fixed_byte_size", kwlist, 0};
    PyObject *obj_self;
    PyObject *obj_value;
    PyObject *obj_padding_bytes;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_self, &obj_value, &obj_padding_bytes)) {
        return NULL;
    }
    PyObject *arg_self = obj_self;
    PyObject *arg_value = obj_value;
    PyObject *arg_padding_bytes;
    if (likely(PyBytes_Check(obj_padding_bytes) || PyByteArray_Check(obj_padding_bytes)))
        arg_padding_bytes = obj_padding_bytes;
    else {
        CPy_TypeError("bytes", obj_padding_bytes); 
        goto fail;
    }
    char retval = CPyDef__decoding___validate_padding_bytes_fixed_byte_size(arg_self, arg_value, arg_padding_bytes);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "validate_padding_bytes_fixed_byte_size", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

char CPyDef__decoding___decoder_fn_boolean(PyObject *cpy_r_data) {
    PyObject *cpy_r_r0;
    int32_t cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    int32_t cpy_r_r5;
    char cpy_r_r6;
    char cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject **cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    CPyPtr cpy_r_r18;
    CPyPtr cpy_r_r19;
    CPyPtr cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject **cpy_r_r26;
    PyObject *cpy_r_r27;
    char cpy_r_r28;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r1 = CPyBytes_Compare(cpy_r_data, cpy_r_r0);
    cpy_r_r2 = cpy_r_r1 >= 0;
    if (unlikely(!cpy_r_r2)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    cpy_r_r3 = cpy_r_r1 == 1;
    if (!cpy_r_r3) goto CPyL3;
    return 0;
CPyL3: ;
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x01' */
    cpy_r_r5 = CPyBytes_Compare(cpy_r_data, cpy_r_r4);
    cpy_r_r6 = cpy_r_r5 >= 0;
    if (unlikely(!cpy_r_r6)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    cpy_r_r7 = cpy_r_r5 == 1;
    if (!cpy_r_r7) goto CPyL6;
    return 1;
CPyL6: ;
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Boolean must be either 0x0 or 0x1.  Got: ' */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{!r:{}}' */
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r13[3] = {cpy_r_r10, cpy_r_data, cpy_r_r11};
    cpy_r_r14 = (PyObject **)&cpy_r_r13;
    cpy_r_r15 = PyObject_VectorcallMethod(cpy_r_r12, cpy_r_r14, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    if (likely(PyUnicode_Check(cpy_r_r15)))
        cpy_r_r16 = cpy_r_r15;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", 213, CPyStatic__decoding___globals, "str", cpy_r_r15);
        goto CPyL14;
    }
    cpy_r_r17 = PyList_New(2);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL15;
    }
    cpy_r_r18 = (CPyPtr)&((PyListObject *)cpy_r_r17)->ob_item;
    cpy_r_r19 = *(CPyPtr *)cpy_r_r18;
    CPy_INCREF(cpy_r_r9);
    *(PyObject * *)cpy_r_r19 = cpy_r_r9;
    cpy_r_r20 = cpy_r_r19 + 8;
    *(PyObject * *)cpy_r_r20 = cpy_r_r16;
    cpy_r_r21 = PyUnicode_Join(cpy_r_r8, cpy_r_r17);
    CPy_DECREF_NO_IMM(cpy_r_r17);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    cpy_r_r22 = CPyStatic__decoding___globals;
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NonEmptyPaddingBytes' */
    cpy_r_r24 = CPyDict_GetItem(cpy_r_r22, cpy_r_r23);
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    PyObject *cpy_r_r25[1] = {cpy_r_r21};
    cpy_r_r26 = (PyObject **)&cpy_r_r25;
    cpy_r_r27 = PyObject_Vectorcall(cpy_r_r24, cpy_r_r26, 1, 0);
    CPy_DECREF(cpy_r_r24);
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL16;
    }
    CPy_DECREF(cpy_r_r21);
    CPy_Raise(cpy_r_r27);
    CPy_DECREF(cpy_r_r27);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL14;
    }
    CPy_Unreachable();
CPyL14: ;
    cpy_r_r28 = 2;
    return cpy_r_r28;
CPyL15: ;
    CPy_DecRef(cpy_r_r16);
    goto CPyL14;
CPyL16: ;
    CPy_DecRef(cpy_r_r21);
    goto CPyL14;
}

PyObject *CPyPy__decoding___decoder_fn_boolean(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"data", 0};
    static CPyArg_Parser parser = {"O:decoder_fn_boolean", kwlist, 0};
    PyObject *obj_data;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_data)) {
        return NULL;
    }
    PyObject *arg_data;
    if (likely(PyBytes_Check(obj_data) || PyByteArray_Check(obj_data)))
        arg_data = obj_data;
    else {
        CPy_TypeError("bytes", obj_data); 
        goto fail;
    }
    char retval = CPyDef__decoding___decoder_fn_boolean(arg_data);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_decoding.py", "decoder_fn_boolean", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
    return NULL;
}

char CPyDef__decoding_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    char cpy_r_r21;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "<module>", -1, CPyStatic__decoding___globals);
        goto CPyL9;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TYPE_CHECKING', 'Any', 'Tuple') */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic__decoding___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL9;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('big_endian_to_int',) */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_utils' */
    cpy_r_r11 = CPyStatic__decoding___globals;
    cpy_r_r12 = CPyImport_ImportFromMany(cpy_r_r10, cpy_r_r9, cpy_r_r9, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL9;
    }
    CPyModule_faster_eth_utils = cpy_r_r12;
    CPy_INCREF(CPyModule_faster_eth_utils);
    CPy_DECREF(cpy_r_r12);
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('InsufficientDataBytes', 'InvalidPointer',
                                    'NonEmptyPaddingBytes') */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.exceptions' */
    cpy_r_r15 = CPyStatic__decoding___globals;
    cpy_r_r16 = CPyImport_ImportFromMany(cpy_r_r14, cpy_r_r13, cpy_r_r13, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL9;
    }
    CPyModule_faster_eth_abi___exceptions = cpy_r_r16;
    CPy_INCREF(CPyModule_faster_eth_abi___exceptions);
    CPy_DECREF(cpy_r_r16);
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('BytesIO', 'ContextFramesBytesIO') */
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.io' */
    cpy_r_r19 = CPyStatic__decoding___globals;
    cpy_r_r20 = CPyImport_ImportFromMany(cpy_r_r18, cpy_r_r17, cpy_r_r17, cpy_r_r19);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_decoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__decoding___globals);
        goto CPyL9;
    }
    CPyModule_faster_eth_abi___io = cpy_r_r20;
    CPy_INCREF(CPyModule_faster_eth_abi___io);
    CPy_DECREF(cpy_r_r20);
    return 1;
CPyL9: ;
    cpy_r_r21 = 2;
    return cpy_r_r21;
}
static PyMethodDef _encodingmodule_methods[] = {
    {"encode_tuple", (PyCFunction)CPyPy__encoding___encode_tuple, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_tuple(values, encoders)\n--\n\n") /* docstring */},
    {"encode_fixed", (PyCFunction)CPyPy__encoding___encode_fixed, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_fixed(value, encode_fn, is_big_endian, data_byte_size)\n--\n\n") /* docstring */},
    {"encode_signed", (PyCFunction)CPyPy__encoding___encode_signed, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_signed(value, encode_fn, data_byte_size)\n--\n\n") /* docstring */},
    {"encode_elements", (PyCFunction)CPyPy__encoding___encode_elements, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_elements(item_encoder, value)\n--\n\n") /* docstring */},
    {"encode_elements_dynamic", (PyCFunction)CPyPy__encoding___encode_elements_dynamic, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_elements_dynamic(item_encoder, value)\n--\n\n") /* docstring */},
    {"encode_uint_256", (PyCFunction)CPyPy__encoding___encode_uint_256, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("encode_uint_256(i)\n--\n\n") /* docstring */},
    {"int_to_big_endian", (PyCFunction)CPyPy__encoding___int_to_big_endian, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("int_to_big_endian(value)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi____encoding(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi____encoding__internal, "__name__");
    CPyStatic__encoding___globals = PyModule_GetDict(CPyModule_faster_eth_abi____encoding__internal);
    if (unlikely(CPyStatic__encoding___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef__encoding_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi____encoding__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef _encodingmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi._encoding",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    _encodingmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi____encoding(void)
{
    if (CPyModule_faster_eth_abi____encoding__internal) {
        Py_INCREF(CPyModule_faster_eth_abi____encoding__internal);
        return CPyModule_faster_eth_abi____encoding__internal;
    }
    CPyModule_faster_eth_abi____encoding__internal = PyModule_Create(&_encodingmodule);
    if (unlikely(CPyModule_faster_eth_abi____encoding__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi____encoding(CPyModule_faster_eth_abi____encoding__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi____encoding__internal;
    fail:
    return NULL;
}

PyObject *CPyDef__encoding___encode_tuple(PyObject *cpy_r_values, PyObject *cpy_r_encoders) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    int32_t cpy_r_r9;
    char cpy_r_r10;
    char cpy_r_r11;
    PyObject *cpy_r_r12;
    int32_t cpy_r_r13;
    char cpy_r_r14;
    PyObject **cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    int32_t cpy_r_r19;
    char cpy_r_r20;
    PyObject **cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    int32_t cpy_r_r25;
    char cpy_r_r26;
    PyObject *cpy_r_r27;
    int32_t cpy_r_r28;
    char cpy_r_r29;
    char cpy_r_r30;
    char cpy_r_r31;
    CPyTagged cpy_r_r32;
    int64_t cpy_r_r33;
    CPyPtr cpy_r_r34;
    int64_t cpy_r_r35;
    char cpy_r_r36;
    CPyPtr cpy_r_r37;
    CPyPtr cpy_r_r38;
    int64_t cpy_r_r39;
    CPyPtr cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    char cpy_r_r44;
    CPyTagged cpy_r_r45;
    PyObject *cpy_r_r46;
    CPyPtr cpy_r_r47;
    int64_t cpy_r_r48;
    CPyTagged cpy_r_r49;
    CPyTagged cpy_r_r50;
    int64_t cpy_r_r51;
    CPyTagged cpy_r_head_length;
    PyObject *cpy_r_r52;
    PyObject *cpy_r_r53;
    CPyPtr cpy_r_r54;
    CPyPtr cpy_r_r55;
    CPyTagged cpy_r_total_offset;
    PyObject *cpy_r_r56;
    PyObject *cpy_r_r57;
    int64_t cpy_r_r58;
    CPyPtr cpy_r_r59;
    int64_t cpy_r_r60;
    char cpy_r_r61;
    CPyPtr cpy_r_r62;
    CPyPtr cpy_r_r63;
    int64_t cpy_r_r64;
    CPyPtr cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject *cpy_r_r67;
    CPyPtr cpy_r_r68;
    int64_t cpy_r_r69;
    CPyTagged cpy_r_r70;
    CPyTagged cpy_r_r71;
    PyObject *cpy_r_r72;
    int32_t cpy_r_r73;
    char cpy_r_r74;
    int64_t cpy_r_r75;
    PyObject *cpy_r_r76;
    int64_t cpy_r_r77;
    int64_t cpy_r_r78;
    CPyPtr cpy_r_r79;
    int64_t cpy_r_r80;
    char cpy_r_r81;
    CPyPtr cpy_r_r82;
    int64_t cpy_r_r83;
    char cpy_r_r84;
    CPyPtr cpy_r_r85;
    CPyPtr cpy_r_r86;
    int64_t cpy_r_r87;
    CPyPtr cpy_r_r88;
    PyObject *cpy_r_r89;
    PyObject *cpy_r_r90;
    CPyPtr cpy_r_r91;
    CPyPtr cpy_r_r92;
    int64_t cpy_r_r93;
    CPyPtr cpy_r_r94;
    PyObject *cpy_r_r95;
    CPyTagged cpy_r_r96;
    PyObject *cpy_r_r97;
    char cpy_r_r98;
    CPyTagged cpy_r_r99;
    PyObject *cpy_r_r100;
    PyObject *cpy_r_r101;
    PyObject *cpy_r_r102;
    int32_t cpy_r_r103;
    char cpy_r_r104;
    int64_t cpy_r_r105;
    int64_t cpy_r_r106;
    PyObject *cpy_r_r107;
    PyObject *cpy_r_r108;
    PyObject *cpy_r_r109;
    PyObject *cpy_r_r110;
    PyObject *cpy_r_r111;
    PyObject *cpy_r_r112;
    PyObject *cpy_r_r113;
    cpy_r_r0 = PyList_New(0);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL54;
    }
    cpy_r_r1 = PyList_New(0);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL55;
    }
    cpy_r_r2 = PyObject_GetIter(cpy_r_values);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL56;
    }
    cpy_r_r3 = PyObject_GetIter(cpy_r_encoders);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL57;
    }
CPyL4: ;
    cpy_r_r4 = PyIter_Next(cpy_r_r2);
    if (cpy_r_r4 == NULL) goto CPyL58;
    cpy_r_r5 = PyIter_Next(cpy_r_r3);
    if (cpy_r_r5 == NULL) goto CPyL59;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_dynamic' */
    cpy_r_r7 = 0 ? Py_True : Py_False;
    cpy_r_r8 = CPyObject_GetAttr3(cpy_r_r5, cpy_r_r6, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL60;
    }
    cpy_r_r9 = PyObject_IsTrue(cpy_r_r8);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r10 = cpy_r_r9 >= 0;
    if (unlikely(!cpy_r_r10)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL60;
    }
    cpy_r_r11 = cpy_r_r9;
    if (!cpy_r_r11) goto CPyL13;
    cpy_r_r12 = Py_None;
    cpy_r_r13 = PyList_Append(cpy_r_r0, cpy_r_r12);
    cpy_r_r14 = cpy_r_r13 >= 0;
    if (unlikely(!cpy_r_r14)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL60;
    }
    PyObject *cpy_r_r15[1] = {cpy_r_r4};
    cpy_r_r16 = (PyObject **)&cpy_r_r15;
    cpy_r_r17 = PyObject_Vectorcall(cpy_r_r5, cpy_r_r16, 1, 0);
    CPy_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL61;
    }
    CPy_DECREF(cpy_r_r4);
    if (likely(PyBytes_Check(cpy_r_r17) || PyByteArray_Check(cpy_r_r17)))
        cpy_r_r18 = cpy_r_r17;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 29, CPyStatic__encoding___globals, "bytes", cpy_r_r17);
        goto CPyL62;
    }
    cpy_r_r19 = PyList_Append(cpy_r_r1, cpy_r_r18);
    CPy_DECREF(cpy_r_r18);
    cpy_r_r20 = cpy_r_r19 >= 0;
    if (unlikely(!cpy_r_r20)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL62;
    } else
        goto CPyL4;
CPyL13: ;
    PyObject *cpy_r_r21[1] = {cpy_r_r4};
    cpy_r_r22 = (PyObject **)&cpy_r_r21;
    cpy_r_r23 = PyObject_Vectorcall(cpy_r_r5, cpy_r_r22, 1, 0);
    CPy_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL61;
    }
    CPy_DECREF(cpy_r_r4);
    if (likely(PyBytes_Check(cpy_r_r23) || PyByteArray_Check(cpy_r_r23)))
        cpy_r_r24 = cpy_r_r23;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 31, CPyStatic__encoding___globals, "bytes", cpy_r_r23);
        goto CPyL62;
    }
    cpy_r_r25 = PyList_Append(cpy_r_r0, cpy_r_r24);
    CPy_DECREF(cpy_r_r24);
    cpy_r_r26 = cpy_r_r25 >= 0;
    if (unlikely(!cpy_r_r26)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL62;
    }
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    cpy_r_r28 = PyList_Append(cpy_r_r1, cpy_r_r27);
    cpy_r_r29 = cpy_r_r28 >= 0;
    if (unlikely(!cpy_r_r29)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL62;
    } else
        goto CPyL4;
CPyL17: ;
    cpy_r_r30 = CPy_NoErrOccurred();
    if (unlikely(!cpy_r_r30)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL56;
    }
    cpy_r_r31 = CPy_NoErrOccurred();
    if (unlikely(!cpy_r_r31)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL56;
    }
    cpy_r_r32 = 0;
    cpy_r_r33 = 0;
CPyL20: ;
    cpy_r_r34 = (CPyPtr)&((PyVarObject *)cpy_r_r0)->ob_size;
    cpy_r_r35 = *(int64_t *)cpy_r_r34;
    cpy_r_r36 = cpy_r_r33 < cpy_r_r35;
    if (!cpy_r_r36) goto CPyL28;
    cpy_r_r37 = (CPyPtr)&((PyListObject *)cpy_r_r0)->ob_item;
    cpy_r_r38 = *(CPyPtr *)cpy_r_r37;
    cpy_r_r39 = cpy_r_r33 * 8;
    cpy_r_r40 = cpy_r_r38 + cpy_r_r39;
    cpy_r_r41 = *(PyObject * *)cpy_r_r40;
    CPy_INCREF(cpy_r_r41);
    if (PyBytes_Check(cpy_r_r41) || PyByteArray_Check(cpy_r_r41))
        cpy_r_r42 = cpy_r_r41;
    else {
        cpy_r_r42 = NULL;
    }
    if (cpy_r_r42 != NULL) goto __LL6;
    if (cpy_r_r41 == Py_None)
        cpy_r_r42 = cpy_r_r41;
    else {
        cpy_r_r42 = NULL;
    }
    if (cpy_r_r42 != NULL) goto __LL6;
    CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 34, CPyStatic__encoding___globals, "bytes or None", cpy_r_r41);
    goto CPyL63;
__LL6: ;
    cpy_r_r43 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r44 = cpy_r_r42 == cpy_r_r43;
    if (cpy_r_r44) {
        goto CPyL64;
    } else
        goto CPyL24;
CPyL23: ;
    cpy_r_r45 = 64;
    goto CPyL26;
CPyL24: ;
    if (likely(cpy_r_r42 != Py_None))
        cpy_r_r46 = cpy_r_r42;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 34, CPyStatic__encoding___globals, "bytes", cpy_r_r42);
        goto CPyL63;
    }
    cpy_r_r47 = (CPyPtr)&((PyVarObject *)cpy_r_r46)->ob_size;
    cpy_r_r48 = *(int64_t *)cpy_r_r47;
    CPy_DECREF(cpy_r_r46);
    cpy_r_r49 = cpy_r_r48 << 1;
    cpy_r_r45 = cpy_r_r49;
CPyL26: ;
    cpy_r_r50 = CPyTagged_Add(cpy_r_r32, cpy_r_r45);
    CPyTagged_DECREF(cpy_r_r32);
    CPyTagged_DECREF(cpy_r_r45);
    cpy_r_r32 = cpy_r_r50;
    cpy_r_r51 = cpy_r_r33 + 1;
    cpy_r_r33 = cpy_r_r51;
    goto CPyL20;
CPyL28: ;
    cpy_r_head_length = cpy_r_r32;
    cpy_r_r52 = PyList_New(1);
    if (unlikely(cpy_r_r52 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL65;
    }
    cpy_r_r53 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    cpy_r_r54 = (CPyPtr)&((PyListObject *)cpy_r_r52)->ob_item;
    cpy_r_r55 = *(CPyPtr *)cpy_r_r54;
    *(PyObject * *)cpy_r_r55 = cpy_r_r53;
    cpy_r_total_offset = 0;
    cpy_r_r56 = CPyList_GetSlice(cpy_r_r1, 0, -2);
    if (unlikely(cpy_r_r56 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL66;
    }
    if (likely(PyList_Check(cpy_r_r56)))
        cpy_r_r57 = cpy_r_r56;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 37, CPyStatic__encoding___globals, "list", cpy_r_r56);
        goto CPyL66;
    }
    cpy_r_r58 = 0;
CPyL32: ;
    cpy_r_r59 = (CPyPtr)&((PyVarObject *)cpy_r_r57)->ob_size;
    cpy_r_r60 = *(int64_t *)cpy_r_r59;
    cpy_r_r61 = cpy_r_r58 < cpy_r_r60;
    if (!cpy_r_r61) goto CPyL67;
    cpy_r_r62 = (CPyPtr)&((PyListObject *)cpy_r_r57)->ob_item;
    cpy_r_r63 = *(CPyPtr *)cpy_r_r62;
    cpy_r_r64 = cpy_r_r58 * 8;
    cpy_r_r65 = cpy_r_r63 + cpy_r_r64;
    cpy_r_r66 = *(PyObject * *)cpy_r_r65;
    CPy_INCREF(cpy_r_r66);
    if (likely(PyBytes_Check(cpy_r_r66) || PyByteArray_Check(cpy_r_r66)))
        cpy_r_r67 = cpy_r_r66;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 37, CPyStatic__encoding___globals, "bytes", cpy_r_r66);
        goto CPyL68;
    }
    cpy_r_r68 = (CPyPtr)&((PyVarObject *)cpy_r_r67)->ob_size;
    cpy_r_r69 = *(int64_t *)cpy_r_r68;
    CPy_DECREF(cpy_r_r67);
    cpy_r_r70 = cpy_r_r69 << 1;
    cpy_r_r71 = CPyTagged_Add(cpy_r_total_offset, cpy_r_r70);
    CPyTagged_DECREF(cpy_r_total_offset);
    cpy_r_total_offset = cpy_r_r71;
    CPyTagged_INCREF(cpy_r_total_offset);
    cpy_r_r72 = CPyTagged_StealAsObject(cpy_r_total_offset);
    cpy_r_r73 = PyList_Append(cpy_r_r52, cpy_r_r72);
    CPy_DECREF(cpy_r_r72);
    cpy_r_r74 = cpy_r_r73 >= 0;
    if (unlikely(!cpy_r_r74)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL68;
    }
    cpy_r_r75 = cpy_r_r58 + 1;
    cpy_r_r58 = cpy_r_r75;
    goto CPyL32;
CPyL36: ;
    cpy_r_r76 = PyList_New(0);
    if (unlikely(cpy_r_r76 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL69;
    }
    cpy_r_r77 = 0;
    cpy_r_r78 = 0;
CPyL38: ;
    cpy_r_r79 = (CPyPtr)&((PyVarObject *)cpy_r_r0)->ob_size;
    cpy_r_r80 = *(int64_t *)cpy_r_r79;
    cpy_r_r81 = cpy_r_r77 < cpy_r_r80;
    if (!cpy_r_r81) goto CPyL70;
    cpy_r_r82 = (CPyPtr)&((PyVarObject *)cpy_r_r52)->ob_size;
    cpy_r_r83 = *(int64_t *)cpy_r_r82;
    cpy_r_r84 = cpy_r_r78 < cpy_r_r83;
    if (!cpy_r_r84) goto CPyL70;
    cpy_r_r85 = (CPyPtr)&((PyListObject *)cpy_r_r0)->ob_item;
    cpy_r_r86 = *(CPyPtr *)cpy_r_r85;
    cpy_r_r87 = cpy_r_r77 * 8;
    cpy_r_r88 = cpy_r_r86 + cpy_r_r87;
    cpy_r_r89 = *(PyObject * *)cpy_r_r88;
    CPy_INCREF(cpy_r_r89);
    if (PyBytes_Check(cpy_r_r89) || PyByteArray_Check(cpy_r_r89))
        cpy_r_r90 = cpy_r_r89;
    else {
        cpy_r_r90 = NULL;
    }
    if (cpy_r_r90 != NULL) goto __LL7;
    if (cpy_r_r89 == Py_None)
        cpy_r_r90 = cpy_r_r89;
    else {
        cpy_r_r90 = NULL;
    }
    if (cpy_r_r90 != NULL) goto __LL7;
    CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 41, CPyStatic__encoding___globals, "bytes or None", cpy_r_r89);
    goto CPyL71;
__LL7: ;
    cpy_r_r91 = (CPyPtr)&((PyListObject *)cpy_r_r52)->ob_item;
    cpy_r_r92 = *(CPyPtr *)cpy_r_r91;
    cpy_r_r93 = cpy_r_r78 * 8;
    cpy_r_r94 = cpy_r_r92 + cpy_r_r93;
    cpy_r_r95 = *(PyObject * *)cpy_r_r94;
    CPy_INCREF(cpy_r_r95);
    if (likely(PyLong_Check(cpy_r_r95)))
        cpy_r_r96 = CPyTagged_FromObject(cpy_r_r95);
    else {
        CPy_TypeError("int", cpy_r_r95); cpy_r_r96 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r95);
    if (unlikely(cpy_r_r96 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL72;
    }
    cpy_r_r97 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r98 = cpy_r_r90 == cpy_r_r97;
    if (cpy_r_r98) {
        goto CPyL73;
    } else
        goto CPyL74;
CPyL43: ;
    cpy_r_r99 = CPyTagged_Add(cpy_r_head_length, cpy_r_r96);
    CPyTagged_DECREF(cpy_r_r96);
    cpy_r_r100 = CPyDef__encoding___encode_uint_256(cpy_r_r99);
    CPyTagged_DECREF(cpy_r_r99);
    if (unlikely(cpy_r_r100 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL71;
    }
    cpy_r_r101 = cpy_r_r100;
    goto CPyL47;
CPyL45: ;
    if (likely(cpy_r_r90 != Py_None))
        cpy_r_r102 = cpy_r_r90;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_tuple", 42, CPyStatic__encoding___globals, "bytes", cpy_r_r90);
        goto CPyL71;
    }
    cpy_r_r101 = cpy_r_r102;
CPyL47: ;
    cpy_r_r103 = PyList_Append(cpy_r_r76, cpy_r_r101);
    CPy_DECREF(cpy_r_r101);
    cpy_r_r104 = cpy_r_r103 >= 0;
    if (unlikely(!cpy_r_r104)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL71;
    }
    cpy_r_r105 = cpy_r_r77 + 1;
    cpy_r_r77 = cpy_r_r105;
    cpy_r_r106 = cpy_r_r78 + 1;
    cpy_r_r78 = cpy_r_r106;
    goto CPyL38;
CPyL49: ;
    cpy_r_r107 = PyList_AsTuple(cpy_r_r76);
    CPy_DECREF_NO_IMM(cpy_r_r76);
    if (unlikely(cpy_r_r107 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL75;
    }
    cpy_r_r108 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    cpy_r_r109 = CPyBytes_Join(cpy_r_r108, cpy_r_r107);
    CPy_DECREF(cpy_r_r107);
    if (unlikely(cpy_r_r109 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL75;
    }
    cpy_r_r110 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    cpy_r_r111 = CPyBytes_Join(cpy_r_r110, cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r1);
    if (unlikely(cpy_r_r111 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL76;
    }
    cpy_r_r112 = CPyBytes_Concat(cpy_r_r109, cpy_r_r111);
    CPy_DECREF(cpy_r_r111);
    if (unlikely(cpy_r_r112 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL54;
    }
    return cpy_r_r112;
CPyL54: ;
    cpy_r_r113 = NULL;
    return cpy_r_r113;
CPyL55: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL54;
CPyL56: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    goto CPyL54;
CPyL57: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    goto CPyL54;
CPyL58: ;
    CPy_DECREF(cpy_r_r2);
    CPy_DECREF(cpy_r_r3);
    goto CPyL17;
CPyL59: ;
    CPy_DECREF(cpy_r_r2);
    CPy_DECREF(cpy_r_r3);
    CPy_DECREF(cpy_r_r4);
    goto CPyL17;
CPyL60: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r5);
    goto CPyL54;
CPyL61: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r4);
    goto CPyL54;
CPyL62: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r3);
    goto CPyL54;
CPyL63: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_r32);
    goto CPyL54;
CPyL64: ;
    CPy_DECREF(cpy_r_r42);
    goto CPyL23;
CPyL65: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_head_length);
    goto CPyL54;
CPyL66: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_head_length);
    CPy_DecRef(cpy_r_r52);
    CPyTagged_DecRef(cpy_r_total_offset);
    goto CPyL54;
CPyL67: ;
    CPyTagged_DECREF(cpy_r_total_offset);
    CPy_DECREF_NO_IMM(cpy_r_r57);
    goto CPyL36;
CPyL68: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_head_length);
    CPy_DecRef(cpy_r_r52);
    CPyTagged_DecRef(cpy_r_total_offset);
    CPy_DecRef(cpy_r_r57);
    goto CPyL54;
CPyL69: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_head_length);
    CPy_DecRef(cpy_r_r52);
    goto CPyL54;
CPyL70: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    CPyTagged_DECREF(cpy_r_head_length);
    CPy_DECREF_NO_IMM(cpy_r_r52);
    goto CPyL49;
CPyL71: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_head_length);
    CPy_DecRef(cpy_r_r52);
    CPy_DecRef(cpy_r_r76);
    goto CPyL54;
CPyL72: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPyTagged_DecRef(cpy_r_head_length);
    CPy_DecRef(cpy_r_r52);
    CPy_DecRef(cpy_r_r76);
    CPy_DecRef(cpy_r_r90);
    goto CPyL54;
CPyL73: ;
    CPy_DECREF(cpy_r_r90);
    goto CPyL43;
CPyL74: ;
    CPyTagged_DECREF(cpy_r_r96);
    goto CPyL45;
CPyL75: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL54;
CPyL76: ;
    CPy_DecRef(cpy_r_r109);
    goto CPyL54;
}

PyObject *CPyPy__encoding___encode_tuple(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"values", "encoders", 0};
    static CPyArg_Parser parser = {"OO:encode_tuple", kwlist, 0};
    PyObject *obj_values;
    PyObject *obj_encoders;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_values, &obj_encoders)) {
        return NULL;
    }
    PyObject *arg_values = obj_values;
    PyObject *arg_encoders = obj_encoders;
    PyObject *retval = CPyDef__encoding___encode_tuple(arg_values, arg_encoders);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_tuple", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

PyObject *CPyDef__encoding___encode_fixed(PyObject *cpy_r_value, PyObject *cpy_r_encode_fn, char cpy_r_is_big_endian, CPyTagged cpy_r_data_byte_size) {
    PyObject **cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject **cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject **cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r0[1] = {cpy_r_value};
    cpy_r_r1 = (PyObject **)&cpy_r_r0;
    cpy_r_r2 = PyObject_Vectorcall(cpy_r_encode_fn, cpy_r_r1, 1, 0);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_fixed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    if (likely(PyBytes_Check(cpy_r_r2) || PyByteArray_Check(cpy_r_r2)))
        cpy_r_r3 = cpy_r_r2;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_fixed", 55, CPyStatic__encoding___globals, "bytes", cpy_r_r2);
        goto CPyL9;
    }
    if (!cpy_r_is_big_endian) goto CPyL6;
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'rjust' */
    CPyTagged_INCREF(cpy_r_data_byte_size);
    cpy_r_r6 = CPyTagged_StealAsObject(cpy_r_data_byte_size);
    PyObject *cpy_r_r7[3] = {cpy_r_r3, cpy_r_r6, cpy_r_r4};
    cpy_r_r8 = (PyObject **)&cpy_r_r7;
    cpy_r_r9 = PyObject_VectorcallMethod(cpy_r_r5, cpy_r_r8, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_fixed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL10;
    }
    CPy_DECREF(cpy_r_r3);
    CPy_DECREF(cpy_r_r6);
    if (likely(PyBytes_Check(cpy_r_r9) || PyByteArray_Check(cpy_r_r9)))
        cpy_r_r10 = cpy_r_r9;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_fixed", 57, CPyStatic__encoding___globals, "bytes", cpy_r_r9);
        goto CPyL9;
    }
    return cpy_r_r10;
CPyL6: ;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ljust' */
    CPyTagged_INCREF(cpy_r_data_byte_size);
    cpy_r_r13 = CPyTagged_StealAsObject(cpy_r_data_byte_size);
    PyObject *cpy_r_r14[3] = {cpy_r_r3, cpy_r_r13, cpy_r_r11};
    cpy_r_r15 = (PyObject **)&cpy_r_r14;
    cpy_r_r16 = PyObject_VectorcallMethod(cpy_r_r12, cpy_r_r15, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_fixed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL11;
    }
    CPy_DECREF(cpy_r_r3);
    CPy_DECREF(cpy_r_r13);
    if (likely(PyBytes_Check(cpy_r_r16) || PyByteArray_Check(cpy_r_r16)))
        cpy_r_r17 = cpy_r_r16;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_fixed", 59, CPyStatic__encoding___globals, "bytes", cpy_r_r16);
        goto CPyL9;
    }
    return cpy_r_r17;
CPyL9: ;
    cpy_r_r18 = NULL;
    return cpy_r_r18;
CPyL10: ;
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r6);
    goto CPyL9;
CPyL11: ;
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r13);
    goto CPyL9;
}

PyObject *CPyPy__encoding___encode_fixed(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", "encode_fn", "is_big_endian", "data_byte_size", 0};
    static CPyArg_Parser parser = {"OOOO:encode_fixed", kwlist, 0};
    PyObject *obj_value;
    PyObject *obj_encode_fn;
    PyObject *obj_is_big_endian;
    PyObject *obj_data_byte_size;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_value, &obj_encode_fn, &obj_is_big_endian, &obj_data_byte_size)) {
        return NULL;
    }
    PyObject *arg_value = obj_value;
    PyObject *arg_encode_fn = obj_encode_fn;
    char arg_is_big_endian;
    if (unlikely(!PyBool_Check(obj_is_big_endian))) {
        CPy_TypeError("bool", obj_is_big_endian); goto fail;
    } else
        arg_is_big_endian = obj_is_big_endian == Py_True;
    CPyTagged arg_data_byte_size;
    if (likely(PyLong_Check(obj_data_byte_size)))
        arg_data_byte_size = CPyTagged_BorrowFromObject(obj_data_byte_size);
    else {
        CPy_TypeError("int", obj_data_byte_size); goto fail;
    }
    PyObject *retval = CPyDef__encoding___encode_fixed(arg_value, arg_encode_fn, arg_is_big_endian, arg_data_byte_size);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_fixed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

PyObject *CPyDef__encoding___encode_signed(PyObject *cpy_r_value, PyObject *cpy_r_encode_fn, CPyTagged cpy_r_data_byte_size) {
    PyObject **cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    char cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject **cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r0[1] = {cpy_r_value};
    cpy_r_r1 = (PyObject **)&cpy_r_r0;
    cpy_r_r2 = PyObject_Vectorcall(cpy_r_encode_fn, cpy_r_r1, 1, 0);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_signed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL11;
    }
    if (likely(PyBytes_Check(cpy_r_r2) || PyByteArray_Check(cpy_r_r2)))
        cpy_r_r3 = cpy_r_r2;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_signed", 67, CPyStatic__encoding___globals, "bytes", cpy_r_r2);
        goto CPyL11;
    }
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    cpy_r_r5 = PyObject_RichCompare(cpy_r_value, cpy_r_r4, 5);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_signed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL12;
    }
    if (unlikely(!PyBool_Check(cpy_r_r5))) {
        CPy_TypeError("bool", cpy_r_r5); cpy_r_r6 = 2;
    } else
        cpy_r_r6 = cpy_r_r5 == Py_True;
    CPy_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r6 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_signed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL12;
    }
    if (!cpy_r_r6) goto CPyL8;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'rjust' */
    CPyTagged_INCREF(cpy_r_data_byte_size);
    cpy_r_r9 = CPyTagged_StealAsObject(cpy_r_data_byte_size);
    PyObject *cpy_r_r10[3] = {cpy_r_r3, cpy_r_r9, cpy_r_r7};
    cpy_r_r11 = (PyObject **)&cpy_r_r10;
    cpy_r_r12 = PyObject_VectorcallMethod(cpy_r_r8, cpy_r_r11, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_signed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL13;
    }
    CPy_DECREF(cpy_r_r3);
    CPy_DECREF(cpy_r_r9);
    if (likely(PyBytes_Check(cpy_r_r12) || PyByteArray_Check(cpy_r_r12)))
        cpy_r_r13 = cpy_r_r12;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_signed", 69, CPyStatic__encoding___globals, "bytes", cpy_r_r12);
        goto CPyL11;
    }
    return cpy_r_r13;
CPyL8: ;
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\xff' */
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'rjust' */
    CPyTagged_INCREF(cpy_r_data_byte_size);
    cpy_r_r16 = CPyTagged_StealAsObject(cpy_r_data_byte_size);
    PyObject *cpy_r_r17[3] = {cpy_r_r3, cpy_r_r16, cpy_r_r14};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_VectorcallMethod(cpy_r_r15, cpy_r_r18, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_signed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL14;
    }
    CPy_DECREF(cpy_r_r3);
    CPy_DECREF(cpy_r_r16);
    if (likely(PyBytes_Check(cpy_r_r19) || PyByteArray_Check(cpy_r_r19)))
        cpy_r_r20 = cpy_r_r19;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_signed", 71, CPyStatic__encoding___globals, "bytes", cpy_r_r19);
        goto CPyL11;
    }
    return cpy_r_r20;
CPyL11: ;
    cpy_r_r21 = NULL;
    return cpy_r_r21;
CPyL12: ;
    CPy_DecRef(cpy_r_r3);
    goto CPyL11;
CPyL13: ;
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r9);
    goto CPyL11;
CPyL14: ;
    CPy_DecRef(cpy_r_r3);
    CPy_DecRef(cpy_r_r16);
    goto CPyL11;
}

PyObject *CPyPy__encoding___encode_signed(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", "encode_fn", "data_byte_size", 0};
    static CPyArg_Parser parser = {"OOO:encode_signed", kwlist, 0};
    PyObject *obj_value;
    PyObject *obj_encode_fn;
    PyObject *obj_data_byte_size;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_value, &obj_encode_fn, &obj_data_byte_size)) {
        return NULL;
    }
    PyObject *arg_value = obj_value;
    PyObject *arg_encode_fn = obj_encode_fn;
    CPyTagged arg_data_byte_size;
    if (likely(PyLong_Check(obj_data_byte_size)))
        arg_data_byte_size = CPyTagged_BorrowFromObject(obj_data_byte_size);
    else {
        CPy_TypeError("int", obj_data_byte_size); goto fail;
    }
    PyObject *retval = CPyDef__encoding___encode_signed(arg_value, arg_encode_fn, arg_data_byte_size);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_signed", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

PyObject *CPyDef__encoding___encode_elements(PyObject *cpy_r_item_encoder, PyObject *cpy_r_value) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    int32_t cpy_r_r7;
    char cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    char cpy_r_r14;
    CPyTagged cpy_r_r15;
    char cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    CPyTagged cpy_r_r19;
    CPyTagged cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    CPyPtr cpy_r_r23;
    CPyPtr cpy_r_r24;
    CPyTagged cpy_r_total_offset;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    CPyPtr cpy_r_r27;
    int64_t cpy_r_r28;
    int64_t cpy_r_r29;
    char cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    CPyPtr cpy_r_r33;
    int64_t cpy_r_r34;
    CPyTagged cpy_r_r35;
    CPyTagged cpy_r_r36;
    PyObject *cpy_r_r37;
    int32_t cpy_r_r38;
    char cpy_r_r39;
    int64_t cpy_r_r40;
    CPyPtr cpy_r_r41;
    int64_t cpy_r_r42;
    PyObject *cpy_r_r43;
    int64_t cpy_r_r44;
    CPyPtr cpy_r_r45;
    int64_t cpy_r_r46;
    char cpy_r_r47;
    CPyPtr cpy_r_r48;
    CPyPtr cpy_r_r49;
    int64_t cpy_r_r50;
    CPyPtr cpy_r_r51;
    PyObject *cpy_r_r52;
    CPyTagged cpy_r_r53;
    CPyTagged cpy_r_r54;
    PyObject *cpy_r_r55;
    int64_t cpy_r_r56;
    PyObject *cpy_r_r57;
    PyObject *cpy_r_r58;
    PyObject *cpy_r_r59;
    PyObject *cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    cpy_r_r0 = PyList_New(0);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL35;
    }
    cpy_r_r1 = PyObject_GetIter(cpy_r_value);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL36;
    }
CPyL2: ;
    cpy_r_r2 = PyIter_Next(cpy_r_r1);
    if (cpy_r_r2 == NULL) goto CPyL37;
    PyObject *cpy_r_r3[1] = {cpy_r_r2};
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = PyObject_Vectorcall(cpy_r_item_encoder, cpy_r_r4, 1, 0);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL38;
    }
    CPy_DECREF(cpy_r_r2);
    if (likely(PyBytes_Check(cpy_r_r5) || PyByteArray_Check(cpy_r_r5)))
        cpy_r_r6 = cpy_r_r5;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_elements", 75, CPyStatic__encoding___globals, "bytes", cpy_r_r5);
        goto CPyL39;
    }
    cpy_r_r7 = PyList_Append(cpy_r_r0, cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    cpy_r_r8 = cpy_r_r7 >= 0;
    if (unlikely(!cpy_r_r8)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL39;
    } else
        goto CPyL2;
CPyL6: ;
    cpy_r_r9 = CPy_NoErrOccurred();
    if (unlikely(!cpy_r_r9)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL36;
    }
    cpy_r_r10 = PyList_AsTuple(cpy_r_r0);
    CPy_DECREF_NO_IMM(cpy_r_r0);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL35;
    }
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_dynamic' */
    cpy_r_r12 = 0 ? Py_True : Py_False;
    cpy_r_r13 = CPyObject_GetAttr3(cpy_r_item_encoder, cpy_r_r11, cpy_r_r12);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL40;
    }
    if (unlikely(!PyBool_Check(cpy_r_r13))) {
        CPy_TypeError("bool", cpy_r_r13); cpy_r_r14 = 2;
    } else
        cpy_r_r14 = cpy_r_r13 == Py_True;
    CPy_DECREF(cpy_r_r13);
    if (unlikely(cpy_r_r14 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL40;
    }
    if (!cpy_r_r14) goto CPyL13;
    cpy_r_r15 = CPyObject_Size(cpy_r_value);
    if (unlikely(cpy_r_r15 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL40;
    }
    cpy_r_r16 = cpy_r_r15 == 0;
    CPyTagged_DECREF(cpy_r_r15);
    if (!cpy_r_r16) goto CPyL15;
CPyL13: ;
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    cpy_r_r18 = CPyBytes_Join(cpy_r_r17, cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL35;
    }
    return cpy_r_r18;
CPyL15: ;
    cpy_r_r19 = CPyObject_Size(cpy_r_value);
    if (unlikely(cpy_r_r19 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL40;
    }
    cpy_r_r20 = CPyTagged_Multiply(64, cpy_r_r19);
    CPyTagged_DECREF(cpy_r_r19);
    cpy_r_r21 = PyList_New(1);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL41;
    }
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    cpy_r_r23 = (CPyPtr)&((PyListObject *)cpy_r_r21)->ob_item;
    cpy_r_r24 = *(CPyPtr *)cpy_r_r23;
    *(PyObject * *)cpy_r_r24 = cpy_r_r22;
    cpy_r_total_offset = 0;
    cpy_r_r25 = CPySequenceTuple_GetSlice(cpy_r_r10, 0, -2);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL42;
    }
    if (likely(PyTuple_Check(cpy_r_r25)))
        cpy_r_r26 = cpy_r_r25;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_elements", 84, CPyStatic__encoding___globals, "tuple", cpy_r_r25);
        goto CPyL42;
    }
    cpy_r_r27 = (CPyPtr)&((PyVarObject *)cpy_r_r26)->ob_size;
    cpy_r_r28 = *(int64_t *)cpy_r_r27;
    cpy_r_r29 = 0;
CPyL20: ;
    cpy_r_r30 = cpy_r_r29 < cpy_r_r28;
    if (!cpy_r_r30) goto CPyL43;
    cpy_r_r31 = CPySequenceTuple_GetItemUnsafe(cpy_r_r26, cpy_r_r29);
    if (likely(PyBytes_Check(cpy_r_r31) || PyByteArray_Check(cpy_r_r31)))
        cpy_r_r32 = cpy_r_r31;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_elements", 84, CPyStatic__encoding___globals, "bytes", cpy_r_r31);
        goto CPyL44;
    }
    cpy_r_r33 = (CPyPtr)&((PyVarObject *)cpy_r_r32)->ob_size;
    cpy_r_r34 = *(int64_t *)cpy_r_r33;
    CPy_DECREF(cpy_r_r32);
    cpy_r_r35 = cpy_r_r34 << 1;
    cpy_r_r36 = CPyTagged_Add(cpy_r_total_offset, cpy_r_r35);
    CPyTagged_DECREF(cpy_r_total_offset);
    cpy_r_total_offset = cpy_r_r36;
    CPyTagged_INCREF(cpy_r_total_offset);
    cpy_r_r37 = CPyTagged_StealAsObject(cpy_r_total_offset);
    cpy_r_r38 = PyList_Append(cpy_r_r21, cpy_r_r37);
    CPy_DECREF(cpy_r_r37);
    cpy_r_r39 = cpy_r_r38 >= 0;
    if (unlikely(!cpy_r_r39)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL44;
    }
    cpy_r_r40 = cpy_r_r29 + 1;
    cpy_r_r29 = cpy_r_r40;
    goto CPyL20;
CPyL24: ;
    cpy_r_r41 = (CPyPtr)&((PyVarObject *)cpy_r_r21)->ob_size;
    cpy_r_r42 = *(int64_t *)cpy_r_r41;
    cpy_r_r43 = PyTuple_New(cpy_r_r42);
    if (unlikely(cpy_r_r43 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL45;
    }
    cpy_r_r44 = 0;
CPyL26: ;
    cpy_r_r45 = (CPyPtr)&((PyVarObject *)cpy_r_r21)->ob_size;
    cpy_r_r46 = *(int64_t *)cpy_r_r45;
    cpy_r_r47 = cpy_r_r44 < cpy_r_r46;
    if (!cpy_r_r47) goto CPyL46;
    cpy_r_r48 = (CPyPtr)&((PyListObject *)cpy_r_r21)->ob_item;
    cpy_r_r49 = *(CPyPtr *)cpy_r_r48;
    cpy_r_r50 = cpy_r_r44 * 8;
    cpy_r_r51 = cpy_r_r49 + cpy_r_r50;
    cpy_r_r52 = *(PyObject * *)cpy_r_r51;
    CPy_INCREF(cpy_r_r52);
    if (likely(PyLong_Check(cpy_r_r52)))
        cpy_r_r53 = CPyTagged_FromObject(cpy_r_r52);
    else {
        CPy_TypeError("int", cpy_r_r52); cpy_r_r53 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r52);
    if (unlikely(cpy_r_r53 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL47;
    }
    cpy_r_r54 = CPyTagged_Add(cpy_r_r20, cpy_r_r53);
    CPyTagged_DECREF(cpy_r_r53);
    cpy_r_r55 = CPyDef__encoding___encode_uint_256(cpy_r_r54);
    CPyTagged_DECREF(cpy_r_r54);
    if (unlikely(cpy_r_r55 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL47;
    }
    CPySequenceTuple_SetItemUnsafe(cpy_r_r43, cpy_r_r44, cpy_r_r55);
    cpy_r_r56 = cpy_r_r44 + 1;
    cpy_r_r44 = cpy_r_r56;
    goto CPyL26;
CPyL31: ;
    cpy_r_r57 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    cpy_r_r58 = CPyBytes_Join(cpy_r_r57, cpy_r_r43);
    CPy_DECREF(cpy_r_r43);
    if (unlikely(cpy_r_r58 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL40;
    }
    cpy_r_r59 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'' */
    cpy_r_r60 = CPyBytes_Join(cpy_r_r59, cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r60 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL48;
    }
    cpy_r_r61 = CPyBytes_Concat(cpy_r_r58, cpy_r_r60);
    CPy_DECREF(cpy_r_r60);
    if (unlikely(cpy_r_r61 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL35;
    }
    return cpy_r_r61;
CPyL35: ;
    cpy_r_r62 = NULL;
    return cpy_r_r62;
CPyL36: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL35;
CPyL37: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL6;
CPyL38: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    goto CPyL35;
CPyL39: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    goto CPyL35;
CPyL40: ;
    CPy_DecRef(cpy_r_r10);
    goto CPyL35;
CPyL41: ;
    CPy_DecRef(cpy_r_r10);
    CPyTagged_DecRef(cpy_r_r20);
    goto CPyL35;
CPyL42: ;
    CPy_DecRef(cpy_r_r10);
    CPyTagged_DecRef(cpy_r_r20);
    CPy_DecRef(cpy_r_r21);
    CPyTagged_DecRef(cpy_r_total_offset);
    goto CPyL35;
CPyL43: ;
    CPyTagged_DECREF(cpy_r_total_offset);
    CPy_DECREF(cpy_r_r26);
    goto CPyL24;
CPyL44: ;
    CPy_DecRef(cpy_r_r10);
    CPyTagged_DecRef(cpy_r_r20);
    CPy_DecRef(cpy_r_r21);
    CPyTagged_DecRef(cpy_r_total_offset);
    CPy_DecRef(cpy_r_r26);
    goto CPyL35;
CPyL45: ;
    CPy_DecRef(cpy_r_r10);
    CPyTagged_DecRef(cpy_r_r20);
    CPy_DecRef(cpy_r_r21);
    goto CPyL35;
CPyL46: ;
    CPyTagged_DECREF(cpy_r_r20);
    CPy_DECREF_NO_IMM(cpy_r_r21);
    goto CPyL31;
CPyL47: ;
    CPy_DecRef(cpy_r_r10);
    CPyTagged_DecRef(cpy_r_r20);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r43);
    goto CPyL35;
CPyL48: ;
    CPy_DecRef(cpy_r_r58);
    goto CPyL35;
}

PyObject *CPyPy__encoding___encode_elements(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"item_encoder", "value", 0};
    static CPyArg_Parser parser = {"OO:encode_elements", kwlist, 0};
    PyObject *obj_item_encoder;
    PyObject *obj_value;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_item_encoder, &obj_value)) {
        return NULL;
    }
    PyObject *arg_item_encoder = obj_item_encoder;
    PyObject *arg_value = obj_value;
    PyObject *retval = CPyDef__encoding___encode_elements(arg_item_encoder, arg_value);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

PyObject *CPyDef__encoding___encode_elements_dynamic(PyObject *cpy_r_item_encoder, PyObject *cpy_r_value) {
    CPyTagged cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    cpy_r_r0 = CPyObject_Size(cpy_r_value);
    if (unlikely(cpy_r_r0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL5;
    }
    cpy_r_r1 = CPyDef__encoding___encode_uint_256(cpy_r_r0);
    CPyTagged_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL5;
    }
    cpy_r_r2 = CPyDef__encoding___encode_elements(cpy_r_item_encoder, cpy_r_value);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL6;
    }
    cpy_r_r3 = CPyBytes_Concat(cpy_r_r1, cpy_r_r2);
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL5;
    }
    return cpy_r_r3;
CPyL5: ;
    cpy_r_r4 = NULL;
    return cpy_r_r4;
CPyL6: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL5;
}

PyObject *CPyPy__encoding___encode_elements_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"item_encoder", "value", 0};
    static CPyArg_Parser parser = {"OO:encode_elements_dynamic", kwlist, 0};
    PyObject *obj_item_encoder;
    PyObject *obj_value;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_item_encoder, &obj_value)) {
        return NULL;
    }
    PyObject *arg_item_encoder = obj_item_encoder;
    PyObject *arg_value = obj_value;
    PyObject *retval = CPyDef__encoding___encode_elements_dynamic(arg_item_encoder, arg_value);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_elements_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

PyObject *CPyDef__encoding___encode_uint_256(CPyTagged cpy_r_i) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    cpy_r_r0 = CPyDef__encoding___int_to_big_endian(cpy_r_i);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL4;
    }
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'rjust' */
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 32 */
    PyObject *cpy_r_r4[3] = {cpy_r_r0, cpy_r_r3, cpy_r_r1};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_VectorcallMethod(cpy_r_r2, cpy_r_r5, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL5;
    }
    CPy_DECREF(cpy_r_r0);
    if (likely(PyBytes_Check(cpy_r_r6) || PyByteArray_Check(cpy_r_r6)))
        cpy_r_r7 = cpy_r_r6;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "encode_uint_256", 105, CPyStatic__encoding___globals, "bytes", cpy_r_r6);
        goto CPyL4;
    }
    return cpy_r_r7;
CPyL4: ;
    cpy_r_r8 = NULL;
    return cpy_r_r8;
CPyL5: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL4;
}

PyObject *CPyPy__encoding___encode_uint_256(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"i", 0};
    static CPyArg_Parser parser = {"O:encode_uint_256", kwlist, 0};
    PyObject *obj_i;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_i)) {
        return NULL;
    }
    CPyTagged arg_i;
    if (likely(PyLong_Check(obj_i)))
        arg_i = CPyTagged_BorrowFromObject(obj_i);
    else {
        CPy_TypeError("int", obj_i); goto fail;
    }
    PyObject *retval = CPyDef__encoding___encode_uint_256(arg_i);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "encode_uint_256", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

PyObject *CPyDef__encoding___int_to_big_endian(CPyTagged cpy_r_value) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject **cpy_r_r3;
    PyObject *cpy_r_r4;
    CPyTagged cpy_r_r5;
    CPyTagged cpy_r_r6;
    CPyTagged cpy_r_r7;
    char cpy_r_r8;
    CPyTagged cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject **cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bit_length' */
    CPyTagged_INCREF(cpy_r_value);
    cpy_r_r1 = CPyTagged_StealAsObject(cpy_r_value);
    PyObject *cpy_r_r2[1] = {cpy_r_r1};
    cpy_r_r3 = (PyObject **)&cpy_r_r2;
    cpy_r_r4 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r3, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "int_to_big_endian", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL10;
    }
    CPy_DECREF(cpy_r_r1);
    if (likely(PyLong_Check(cpy_r_r4)))
        cpy_r_r5 = CPyTagged_FromObject(cpy_r_r4);
    else {
        CPy_TypeError("int", cpy_r_r4); cpy_r_r5 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r5 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "int_to_big_endian", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    cpy_r_r6 = CPyTagged_Add(cpy_r_r5, 14);
    CPyTagged_DECREF(cpy_r_r5);
    cpy_r_r7 = CPyTagged_Rshift(cpy_r_r6, 6);
    CPyTagged_DECREF(cpy_r_r6);
    if (unlikely(cpy_r_r7 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "int_to_big_endian", -1, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    cpy_r_r8 = cpy_r_r7 != 0;
    if (!cpy_r_r8) goto CPyL11;
    cpy_r_r9 = cpy_r_r7;
    goto CPyL6;
CPyL5: ;
    cpy_r_r9 = 2;
CPyL6: ;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'big' */
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'to_bytes' */
    CPyTagged_INCREF(cpy_r_value);
    cpy_r_r12 = CPyTagged_StealAsObject(cpy_r_value);
    cpy_r_r13 = CPyTagged_StealAsObject(cpy_r_r9);
    PyObject *cpy_r_r14[3] = {cpy_r_r12, cpy_r_r13, cpy_r_r10};
    cpy_r_r15 = (PyObject **)&cpy_r_r14;
    cpy_r_r16 = PyObject_VectorcallMethod(cpy_r_r11, cpy_r_r15, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "int_to_big_endian", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL12;
    }
    CPy_DECREF(cpy_r_r12);
    CPy_DECREF(cpy_r_r13);
    if (likely(PyBytes_Check(cpy_r_r16) || PyByteArray_Check(cpy_r_r16)))
        cpy_r_r17 = cpy_r_r16;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_encoding.py", "int_to_big_endian", 110, CPyStatic__encoding___globals, "bytes", cpy_r_r16);
        goto CPyL9;
    }
    return cpy_r_r17;
CPyL9: ;
    cpy_r_r18 = NULL;
    return cpy_r_r18;
CPyL10: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL9;
CPyL11: ;
    CPyTagged_DECREF(cpy_r_r7);
    goto CPyL5;
CPyL12: ;
    CPy_DecRef(cpy_r_r12);
    CPy_DecRef(cpy_r_r13);
    goto CPyL9;
}

PyObject *CPyPy__encoding___int_to_big_endian(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", 0};
    static CPyArg_Parser parser = {"O:int_to_big_endian", kwlist, 0};
    PyObject *obj_value;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_value)) {
        return NULL;
    }
    CPyTagged arg_value;
    if (likely(PyLong_Check(obj_value)))
        arg_value = CPyTagged_BorrowFromObject(obj_value);
    else {
        CPy_TypeError("int", obj_value); goto fail;
    }
    PyObject *retval = CPyDef__encoding___int_to_big_endian(arg_value);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_encoding.py", "int_to_big_endian", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
    return NULL;
}

char CPyDef__encoding_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject **cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    int32_t cpy_r_r18;
    char cpy_r_r19;
    char cpy_r_r20;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "<module>", -1, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TYPE_CHECKING', 'Any', 'Callable', 'List', 'Optional',
                                   'Sequence', 'TypeVar') */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic__encoding___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'T' */
    cpy_r_r10 = CPyStatic__encoding___globals;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TypeVar' */
    cpy_r_r12 = CPyDict_GetItem(cpy_r_r10, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    PyObject *cpy_r_r13[1] = {cpy_r_r9};
    cpy_r_r14 = (PyObject **)&cpy_r_r13;
    cpy_r_r15 = PyObject_Vectorcall(cpy_r_r12, cpy_r_r14, 1, 0);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    cpy_r_r16 = CPyStatic__encoding___globals;
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'T' */
    cpy_r_r18 = CPyDict_SetItem(cpy_r_r16, cpy_r_r17, cpy_r_r15);
    CPy_DECREF(cpy_r_r15);
    cpy_r_r19 = cpy_r_r18 >= 0;
    if (unlikely(!cpy_r_r19)) {
        CPy_AddTraceback("faster_eth_abi/_encoding.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__encoding___globals);
        goto CPyL9;
    }
    return 1;
CPyL9: ;
    cpy_r_r20 = 2;
    return cpy_r_r20;
}

static int
_grammar___ABIType_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    return CPyPy__grammar___ABIType_____init__(self, args, kwds) != NULL ? 0 : -1;
}
static PyObject *CPyDunder__RichCompare__grammar___ABIType(PyObject *obj_lhs, PyObject *obj_rhs, int op) {
    switch (op) {
        case Py_EQ: {
            PyObject *arg_lhs;
            if (likely(PyObject_TypeCheck(obj_lhs, CPyType__grammar___ABIType)))
                arg_lhs = obj_lhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_lhs); 
                return NULL;
            }
            PyObject *arg_rhs = obj_rhs;
            char retval = CPyDef__grammar___ABIType_____eq__(arg_lhs, arg_rhs);
            if (retval == 2) {
                return NULL;
            }
            PyObject *retbox = retval ? Py_True : Py_False;
            CPy_INCREF(retbox);
            return retbox;
        }
        case Py_NE: {
            PyObject *arg_lhs;
            if (likely(PyObject_TypeCheck(obj_lhs, CPyType__grammar___ABIType)))
                arg_lhs = obj_lhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_lhs); 
                return NULL;
            }
            PyObject *arg_rhs;
            if (likely(PyObject_TypeCheck(obj_rhs, CPyType__grammar___ABIType)))
                arg_rhs = obj_rhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_rhs); 
                return NULL;
            }
            char retval = CPyDef__grammar___ABIType_____ne__(arg_lhs, arg_rhs);
            if (retval == 2) {
                return NULL;
            }
            PyObject *retbox = retval ? Py_True : Py_False;
            CPy_INCREF(retbox);
            return retbox;
        }
    }
    Py_INCREF(Py_NotImplemented);
    return Py_NotImplemented;
}
PyObject *CPyDef__grammar_____mypyc__ABIType_setup(PyObject *cpy_r_type);
PyObject *CPyDef__grammar___ABIType(PyObject *cpy_r_arrlist, PyObject *cpy_r_node);

static PyObject *
_grammar___ABIType_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyObject *self = CPyDef__grammar_____mypyc__ABIType_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
_grammar___ABIType_traverse(faster_eth_abi____grammar___ABITypeObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->_arrlist);
    Py_VISIT(self->_node);
    return 0;
}

static int
_grammar___ABIType_clear(faster_eth_abi____grammar___ABITypeObject *self)
{
    Py_CLEAR(self->_arrlist);
    Py_CLEAR(self->_node);
    return 0;
}

static void
_grammar___ABIType_dealloc(faster_eth_abi____grammar___ABITypeObject *self)
{
    PyObject_GC_UnTrack(self);
    CPy_TRASHCAN_BEGIN(self, _grammar___ABIType_dealloc)
    _grammar___ABIType_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem _grammar___ABIType_vtable_shadow[11];
static bool
CPyDef__grammar___ABIType_trait_vtable_setup_shadow(void)
{
    CPyVTableItem _grammar___ABIType_vtable_shadow_scratch[] = {
        (CPyVTableItem)CPyDef__grammar___ABIType_____init___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____repr___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____eq___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___to_type_str__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___item_type__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___validate__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___invalidate__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_array__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_dynamic__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType____has_dynamic_arrlist__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____ne__,
    };
    memcpy(_grammar___ABIType_vtable_shadow, _grammar___ABIType_vtable_shadow_scratch, sizeof(_grammar___ABIType_vtable_shadow));
    return 1;
}

static CPyVTableItem _grammar___ABIType_vtable[11];
static bool
CPyDef__grammar___ABIType_trait_vtable_setup(void)
{
    CPyDef__grammar___ABIType_trait_vtable_setup_shadow();
    CPyVTableItem _grammar___ABIType_vtable_scratch[] = {
        (CPyVTableItem)CPyDef__grammar___ABIType_____init__,
        (CPyVTableItem)CPyDef__grammar___ABIType_____repr__,
        (CPyVTableItem)CPyDef__grammar___ABIType_____eq__,
        (CPyVTableItem)CPyDef__grammar___ABIType___to_type_str,
        (CPyVTableItem)CPyDef__grammar___ABIType___item_type,
        (CPyVTableItem)CPyDef__grammar___ABIType___validate,
        (CPyVTableItem)CPyDef__grammar___ABIType___invalidate,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_array,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_dynamic,
        (CPyVTableItem)CPyDef__grammar___ABIType____has_dynamic_arrlist,
        (CPyVTableItem)CPyDef__grammar___ABIType_____ne__,
    };
    memcpy(_grammar___ABIType_vtable, _grammar___ABIType_vtable_scratch, sizeof(_grammar___ABIType_vtable));
    return 1;
}

static PyObject *
_grammar___ABIType_get_arrlist(faster_eth_abi____grammar___ABITypeObject *self, void *closure);
static int
_grammar___ABIType_set_arrlist(faster_eth_abi____grammar___ABITypeObject *self, PyObject *value, void *closure);
static PyObject *
_grammar___ABIType_get_node(faster_eth_abi____grammar___ABITypeObject *self, void *closure);
static int
_grammar___ABIType_set_node(faster_eth_abi____grammar___ABITypeObject *self, PyObject *value, void *closure);
static PyObject *
_grammar___ABIType_get_item_type(faster_eth_abi____grammar___ABITypeObject *self, void *closure);
static PyObject *
_grammar___ABIType_get_is_array(faster_eth_abi____grammar___ABITypeObject *self, void *closure);
static PyObject *
_grammar___ABIType_get_is_dynamic(faster_eth_abi____grammar___ABITypeObject *self, void *closure);
static PyObject *
_grammar___ABIType_get__has_dynamic_arrlist(faster_eth_abi____grammar___ABITypeObject *self, void *closure);

static PyGetSetDef _grammar___ABIType_getseters[] = {
    {"arrlist",
     (getter)_grammar___ABIType_get_arrlist, (setter)_grammar___ABIType_set_arrlist,
     NULL, NULL},
    {"node",
     (getter)_grammar___ABIType_get_node, (setter)_grammar___ABIType_set_node,
     NULL, NULL},
    {"item_type",
     (getter)_grammar___ABIType_get_item_type,
    NULL, NULL, NULL},
    {"is_array",
     (getter)_grammar___ABIType_get_is_array,
    NULL, NULL, NULL},
    {"is_dynamic",
     (getter)_grammar___ABIType_get_is_dynamic,
    NULL, NULL, NULL},
    {"_has_dynamic_arrlist",
     (getter)_grammar___ABIType_get__has_dynamic_arrlist,
    NULL, NULL, NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef _grammar___ABIType_methods[] = {
    {"__init__",
     (PyCFunction)CPyPy__grammar___ABIType_____init__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__init__($self, arrlist=None, node=None)\n--\n\n")},
    {"__repr__",
     (PyCFunction)CPyPy__grammar___ABIType_____repr__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__repr__($self, /)\n--\n\n")},
    {"__eq__",
     (PyCFunction)CPyPy__grammar___ABIType_____eq__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__eq__($self, other, /)\n--\n\n")},
    {"to_type_str",
     (PyCFunction)CPyPy__grammar___ABIType___to_type_str,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("to_type_str($self)\n--\n\n")},
    {"validate",
     (PyCFunction)CPyPy__grammar___ABIType___validate,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate($self)\n--\n\n")},
    {"invalidate",
     (PyCFunction)CPyPy__grammar___ABIType___invalidate,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("invalidate($self, error_msg)\n--\n\n")},
    {"__ne__",
     (PyCFunction)CPyPy__grammar___ABIType_____ne__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__ne__($rhs)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType__grammar___ABIType_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "ABIType",
    .tp_new = _grammar___ABIType_new,
    .tp_dealloc = (destructor)_grammar___ABIType_dealloc,
    .tp_traverse = (traverseproc)_grammar___ABIType_traverse,
    .tp_clear = (inquiry)_grammar___ABIType_clear,
    .tp_getset = _grammar___ABIType_getseters,
    .tp_methods = _grammar___ABIType_methods,
    .tp_init = _grammar___ABIType_init,
    .tp_repr = CPyDef__grammar___ABIType_____repr__,
    .tp_richcompare = CPyDunder__RichCompare__grammar___ABIType,
    .tp_basicsize = sizeof(faster_eth_abi____grammar___ABITypeObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("ABIType(arrlist=None, node=None)\n--\n\n"),
};
static PyTypeObject *CPyType__grammar___ABIType_template = &CPyType__grammar___ABIType_template_;

PyObject *CPyDef__grammar_____mypyc__ABIType_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi____grammar___ABITypeObject *self;
    self = (faster_eth_abi____grammar___ABITypeObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    if (type != CPyType__grammar___ABIType) {
        self->vtable = _grammar___ABIType_vtable_shadow;
    } else {
        self->vtable = _grammar___ABIType_vtable;
    }
    return (PyObject *)self;
}

PyObject *CPyDef__grammar___ABIType(PyObject *cpy_r_arrlist, PyObject *cpy_r_node)
{
    PyObject *self = CPyDef__grammar_____mypyc__ABIType_setup((PyObject *)CPyType__grammar___ABIType);
    if (self == NULL)
        return NULL;
    char res = CPyDef__grammar___ABIType_____init__(self, cpy_r_arrlist, cpy_r_node);
    if (res == 2) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}

static PyObject *
_grammar___ABIType_get_arrlist(faster_eth_abi____grammar___ABITypeObject *self, void *closure)
{
    if (unlikely(self->_arrlist == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute 'arrlist' of 'ABIType' undefined");
        return NULL;
    }
    CPy_INCREF(self->_arrlist);
    PyObject *retval = self->_arrlist;
    return retval;
}

static int
_grammar___ABIType_set_arrlist(faster_eth_abi____grammar___ABITypeObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'ABIType' object attribute 'arrlist' cannot be deleted");
        return -1;
    }
    if (self->_arrlist != NULL) {
        CPy_DECREF(self->_arrlist);
    }
    PyObject *tmp;
    tmp = value;
    if (tmp != NULL) goto __LL8;
    if (value == Py_None)
        tmp = value;
    else {
        tmp = NULL;
    }
    if (tmp != NULL) goto __LL8;
    CPy_TypeError("object or None", value); 
    tmp = NULL;
__LL8: ;
    if (!tmp)
        return -1;
    CPy_INCREF(tmp);
    self->_arrlist = tmp;
    return 0;
}

static PyObject *
_grammar___ABIType_get_node(faster_eth_abi____grammar___ABITypeObject *self, void *closure)
{
    if (unlikely(self->_node == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute 'node' of 'ABIType' undefined");
        return NULL;
    }
    CPy_INCREF(self->_node);
    PyObject *retval = self->_node;
    return retval;
}

static int
_grammar___ABIType_set_node(faster_eth_abi____grammar___ABITypeObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'ABIType' object attribute 'node' cannot be deleted");
        return -1;
    }
    if (self->_node != NULL) {
        CPy_DECREF(self->_node);
    }
    PyObject *tmp;
    tmp = value;
    if (tmp != NULL) goto __LL9;
    if (value == Py_None)
        tmp = value;
    else {
        tmp = NULL;
    }
    if (tmp != NULL) goto __LL9;
    CPy_TypeError("object or None", value); 
    tmp = NULL;
__LL9: ;
    if (!tmp)
        return -1;
    CPy_INCREF(tmp);
    self->_node = tmp;
    return 0;
}

static PyObject *
_grammar___ABIType_get_item_type(faster_eth_abi____grammar___ABITypeObject *self, void *closure)
{
    return CPyDef__grammar___ABIType___item_type((PyObject *) self);
}

static PyObject *
_grammar___ABIType_get_is_array(faster_eth_abi____grammar___ABITypeObject *self, void *closure)
{
    char retval = CPyDef__grammar___ABIType___is_array((PyObject *) self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
}

static PyObject *
_grammar___ABIType_get_is_dynamic(faster_eth_abi____grammar___ABITypeObject *self, void *closure)
{
    char retval = CPyDef__grammar___ABIType___is_dynamic((PyObject *) self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
}

static PyObject *
_grammar___ABIType_get__has_dynamic_arrlist(faster_eth_abi____grammar___ABITypeObject *self, void *closure)
{
    char retval = CPyDef__grammar___ABIType____has_dynamic_arrlist((PyObject *) self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
}

static int
_grammar___TupleType_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    return CPyPy__grammar___TupleType_____init__(self, args, kwds) != NULL ? 0 : -1;
}
static PyObject *CPyDunder__RichCompare__grammar___TupleType(PyObject *obj_lhs, PyObject *obj_rhs, int op) {
    switch (op) {
        case Py_EQ: {
            PyObject *arg_lhs;
            if (likely(PyObject_TypeCheck(obj_lhs, CPyType__grammar___ABIType)))
                arg_lhs = obj_lhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_lhs); 
                return NULL;
            }
            PyObject *arg_rhs = obj_rhs;
            char retval = CPyDef__grammar___ABIType_____eq__(arg_lhs, arg_rhs);
            if (retval == 2) {
                return NULL;
            }
            PyObject *retbox = retval ? Py_True : Py_False;
            CPy_INCREF(retbox);
            return retbox;
        }
        case Py_NE: {
            PyObject *arg_lhs;
            if (likely(PyObject_TypeCheck(obj_lhs, CPyType__grammar___ABIType)))
                arg_lhs = obj_lhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_lhs); 
                return NULL;
            }
            PyObject *arg_rhs;
            if (likely(PyObject_TypeCheck(obj_rhs, CPyType__grammar___ABIType)))
                arg_rhs = obj_rhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_rhs); 
                return NULL;
            }
            char retval = CPyDef__grammar___ABIType_____ne__(arg_lhs, arg_rhs);
            if (retval == 2) {
                return NULL;
            }
            PyObject *retbox = retval ? Py_True : Py_False;
            CPy_INCREF(retbox);
            return retbox;
        }
    }
    Py_INCREF(Py_NotImplemented);
    return Py_NotImplemented;
}
PyObject *CPyDef__grammar_____mypyc__TupleType_setup(PyObject *cpy_r_type);
PyObject *CPyDef__grammar___TupleType(PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);

static PyObject *
_grammar___TupleType_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyObject *self = CPyDef__grammar_____mypyc__TupleType_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
_grammar___TupleType_traverse(faster_eth_abi____grammar___TupleTypeObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->_arrlist);
    Py_VISIT(self->_node);
    Py_VISIT(self->_components);
    return 0;
}

static int
_grammar___TupleType_clear(faster_eth_abi____grammar___TupleTypeObject *self)
{
    Py_CLEAR(self->_arrlist);
    Py_CLEAR(self->_node);
    Py_CLEAR(self->_components);
    return 0;
}

static void
_grammar___TupleType_dealloc(faster_eth_abi____grammar___TupleTypeObject *self)
{
    PyObject_GC_UnTrack(self);
    CPy_TRASHCAN_BEGIN(self, _grammar___TupleType_dealloc)
    _grammar___TupleType_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem _grammar___TupleType_vtable_shadow[16];
static bool
CPyDef__grammar___TupleType_trait_vtable_setup_shadow(void)
{
    CPyVTableItem _grammar___TupleType_vtable_shadow_scratch[] = {
        (CPyVTableItem)CPyDef__grammar___ABIType_____init___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____repr___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____eq___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___to_type_str__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___item_type__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___validate__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___invalidate__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_array__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_dynamic__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType____has_dynamic_arrlist__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____ne__,
        (CPyVTableItem)CPyDef__grammar___TupleType_____init___3__TupleType_glue,
        (CPyVTableItem)CPyDef__grammar___TupleType___to_type_str__TupleType_glue,
        (CPyVTableItem)CPyDef__grammar___TupleType___item_type__TupleType_glue,
        (CPyVTableItem)CPyDef__grammar___TupleType___validate__TupleType_glue,
        (CPyVTableItem)CPyDef__grammar___TupleType___is_dynamic__TupleType_glue,
    };
    memcpy(_grammar___TupleType_vtable_shadow, _grammar___TupleType_vtable_shadow_scratch, sizeof(_grammar___TupleType_vtable_shadow));
    return 1;
}

static CPyVTableItem _grammar___TupleType_vtable[16];
static bool
CPyDef__grammar___TupleType_trait_vtable_setup(void)
{
    CPyDef__grammar___TupleType_trait_vtable_setup_shadow();
    CPyVTableItem _grammar___TupleType_vtable_scratch[] = {
        (CPyVTableItem)CPyDef__grammar___TupleType_____init__,
        (CPyVTableItem)CPyDef__grammar___ABIType_____repr__,
        (CPyVTableItem)CPyDef__grammar___ABIType_____eq__,
        (CPyVTableItem)CPyDef__grammar___TupleType___to_type_str,
        (CPyVTableItem)CPyDef__grammar___TupleType___item_type__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___TupleType___validate,
        (CPyVTableItem)CPyDef__grammar___ABIType___invalidate,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_array,
        (CPyVTableItem)CPyDef__grammar___TupleType___is_dynamic,
        (CPyVTableItem)CPyDef__grammar___ABIType____has_dynamic_arrlist,
        (CPyVTableItem)CPyDef__grammar___ABIType_____ne__,
        (CPyVTableItem)CPyDef__grammar___TupleType_____init__,
        (CPyVTableItem)CPyDef__grammar___TupleType___to_type_str,
        (CPyVTableItem)CPyDef__grammar___TupleType___item_type,
        (CPyVTableItem)CPyDef__grammar___TupleType___validate,
        (CPyVTableItem)CPyDef__grammar___TupleType___is_dynamic,
    };
    memcpy(_grammar___TupleType_vtable, _grammar___TupleType_vtable_scratch, sizeof(_grammar___TupleType_vtable));
    return 1;
}

static PyObject *
_grammar___TupleType_get_components(faster_eth_abi____grammar___TupleTypeObject *self, void *closure);
static int
_grammar___TupleType_set_components(faster_eth_abi____grammar___TupleTypeObject *self, PyObject *value, void *closure);
static PyObject *
_grammar___TupleType_get_item_type(faster_eth_abi____grammar___TupleTypeObject *self, void *closure);
static PyObject *
_grammar___TupleType_get_is_dynamic(faster_eth_abi____grammar___TupleTypeObject *self, void *closure);

static PyGetSetDef _grammar___TupleType_getseters[] = {
    {"components",
     (getter)_grammar___TupleType_get_components, (setter)_grammar___TupleType_set_components,
     NULL, NULL},
    {"item_type",
     (getter)_grammar___TupleType_get_item_type,
    NULL, NULL, NULL},
    {"is_dynamic",
     (getter)_grammar___TupleType_get_is_dynamic,
    NULL, NULL, NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef _grammar___TupleType_methods[] = {
    {"__init__",
     (PyCFunction)CPyPy__grammar___TupleType_____init__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__init__($self, components, arrlist=None, *, node=None)\n--\n\n")},
    {"to_type_str",
     (PyCFunction)CPyPy__grammar___TupleType___to_type_str,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("to_type_str($self)\n--\n\n")},
    {"validate",
     (PyCFunction)CPyPy__grammar___TupleType___validate,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate($self)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType__grammar___TupleType_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "TupleType",
    .tp_new = _grammar___TupleType_new,
    .tp_dealloc = (destructor)_grammar___TupleType_dealloc,
    .tp_traverse = (traverseproc)_grammar___TupleType_traverse,
    .tp_clear = (inquiry)_grammar___TupleType_clear,
    .tp_getset = _grammar___TupleType_getseters,
    .tp_methods = _grammar___TupleType_methods,
    .tp_init = _grammar___TupleType_init,
    .tp_richcompare = CPyDunder__RichCompare__grammar___TupleType,
    .tp_basicsize = sizeof(faster_eth_abi____grammar___TupleTypeObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("TupleType(components, arrlist=None, *, node=None)\n--\n\n"),
};
static PyTypeObject *CPyType__grammar___TupleType_template = &CPyType__grammar___TupleType_template_;

PyObject *CPyDef__grammar_____mypyc__TupleType_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi____grammar___TupleTypeObject *self;
    self = (faster_eth_abi____grammar___TupleTypeObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    if (type != CPyType__grammar___TupleType) {
        self->vtable = _grammar___TupleType_vtable_shadow;
    } else {
        self->vtable = _grammar___TupleType_vtable;
    }
    return (PyObject *)self;
}

PyObject *CPyDef__grammar___TupleType(PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node)
{
    PyObject *self = CPyDef__grammar_____mypyc__TupleType_setup((PyObject *)CPyType__grammar___TupleType);
    if (self == NULL)
        return NULL;
    char res = CPyDef__grammar___TupleType_____init__(self, cpy_r_components, cpy_r_arrlist, cpy_r_node);
    if (res == 2) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}

static PyObject *
_grammar___TupleType_get_components(faster_eth_abi____grammar___TupleTypeObject *self, void *closure)
{
    if (unlikely(self->_components == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute 'components' of 'TupleType' undefined");
        return NULL;
    }
    CPy_INCREF(self->_components);
    PyObject *retval = self->_components;
    return retval;
}

static int
_grammar___TupleType_set_components(faster_eth_abi____grammar___TupleTypeObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'TupleType' object attribute 'components' cannot be deleted");
        return -1;
    }
    if (self->_components != NULL) {
        CPy_DECREF(self->_components);
    }
    PyObject * tmp;
    if (likely(PyTuple_Check(value)))
        tmp = value;
    else {
        CPy_TypeError("tuple", value); 
        tmp = NULL;
    }
    if (!tmp)
        return -1;
    CPy_INCREF(tmp);
    self->_components = tmp;
    return 0;
}

static PyObject *
_grammar___TupleType_get_item_type(faster_eth_abi____grammar___TupleTypeObject *self, void *closure)
{
    return CPyDef__grammar___TupleType___item_type((PyObject *) self);
}

static PyObject *
_grammar___TupleType_get_is_dynamic(faster_eth_abi____grammar___TupleTypeObject *self, void *closure)
{
    char retval = CPyDef__grammar___TupleType___is_dynamic((PyObject *) self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
}

static int
_grammar___BasicType_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    return CPyPy__grammar___BasicType_____init__(self, args, kwds) != NULL ? 0 : -1;
}
static PyObject *CPyDunder__RichCompare__grammar___BasicType(PyObject *obj_lhs, PyObject *obj_rhs, int op) {
    switch (op) {
        case Py_EQ: {
            PyObject *arg_lhs;
            if (likely(PyObject_TypeCheck(obj_lhs, CPyType__grammar___ABIType)))
                arg_lhs = obj_lhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_lhs); 
                return NULL;
            }
            PyObject *arg_rhs = obj_rhs;
            char retval = CPyDef__grammar___ABIType_____eq__(arg_lhs, arg_rhs);
            if (retval == 2) {
                return NULL;
            }
            PyObject *retbox = retval ? Py_True : Py_False;
            CPy_INCREF(retbox);
            return retbox;
        }
        case Py_NE: {
            PyObject *arg_lhs;
            if (likely(PyObject_TypeCheck(obj_lhs, CPyType__grammar___ABIType)))
                arg_lhs = obj_lhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_lhs); 
                return NULL;
            }
            PyObject *arg_rhs;
            if (likely(PyObject_TypeCheck(obj_rhs, CPyType__grammar___ABIType)))
                arg_rhs = obj_rhs;
            else {
                CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_rhs); 
                return NULL;
            }
            char retval = CPyDef__grammar___ABIType_____ne__(arg_lhs, arg_rhs);
            if (retval == 2) {
                return NULL;
            }
            PyObject *retbox = retval ? Py_True : Py_False;
            CPy_INCREF(retbox);
            return retbox;
        }
    }
    Py_INCREF(Py_NotImplemented);
    return Py_NotImplemented;
}
PyObject *CPyDef__grammar_____mypyc__BasicType_setup(PyObject *cpy_r_type);
PyObject *CPyDef__grammar___BasicType(PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);

static PyObject *
_grammar___BasicType_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyObject *self = CPyDef__grammar_____mypyc__BasicType_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
_grammar___BasicType_traverse(faster_eth_abi____grammar___BasicTypeObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->_arrlist);
    Py_VISIT(self->_node);
    Py_VISIT(self->_base);
    Py_VISIT(self->_sub);
    return 0;
}

static int
_grammar___BasicType_clear(faster_eth_abi____grammar___BasicTypeObject *self)
{
    Py_CLEAR(self->_arrlist);
    Py_CLEAR(self->_node);
    Py_CLEAR(self->_base);
    Py_CLEAR(self->_sub);
    return 0;
}

static void
_grammar___BasicType_dealloc(faster_eth_abi____grammar___BasicTypeObject *self)
{
    PyObject_GC_UnTrack(self);
    CPy_TRASHCAN_BEGIN(self, _grammar___BasicType_dealloc)
    _grammar___BasicType_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem _grammar___BasicType_vtable_shadow[16];
static bool
CPyDef__grammar___BasicType_trait_vtable_setup_shadow(void)
{
    CPyVTableItem _grammar___BasicType_vtable_shadow_scratch[] = {
        (CPyVTableItem)CPyDef__grammar___ABIType_____init___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____repr___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____eq___3__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___to_type_str__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___item_type__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___validate__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___invalidate__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_array__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_dynamic__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType____has_dynamic_arrlist__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___ABIType_____ne__,
        (CPyVTableItem)CPyDef__grammar___BasicType_____init___3__BasicType_glue,
        (CPyVTableItem)CPyDef__grammar___BasicType___to_type_str__BasicType_glue,
        (CPyVTableItem)CPyDef__grammar___BasicType___item_type__BasicType_glue,
        (CPyVTableItem)CPyDef__grammar___BasicType___is_dynamic__BasicType_glue,
        (CPyVTableItem)CPyDef__grammar___BasicType___validate__BasicType_glue,
    };
    memcpy(_grammar___BasicType_vtable_shadow, _grammar___BasicType_vtable_shadow_scratch, sizeof(_grammar___BasicType_vtable_shadow));
    return 1;
}

static CPyVTableItem _grammar___BasicType_vtable[16];
static bool
CPyDef__grammar___BasicType_trait_vtable_setup(void)
{
    CPyDef__grammar___BasicType_trait_vtable_setup_shadow();
    CPyVTableItem _grammar___BasicType_vtable_scratch[] = {
        (CPyVTableItem)CPyDef__grammar___BasicType_____init__,
        (CPyVTableItem)CPyDef__grammar___ABIType_____repr__,
        (CPyVTableItem)CPyDef__grammar___ABIType_____eq__,
        (CPyVTableItem)CPyDef__grammar___BasicType___to_type_str,
        (CPyVTableItem)CPyDef__grammar___BasicType___item_type__ABIType_glue,
        (CPyVTableItem)CPyDef__grammar___BasicType___validate,
        (CPyVTableItem)CPyDef__grammar___ABIType___invalidate,
        (CPyVTableItem)CPyDef__grammar___ABIType___is_array,
        (CPyVTableItem)CPyDef__grammar___BasicType___is_dynamic,
        (CPyVTableItem)CPyDef__grammar___ABIType____has_dynamic_arrlist,
        (CPyVTableItem)CPyDef__grammar___ABIType_____ne__,
        (CPyVTableItem)CPyDef__grammar___BasicType_____init__,
        (CPyVTableItem)CPyDef__grammar___BasicType___to_type_str,
        (CPyVTableItem)CPyDef__grammar___BasicType___item_type,
        (CPyVTableItem)CPyDef__grammar___BasicType___is_dynamic,
        (CPyVTableItem)CPyDef__grammar___BasicType___validate,
    };
    memcpy(_grammar___BasicType_vtable, _grammar___BasicType_vtable_scratch, sizeof(_grammar___BasicType_vtable));
    return 1;
}

static PyObject *
_grammar___BasicType_get_base(faster_eth_abi____grammar___BasicTypeObject *self, void *closure);
static int
_grammar___BasicType_set_base(faster_eth_abi____grammar___BasicTypeObject *self, PyObject *value, void *closure);
static PyObject *
_grammar___BasicType_get_sub(faster_eth_abi____grammar___BasicTypeObject *self, void *closure);
static int
_grammar___BasicType_set_sub(faster_eth_abi____grammar___BasicTypeObject *self, PyObject *value, void *closure);
static PyObject *
_grammar___BasicType_get_item_type(faster_eth_abi____grammar___BasicTypeObject *self, void *closure);
static PyObject *
_grammar___BasicType_get_is_dynamic(faster_eth_abi____grammar___BasicTypeObject *self, void *closure);

static PyGetSetDef _grammar___BasicType_getseters[] = {
    {"base",
     (getter)_grammar___BasicType_get_base, (setter)_grammar___BasicType_set_base,
     NULL, NULL},
    {"sub",
     (getter)_grammar___BasicType_get_sub, (setter)_grammar___BasicType_set_sub,
     NULL, NULL},
    {"item_type",
     (getter)_grammar___BasicType_get_item_type,
    NULL, NULL, NULL},
    {"is_dynamic",
     (getter)_grammar___BasicType_get_is_dynamic,
    NULL, NULL, NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef _grammar___BasicType_methods[] = {
    {"__init__",
     (PyCFunction)CPyPy__grammar___BasicType_____init__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__init__($self, base, sub=None, arrlist=None, *, node=None)\n--\n\n")},
    {"to_type_str",
     (PyCFunction)CPyPy__grammar___BasicType___to_type_str,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("to_type_str($self)\n--\n\n")},
    {"validate",
     (PyCFunction)CPyPy__grammar___BasicType___validate,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate($self)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType__grammar___BasicType_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "BasicType",
    .tp_new = _grammar___BasicType_new,
    .tp_dealloc = (destructor)_grammar___BasicType_dealloc,
    .tp_traverse = (traverseproc)_grammar___BasicType_traverse,
    .tp_clear = (inquiry)_grammar___BasicType_clear,
    .tp_getset = _grammar___BasicType_getseters,
    .tp_methods = _grammar___BasicType_methods,
    .tp_init = _grammar___BasicType_init,
    .tp_richcompare = CPyDunder__RichCompare__grammar___BasicType,
    .tp_basicsize = sizeof(faster_eth_abi____grammar___BasicTypeObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("BasicType(base, sub=None, arrlist=None, *, node=None)\n--\n\n"),
};
static PyTypeObject *CPyType__grammar___BasicType_template = &CPyType__grammar___BasicType_template_;

PyObject *CPyDef__grammar_____mypyc__BasicType_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi____grammar___BasicTypeObject *self;
    self = (faster_eth_abi____grammar___BasicTypeObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    if (type != CPyType__grammar___BasicType) {
        self->vtable = _grammar___BasicType_vtable_shadow;
    } else {
        self->vtable = _grammar___BasicType_vtable;
    }
    return (PyObject *)self;
}

PyObject *CPyDef__grammar___BasicType(PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node)
{
    PyObject *self = CPyDef__grammar_____mypyc__BasicType_setup((PyObject *)CPyType__grammar___BasicType);
    if (self == NULL)
        return NULL;
    char res = CPyDef__grammar___BasicType_____init__(self, cpy_r_base, cpy_r_sub, cpy_r_arrlist, cpy_r_node);
    if (res == 2) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}

static PyObject *
_grammar___BasicType_get_base(faster_eth_abi____grammar___BasicTypeObject *self, void *closure)
{
    if (unlikely(self->_base == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute 'base' of 'BasicType' undefined");
        return NULL;
    }
    CPy_INCREF(self->_base);
    PyObject *retval = self->_base;
    return retval;
}

static int
_grammar___BasicType_set_base(faster_eth_abi____grammar___BasicTypeObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'BasicType' object attribute 'base' cannot be deleted");
        return -1;
    }
    if (self->_base != NULL) {
        CPy_DECREF(self->_base);
    }
    PyObject *tmp;
    if (likely(PyUnicode_Check(value)))
        tmp = value;
    else {
        CPy_TypeError("str", value); 
        tmp = NULL;
    }
    if (!tmp)
        return -1;
    CPy_INCREF(tmp);
    self->_base = tmp;
    return 0;
}

static PyObject *
_grammar___BasicType_get_sub(faster_eth_abi____grammar___BasicTypeObject *self, void *closure)
{
    if (unlikely(self->_sub == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute 'sub' of 'BasicType' undefined");
        return NULL;
    }
    CPy_INCREF(self->_sub);
    PyObject *retval = self->_sub;
    return retval;
}

static int
_grammar___BasicType_set_sub(faster_eth_abi____grammar___BasicTypeObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'BasicType' object attribute 'sub' cannot be deleted");
        return -1;
    }
    if (self->_sub != NULL) {
        CPy_DECREF(self->_sub);
    }
    PyObject *tmp;
    if (PyLong_Check(value))
        tmp = value;
    else {
        tmp = NULL;
    }
    if (tmp != NULL) goto __LL10;
    if (PyTuple_Check(value))
        tmp = value;
    else {
        tmp = NULL;
    }
    if (tmp != NULL) goto __LL10;
    if (value == Py_None)
        tmp = value;
    else {
        tmp = NULL;
    }
    if (tmp != NULL) goto __LL10;
    CPy_TypeError("union[int, tuple, None]", value); 
    tmp = NULL;
__LL10: ;
    if (!tmp)
        return -1;
    CPy_INCREF(tmp);
    self->_sub = tmp;
    return 0;
}

static PyObject *
_grammar___BasicType_get_item_type(faster_eth_abi____grammar___BasicTypeObject *self, void *closure)
{
    return CPyDef__grammar___BasicType___item_type((PyObject *) self);
}

static PyObject *
_grammar___BasicType_get_is_dynamic(faster_eth_abi____grammar___BasicTypeObject *self, void *closure)
{
    char retval = CPyDef__grammar___BasicType___is_dynamic((PyObject *) self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
}
static PyMethodDef _grammarmodule_methods[] = {
    {"normalize", (PyCFunction)CPyPy__grammar___normalize, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("normalize(type_str)\n--\n\n") /* docstring */},
    {"__normalize", (PyCFunction)CPyPy__grammar_____normalize, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__normalize(match)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi____grammar(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi____grammar__internal, "__name__");
    CPyStatic__grammar___globals = PyModule_GetDict(CPyModule_faster_eth_abi____grammar__internal);
    if (unlikely(CPyStatic__grammar___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef__grammar_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi____grammar__internal);
    Py_CLEAR(modname);
    CPy_XDECREF(CPyStatic__grammar___TYPE_ALIASES);
    CPyStatic__grammar___TYPE_ALIASES = NULL;
    CPy_XDECREF(CPyStatic__grammar___TYPE_ALIAS_RE);
    CPyStatic__grammar___TYPE_ALIAS_RE = NULL;
    Py_CLEAR(CPyType__grammar___ABIType);
    Py_CLEAR(CPyType__grammar___TupleType);
    Py_CLEAR(CPyType__grammar___BasicType);
    return -1;
}
static struct PyModuleDef _grammarmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi._grammar",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    _grammarmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi____grammar(void)
{
    if (CPyModule_faster_eth_abi____grammar__internal) {
        Py_INCREF(CPyModule_faster_eth_abi____grammar__internal);
        return CPyModule_faster_eth_abi____grammar__internal;
    }
    CPyModule_faster_eth_abi____grammar__internal = PyModule_Create(&_grammarmodule);
    if (unlikely(CPyModule_faster_eth_abi____grammar__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi____grammar(CPyModule_faster_eth_abi____grammar__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi____grammar__internal;
    fail:
    return NULL;
}

char CPyDef__grammar___ABIType_____init__(PyObject *cpy_r_self, PyObject *cpy_r_arrlist, PyObject *cpy_r_node) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    char cpy_r_r4;
    if (cpy_r_arrlist != NULL) goto CPyL8;
    cpy_r_r0 = Py_None;
    cpy_r_arrlist = cpy_r_r0;
CPyL2: ;
    if (cpy_r_node != NULL) goto CPyL9;
    cpy_r_r1 = Py_None;
    cpy_r_node = cpy_r_r1;
CPyL4: ;
    if (((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_arrlist != NULL) {
        CPy_DECREF(((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_arrlist);
    }
    ((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_arrlist = cpy_r_arrlist;
    cpy_r_r2 = 1;
    if (unlikely(!cpy_r_r2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL10;
    }
    if (((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_node != NULL) {
        CPy_DECREF(((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_node);
    }
    ((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_node = cpy_r_node;
    cpy_r_r3 = 1;
    if (unlikely(!cpy_r_r3)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL7;
    }
    return 1;
CPyL7: ;
    cpy_r_r4 = 2;
    return cpy_r_r4;
CPyL8: ;
    CPy_INCREF(cpy_r_arrlist);
    goto CPyL2;
CPyL9: ;
    CPy_INCREF(cpy_r_node);
    goto CPyL4;
CPyL10: ;
    CPy_DecRef(cpy_r_node);
    goto CPyL7;
}

PyObject *CPyPy__grammar___ABIType_____init__(PyObject *self, PyObject *args, PyObject *kw) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"arrlist", "node", 0};
    PyObject *obj_arrlist = NULL;
    PyObject *obj_node = NULL;
    if (!CPyArg_ParseTupleAndKeywords(args, kw, "|OO", "__init__", kwlist, &obj_arrlist, &obj_node)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *arg_arrlist;
    if (obj_arrlist == NULL) {
        arg_arrlist = NULL;
        goto __LL11;
    }
    arg_arrlist = obj_arrlist;
    if (arg_arrlist != NULL) goto __LL11;
    if (obj_arrlist == Py_None)
        arg_arrlist = obj_arrlist;
    else {
        arg_arrlist = NULL;
    }
    if (arg_arrlist != NULL) goto __LL11;
    CPy_TypeError("object or None", obj_arrlist); 
    goto fail;
__LL11: ;
    PyObject *arg_node;
    if (obj_node == NULL) {
        arg_node = NULL;
        goto __LL12;
    }
    arg_node = obj_node;
    if (arg_node != NULL) goto __LL12;
    if (obj_node == Py_None)
        arg_node = obj_node;
    else {
        arg_node = NULL;
    }
    if (arg_node != NULL) goto __LL12;
    CPy_TypeError("object or None", obj_node); 
    goto fail;
__LL12: ;
    char retval = CPyDef__grammar___ABIType_____init__(arg_self, arg_arrlist, arg_node);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType_____init___3__ABIType_glue(PyObject *cpy_r_self, PyObject *cpy_r_arrlist, PyObject *cpy_r_node) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    char cpy_r_r4;
    int32_t cpy_r_r5;
    char cpy_r_r6;
    int32_t cpy_r_r7;
    char cpy_r_r8;
    PyObject *cpy_r_r9;
    int32_t cpy_r_r10;
    char cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    char cpy_r_r14;
    char cpy_r_r15;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__init__' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r_self, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL15;
    cpy_r_r2 = PyList_New(0);
    if (cpy_r_r2 == NULL) goto CPyL16;
    cpy_r_r3 = PyDict_New();
    if (cpy_r_r3 == NULL) goto CPyL17;
    cpy_r_r4 = 0;
    if (cpy_r_arrlist == NULL) goto CPyL5;
    cpy_r_r5 = PyList_Append(cpy_r_r2, cpy_r_arrlist);
    cpy_r_r6 = cpy_r_r5 >= 0;
    if (!cpy_r_r6) {
        goto CPyL18;
    } else
        goto CPyL6;
CPyL5: ;
    cpy_r_r4 = 1;
CPyL6: ;
    if (cpy_r_node == NULL) goto CPyL10;
    if (cpy_r_r4) goto CPyL9;
    cpy_r_r7 = PyList_Append(cpy_r_r2, cpy_r_node);
    cpy_r_r8 = cpy_r_r7 >= 0;
    if (!cpy_r_r8) {
        goto CPyL18;
    } else
        goto CPyL11;
CPyL9: ;
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'node' */
    cpy_r_r10 = CPyDict_SetItem(cpy_r_r3, cpy_r_r9, cpy_r_node);
    cpy_r_r11 = cpy_r_r10 >= 0;
    if (!cpy_r_r11) {
        goto CPyL18;
    } else
        goto CPyL11;
CPyL10: ;
    cpy_r_r4 = 1;
CPyL11: ;
    cpy_r_r12 = PyList_AsTuple(cpy_r_r2);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    if (cpy_r_r12 == NULL) goto CPyL19;
    cpy_r_r13 = PyObject_Call(cpy_r_r1, cpy_r_r12, cpy_r_r3);
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_r12);
    CPy_DECREF(cpy_r_r3);
    if (cpy_r_r13 == NULL) goto CPyL15;
    if (unlikely(cpy_r_r13 != Py_None)) {
        CPy_TypeError("None", cpy_r_r13); cpy_r_r14 = 2;
    } else
        cpy_r_r14 = 1;
    CPy_DECREF(cpy_r_r13);
    if (cpy_r_r14 == 2) goto CPyL15;
    return cpy_r_r14;
CPyL15: ;
    cpy_r_r15 = 2;
    return cpy_r_r15;
CPyL16: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL15;
CPyL17: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    goto CPyL15;
CPyL18: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    CPy_DECREF(cpy_r_r3);
    goto CPyL15;
CPyL19: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_r3);
    goto CPyL15;
}

PyObject *CPyPy__grammar___ABIType_____init___3__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"arrlist", "node", 0};
    static CPyArg_Parser parser = {"|OO:__init____ABIType_glue", kwlist, 0};
    PyObject *obj_arrlist = NULL;
    PyObject *obj_node = NULL;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_arrlist, &obj_node)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *arg_arrlist;
    if (obj_arrlist == NULL) {
        arg_arrlist = NULL;
        goto __LL13;
    }
    arg_arrlist = obj_arrlist;
    if (arg_arrlist != NULL) goto __LL13;
    if (obj_arrlist == Py_None)
        arg_arrlist = obj_arrlist;
    else {
        arg_arrlist = NULL;
    }
    if (arg_arrlist != NULL) goto __LL13;
    CPy_TypeError("object or None", obj_arrlist); 
    goto fail;
__LL13: ;
    PyObject *arg_node;
    if (obj_node == NULL) {
        arg_node = NULL;
        goto __LL14;
    }
    arg_node = obj_node;
    if (arg_node != NULL) goto __LL14;
    if (obj_node == Py_None)
        arg_node = obj_node;
    else {
        arg_node = NULL;
    }
    if (arg_node != NULL) goto __LL14;
    CPy_TypeError("object or None", obj_node); 
    goto fail;
__LL14: ;
    char retval = CPyDef__grammar___ABIType_____init___3__ABIType_glue(arg_self, arg_arrlist, arg_node);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init____ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType_____repr__(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject **cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject **cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    CPyPtr cpy_r_r24;
    CPyPtr cpy_r_r25;
    CPyPtr cpy_r_r26;
    CPyPtr cpy_r_r27;
    CPyPtr cpy_r_r28;
    CPyPtr cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '<' */
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{:{}}' */
    cpy_r_r3 = CPy_TYPE(cpy_r_self);
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__qualname__' */
    cpy_r_r5 = CPyObject_GetAttr(cpy_r_r3, cpy_r_r4);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL10;
    }
    if (likely(PyUnicode_Check(cpy_r_r5)))
        cpy_r_r6 = cpy_r_r5;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "__repr__", 76, CPyStatic__grammar___globals, "str", cpy_r_r5);
        goto CPyL10;
    }
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r9[3] = {cpy_r_r2, cpy_r_r6, cpy_r_r7};
    cpy_r_r10 = (PyObject **)&cpy_r_r9;
    cpy_r_r11 = PyObject_VectorcallMethod(cpy_r_r8, cpy_r_r10, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL11;
    }
    CPy_DECREF(cpy_r_r6);
    if (likely(PyUnicode_Check(cpy_r_r11)))
        cpy_r_r12 = cpy_r_r11;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "__repr__", 76, CPyStatic__grammar___globals, "str", cpy_r_r11);
        goto CPyL10;
    }
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' ' */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{!r:{}}' */
    cpy_r_r15 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___ABIType, 3, faster_eth_abi____grammar___ABITypeObject, PyObject * (*)(PyObject *))(cpy_r_self); /* to_type_str */
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL12;
    }
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r18[3] = {cpy_r_r14, cpy_r_r15, cpy_r_r16};
    cpy_r_r19 = (PyObject **)&cpy_r_r18;
    cpy_r_r20 = PyObject_VectorcallMethod(cpy_r_r17, cpy_r_r19, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL13;
    }
    CPy_DECREF(cpy_r_r15);
    if (likely(PyUnicode_Check(cpy_r_r20)))
        cpy_r_r21 = cpy_r_r20;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "__repr__", 76, CPyStatic__grammar___globals, "str", cpy_r_r20);
        goto CPyL12;
    }
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '>' */
    cpy_r_r23 = PyList_New(5);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL14;
    }
    cpy_r_r24 = (CPyPtr)&((PyListObject *)cpy_r_r23)->ob_item;
    cpy_r_r25 = *(CPyPtr *)cpy_r_r24;
    CPy_INCREF(cpy_r_r1);
    *(PyObject * *)cpy_r_r25 = cpy_r_r1;
    cpy_r_r26 = cpy_r_r25 + 8;
    *(PyObject * *)cpy_r_r26 = cpy_r_r12;
    CPy_INCREF(cpy_r_r13);
    cpy_r_r27 = cpy_r_r25 + 16;
    *(PyObject * *)cpy_r_r27 = cpy_r_r13;
    cpy_r_r28 = cpy_r_r25 + 24;
    *(PyObject * *)cpy_r_r28 = cpy_r_r21;
    CPy_INCREF(cpy_r_r22);
    cpy_r_r29 = cpy_r_r25 + 32;
    *(PyObject * *)cpy_r_r29 = cpy_r_r22;
    cpy_r_r30 = PyUnicode_Join(cpy_r_r0, cpy_r_r23);
    CPy_DECREF_NO_IMM(cpy_r_r23);
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL10;
    }
    return cpy_r_r30;
CPyL10: ;
    cpy_r_r31 = NULL;
    return cpy_r_r31;
CPyL11: ;
    CPy_DecRef(cpy_r_r6);
    goto CPyL10;
CPyL12: ;
    CPy_DecRef(cpy_r_r12);
    goto CPyL10;
CPyL13: ;
    CPy_DecRef(cpy_r_r12);
    CPy_DecRef(cpy_r_r15);
    goto CPyL10;
CPyL14: ;
    CPy_DecRef(cpy_r_r12);
    CPy_DecRef(cpy_r_r21);
    goto CPyL10;
}

PyObject *CPyPy__grammar___ABIType_____repr__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":__repr__", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType_____repr__(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType_____repr___3__ABIType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__repr__' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (likely(PyUnicode_Check(cpy_r_r3)))
        cpy_r_r4 = cpy_r_r3;
    else {
        CPy_TypeError("str", cpy_r_r3); 
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = NULL;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___ABIType_____repr___3__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":__repr____ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType_____repr___3__ABIType_glue(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__repr____ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType_____eq__(PyObject *cpy_r_self, PyObject *cpy_r_other) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject **cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    char cpy_r_r11;
    char cpy_r_r12;
    cpy_r_r0 = CPy_TYPE(cpy_r_self);
    cpy_r_r1 = CPy_TYPE(cpy_r_other);
    cpy_r_r2 = cpy_r_r0 == cpy_r_r1;
    CPy_DECREF(cpy_r_r0);
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2) goto CPyL2;
    cpy_r_r3 = cpy_r_r2 ? Py_True : Py_False;
    cpy_r_r4 = cpy_r_r3;
    goto CPyL6;
CPyL2: ;
    cpy_r_r5 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___ABIType, 3, faster_eth_abi____grammar___ABITypeObject, PyObject * (*)(PyObject *))(cpy_r_self); /* to_type_str */
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__eq__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'to_type_str' */
    PyObject *cpy_r_r7[1] = {cpy_r_other};
    cpy_r_r8 = (PyObject **)&cpy_r_r7;
    cpy_r_r9 = PyObject_VectorcallMethod(cpy_r_r6, cpy_r_r8, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__eq__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL9;
    }
    cpy_r_r10 = PyObject_RichCompare(cpy_r_r5, cpy_r_r9, 2);
    CPy_DECREF(cpy_r_r5);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__eq__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    cpy_r_r4 = cpy_r_r10;
CPyL6: ;
    if (unlikely(!PyBool_Check(cpy_r_r4))) {
        CPy_TypeError("bool", cpy_r_r4); cpy_r_r11 = 2;
    } else
        cpy_r_r11 = cpy_r_r4 == Py_True;
    CPy_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r11 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__eq__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    return cpy_r_r11;
CPyL8: ;
    cpy_r_r12 = 2;
    return cpy_r_r12;
CPyL9: ;
    CPy_DecRef(cpy_r_r5);
    goto CPyL8;
}

PyObject *CPyPy__grammar___ABIType_____eq__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"other", 0};
    static CPyArg_Parser parser = {"O:__eq__", kwlist, 0};
    PyObject *obj_other;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_other)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *arg_other = obj_other;
    char retval = CPyDef__grammar___ABIType_____eq__(arg_self, arg_other);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__eq__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType_____eq___3__ABIType_glue(PyObject *cpy_r_self, PyObject *cpy_r_other) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    char cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__eq__' */
    PyObject *cpy_r_r1[2] = {cpy_r_self, cpy_r_other};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775810ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (unlikely(!PyBool_Check(cpy_r_r3))) {
        CPy_TypeError("bool", cpy_r_r3); cpy_r_r4 = 2;
    } else
        cpy_r_r4 = cpy_r_r3 == Py_True;
    CPy_DECREF(cpy_r_r3);
    if (cpy_r_r4 == 2) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___ABIType_____eq___3__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"other", 0};
    static CPyArg_Parser parser = {"O:__eq____ABIType_glue", kwlist, 0};
    PyObject *obj_other;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_other)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *arg_other = obj_other;
    char retval = CPyDef__grammar___ABIType_____eq___3__ABIType_glue(arg_self, arg_other);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__eq____ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType___to_type_str(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Must implement `to_type_str`' */
    cpy_r_r1 = CPyModule_builtins;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NotImplementedError' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    PyObject *cpy_r_r4[1] = {cpy_r_r0};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_Vectorcall(cpy_r_r3, cpy_r_r5, 1, 0);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Raise(cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Unreachable();
CPyL4: ;
    cpy_r_r7 = NULL;
    return cpy_r_r7;
}

PyObject *CPyPy__grammar___ABIType___to_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":to_type_str", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType___to_type_str(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType___to_type_str__ABIType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'to_type_str' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (likely(PyUnicode_Check(cpy_r_r3)))
        cpy_r_r4 = cpy_r_r3;
    else {
        CPy_TypeError("str", cpy_r_r3); 
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = NULL;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___ABIType___to_type_str__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":to_type_str__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType___to_type_str__ABIType_glue(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType___item_type(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Must implement `item_type`' */
    cpy_r_r1 = CPyModule_builtins;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NotImplementedError' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    PyObject *cpy_r_r4[1] = {cpy_r_r0};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_Vectorcall(cpy_r_r3, cpy_r_r5, 1, 0);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Raise(cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Unreachable();
CPyL4: ;
    cpy_r_r7 = NULL;
    return cpy_r_r7;
}

PyObject *CPyPy__grammar___ABIType___item_type(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType___item_type(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType___item_type__ABIType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'item_type' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (likely(PyObject_TypeCheck(cpy_r_r1, CPyType__grammar___ABIType)))
        cpy_r_r2 = cpy_r_r1;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", cpy_r_r1); 
        cpy_r_r2 = NULL;
    }
    if (cpy_r_r2 == NULL) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___ABIType___item_type__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___ABIType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj___mypyc_self__); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType___item_type__ABIType_glue(arg___mypyc_self__);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType___validate(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Must implement `validate`' */
    cpy_r_r1 = CPyModule_builtins;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NotImplementedError' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    PyObject *cpy_r_r4[1] = {cpy_r_r0};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_Vectorcall(cpy_r_r3, cpy_r_r5, 1, 0);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Raise(cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Unreachable();
CPyL4: ;
    cpy_r_r7 = 2;
    return cpy_r_r7;
}

PyObject *CPyPy__grammar___ABIType___validate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":validate", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType___validate(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType___validate__ABIType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    char cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'validate' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (unlikely(cpy_r_r3 != Py_None)) {
        CPy_TypeError("None", cpy_r_r3); cpy_r_r4 = 2;
    } else
        cpy_r_r4 = 1;
    CPy_DECREF(cpy_r_r3);
    if (cpy_r_r4 == 2) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___ABIType___validate__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":validate__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType___validate__ABIType_glue(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType___invalidate(PyObject *cpy_r_self, PyObject *cpy_r_error_msg) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject **cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    cpy_r_r0 = ((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_node;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "invalidate", "ABIType", "node", 112, CPyStatic__grammar___globals);
        goto CPyL16;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "For '" */
    CPy_INCREF(cpy_r_r0);
    cpy_r_r2 = cpy_r_r0;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'text' */
    cpy_r_r4 = CPyObject_GetAttr(cpy_r_r2, cpy_r_r3);
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL17;
    }
    cpy_r_r5 = PyObject_Str(cpy_r_r4);
    CPy_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL17;
    }
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "' type at column " */
    CPy_INCREF(cpy_r_r0);
    cpy_r_r7 = cpy_r_r0;
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'start' */
    cpy_r_r9 = CPyObject_GetAttr(cpy_r_r7, cpy_r_r8);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL18;
    }
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r11 = PyNumber_Add(cpy_r_r9, cpy_r_r10);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL18;
    }
    cpy_r_r12 = PyObject_Str(cpy_r_r11);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL18;
    }
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* " in '" */
    cpy_r_r14 = cpy_r_r0;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'full_text' */
    cpy_r_r16 = CPyObject_GetAttr(cpy_r_r14, cpy_r_r15);
    CPy_DECREF(cpy_r_r14);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL19;
    }
    cpy_r_r17 = PyObject_Str(cpy_r_r16);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL19;
    }
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "': " */
    cpy_r_r19 = CPyStr_Build(8, cpy_r_r1, cpy_r_r5, cpy_r_r6, cpy_r_r12, cpy_r_r13, cpy_r_r17, cpy_r_r18, cpy_r_error_msg);
    CPy_DECREF(cpy_r_r5);
    CPy_DECREF(cpy_r_r12);
    CPy_DECREF(cpy_r_r17);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL16;
    }
    cpy_r_r20 = CPyStatic__grammar___globals;
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ABITypeError' */
    cpy_r_r22 = CPyDict_GetItem(cpy_r_r20, cpy_r_r21);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL20;
    }
    PyObject *cpy_r_r23[1] = {cpy_r_r19};
    cpy_r_r24 = (PyObject **)&cpy_r_r23;
    cpy_r_r25 = PyObject_Vectorcall(cpy_r_r22, cpy_r_r24, 1, 0);
    CPy_DECREF(cpy_r_r22);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL20;
    }
    CPy_DECREF(cpy_r_r19);
    CPy_Raise(cpy_r_r25);
    CPy_DECREF(cpy_r_r25);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL16;
    }
    CPy_Unreachable();
CPyL16: ;
    cpy_r_r26 = NULL;
    return cpy_r_r26;
CPyL17: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL16;
CPyL18: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r5);
    goto CPyL16;
CPyL19: ;
    CPy_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r12);
    goto CPyL16;
CPyL20: ;
    CPy_DecRef(cpy_r_r19);
    goto CPyL16;
}

PyObject *CPyPy__grammar___ABIType___invalidate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"error_msg", 0};
    static CPyArg_Parser parser = {"O:invalidate", kwlist, 0};
    PyObject *obj_error_msg;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_error_msg)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *arg_error_msg;
    if (likely(PyUnicode_Check(obj_error_msg)))
        arg_error_msg = obj_error_msg;
    else {
        CPy_TypeError("str", obj_error_msg); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType___invalidate(arg_self, arg_error_msg);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___ABIType___invalidate__ABIType_glue(PyObject *cpy_r_self, PyObject *cpy_r_error_msg) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'invalidate' */
    PyObject *cpy_r_r1[2] = {cpy_r_self, cpy_r_error_msg};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775810ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL2;
    return cpy_r_r3;
CPyL2: ;
    cpy_r_r4 = NULL;
    return cpy_r_r4;
}

PyObject *CPyPy__grammar___ABIType___invalidate__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"error_msg", 0};
    static CPyArg_Parser parser = {"O:invalidate__ABIType_glue", kwlist, 0};
    PyObject *obj_error_msg;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_error_msg)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    PyObject *arg_error_msg;
    if (likely(PyUnicode_Check(obj_error_msg)))
        arg_error_msg = obj_error_msg;
    else {
        CPy_TypeError("str", obj_error_msg); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___ABIType___invalidate__ABIType_glue(arg_self, arg_error_msg);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "invalidate__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType___is_array(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    cpy_r_r0 = ((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_arrlist;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "is_array", "ABIType", "arrlist", 126, CPyStatic__grammar___globals);
        goto CPyL2;
    }
CPyL1: ;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    return cpy_r_r2;
CPyL2: ;
    cpy_r_r3 = 2;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___ABIType___is_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_array", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType___is_array(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_array", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType___is_array__ABIType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_array' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (unlikely(!PyBool_Check(cpy_r_r1))) {
        CPy_TypeError("bool", cpy_r_r1); cpy_r_r2 = 2;
    } else
        cpy_r_r2 = cpy_r_r1 == Py_True;
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2 == 2) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = 2;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___ABIType___is_array__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_array__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___ABIType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj___mypyc_self__); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType___is_array__ABIType_glue(arg___mypyc_self__);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_array__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType___is_dynamic(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Must implement `is_dynamic`' */
    cpy_r_r1 = CPyModule_builtins;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NotImplementedError' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    PyObject *cpy_r_r4[1] = {cpy_r_r0};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_Vectorcall(cpy_r_r3, cpy_r_r5, 1, 0);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Raise(cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL4;
    }
    CPy_Unreachable();
CPyL4: ;
    cpy_r_r7 = 2;
    return cpy_r_r7;
}

PyObject *CPyPy__grammar___ABIType___is_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_dynamic", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType___is_dynamic(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType___is_dynamic__ABIType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_dynamic' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (unlikely(!PyBool_Check(cpy_r_r1))) {
        CPy_TypeError("bool", cpy_r_r1); cpy_r_r2 = 2;
    } else
        cpy_r_r2 = cpy_r_r1 == Py_True;
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2 == 2) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = 2;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___ABIType___is_dynamic__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_dynamic__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___ABIType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj___mypyc_self__); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType___is_dynamic__ABIType_glue(arg___mypyc_self__);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType____has_dynamic_arrlist(PyObject *cpy_r_self) {
    char cpy_r_r0;
    char cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_dim;
    CPyTagged cpy_r_r6;
    char cpy_r_r7;
    char cpy_r_r8;
    char cpy_r_r9;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r_self, CPyType__grammar___ABIType, 7, faster_eth_abi____grammar___ABITypeObject, char); /* is_array */
    if (unlikely(cpy_r_r0 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL12;
    }
CPyL1: ;
    if (cpy_r_r0) goto CPyL3;
CPyL2: ;
    cpy_r_r1 = cpy_r_r0;
    goto CPyL11;
CPyL3: ;
    cpy_r_r2 = 0;
    cpy_r_r3 = ((faster_eth_abi____grammar___ABITypeObject *)cpy_r_self)->_arrlist;
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist", "ABIType", "arrlist", 139, CPyStatic__grammar___globals);
        goto CPyL12;
    }
    CPy_INCREF(cpy_r_r3);
CPyL4: ;
    cpy_r_r4 = PyObject_GetIter(cpy_r_r3);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL12;
    }
CPyL5: ;
    cpy_r_r5 = PyIter_Next(cpy_r_r4);
    if (cpy_r_r5 == NULL) goto CPyL13;
    cpy_r_dim = cpy_r_r5;
    cpy_r_r6 = CPyObject_Size(cpy_r_dim);
    CPy_DECREF(cpy_r_dim);
    if (unlikely(cpy_r_r6 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL14;
    }
    cpy_r_r7 = cpy_r_r6 == 0;
    CPyTagged_DECREF(cpy_r_r6);
    if (cpy_r_r7) {
        goto CPyL15;
    } else
        goto CPyL5;
CPyL8: ;
    cpy_r_r2 = 1;
    goto CPyL10;
CPyL9: ;
    cpy_r_r8 = CPy_NoErrOccurred();
    if (unlikely(!cpy_r_r8)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL12;
    }
CPyL10: ;
    cpy_r_r1 = cpy_r_r2;
CPyL11: ;
    return cpy_r_r1;
CPyL12: ;
    cpy_r_r9 = 2;
    return cpy_r_r9;
CPyL13: ;
    CPy_DECREF(cpy_r_r4);
    goto CPyL9;
CPyL14: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL12;
CPyL15: ;
    CPy_DECREF(cpy_r_r4);
    goto CPyL8;
}

PyObject *CPyPy__grammar___ABIType____has_dynamic_arrlist(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":_has_dynamic_arrlist", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___ABIType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType____has_dynamic_arrlist(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType____has_dynamic_arrlist__ABIType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_has_dynamic_arrlist' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (unlikely(!PyBool_Check(cpy_r_r1))) {
        CPy_TypeError("bool", cpy_r_r1); cpy_r_r2 = 2;
    } else
        cpy_r_r2 = cpy_r_r1 == Py_True;
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2 == 2) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = 2;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___ABIType____has_dynamic_arrlist__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":_has_dynamic_arrlist__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___ABIType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj___mypyc_self__); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType____has_dynamic_arrlist__ABIType_glue(arg___mypyc_self__);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "_has_dynamic_arrlist__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___ABIType_____ne__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_rhs) {
    char cpy_r_r0;
    char cpy_r_r1;
    char cpy_r_r2;
    cpy_r_r0 = CPY_GET_METHOD(cpy_r___mypyc_self__, CPyType__grammar___ABIType, 2, faster_eth_abi____grammar___ABITypeObject, char (*)(PyObject *, PyObject *))(cpy_r___mypyc_self__, cpy_r_rhs); /* __eq__ */
    if (cpy_r_r0 == 2) goto CPyL2;
    cpy_r_r1 = cpy_r_r0 ^ 1;
    return cpy_r_r1;
CPyL2: ;
    cpy_r_r2 = 2;
    return cpy_r_r2;
}

PyObject *CPyPy__grammar___ABIType_____ne__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"rhs", 0};
    static CPyArg_Parser parser = {"O:__ne__", kwlist, 0};
    PyObject *obj_rhs;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_rhs)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___ABIType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj___mypyc_self__); 
        goto fail;
    }
    PyObject *arg_rhs;
    if (likely(PyObject_TypeCheck(obj_rhs, CPyType__grammar___ABIType)))
        arg_rhs = obj_rhs;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_rhs); 
        goto fail;
    }
    char retval = CPyDef__grammar___ABIType_____ne__(arg___mypyc_self__, arg_rhs);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__ne__", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___TupleType_____init__(PyObject *cpy_r_self, PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    char cpy_r_r4;
    if (cpy_r_arrlist != NULL) goto CPyL8;
    cpy_r_r0 = Py_None;
    cpy_r_arrlist = cpy_r_r0;
CPyL2: ;
    if (cpy_r_node != NULL) goto CPyL9;
    cpy_r_r1 = Py_None;
    cpy_r_node = cpy_r_r1;
CPyL4: ;
    cpy_r_r2 = CPyDef__grammar___ABIType_____init__(cpy_r_self, cpy_r_arrlist, cpy_r_node);
    CPy_DECREF(cpy_r_arrlist);
    CPy_DECREF(cpy_r_node);
    if (unlikely(cpy_r_r2 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL7;
    }
    CPy_INCREF(cpy_r_components);
    if (((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components != NULL) {
        CPy_DECREF(((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components);
    }
    ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components = cpy_r_components;
    cpy_r_r3 = 1;
    if (unlikely(!cpy_r_r3)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL7;
    }
    return 1;
CPyL7: ;
    cpy_r_r4 = 2;
    return cpy_r_r4;
CPyL8: ;
    CPy_INCREF(cpy_r_arrlist);
    goto CPyL2;
CPyL9: ;
    CPy_INCREF(cpy_r_node);
    goto CPyL4;
}

PyObject *CPyPy__grammar___TupleType_____init__(PyObject *self, PyObject *args, PyObject *kw) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"components", "arrlist", "node", 0};
    PyObject *obj_components;
    PyObject *obj_arrlist = NULL;
    PyObject *obj_node = NULL;
    if (!CPyArg_ParseTupleAndKeywords(args, kw, "O|O$O", "__init__", kwlist, &obj_components, &obj_arrlist, &obj_node)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    PyObject * arg_components;
    if (likely(PyTuple_Check(obj_components)))
        arg_components = obj_components;
    else {
        CPy_TypeError("tuple", obj_components); 
        goto fail;
    }
    PyObject *arg_arrlist;
    if (obj_arrlist == NULL) {
        arg_arrlist = NULL;
        goto __LL15;
    }
    arg_arrlist = obj_arrlist;
    if (arg_arrlist != NULL) goto __LL15;
    if (obj_arrlist == Py_None)
        arg_arrlist = obj_arrlist;
    else {
        arg_arrlist = NULL;
    }
    if (arg_arrlist != NULL) goto __LL15;
    CPy_TypeError("object or None", obj_arrlist); 
    goto fail;
__LL15: ;
    PyObject *arg_node;
    if (obj_node == NULL) {
        arg_node = NULL;
        goto __LL16;
    }
    arg_node = obj_node;
    if (arg_node != NULL) goto __LL16;
    if (obj_node == Py_None)
        arg_node = obj_node;
    else {
        arg_node = NULL;
    }
    if (arg_node != NULL) goto __LL16;
    CPy_TypeError("object or None", obj_node); 
    goto fail;
__LL16: ;
    char retval = CPyDef__grammar___TupleType_____init__(arg_self, arg_components, arg_arrlist, arg_node);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___TupleType_____init___3__TupleType_glue(PyObject *cpy_r_self, PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    CPyPtr cpy_r_r3;
    CPyPtr cpy_r_r4;
    PyObject *cpy_r_r5;
    char cpy_r_r6;
    int32_t cpy_r_r7;
    char cpy_r_r8;
    PyObject *cpy_r_r9;
    int32_t cpy_r_r10;
    char cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    char cpy_r_r14;
    char cpy_r_r15;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__init__' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r_self, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL12;
    cpy_r_r2 = PyList_New(1);
    if (cpy_r_r2 == NULL) goto CPyL13;
    cpy_r_r3 = (CPyPtr)&((PyListObject *)cpy_r_r2)->ob_item;
    cpy_r_r4 = *(CPyPtr *)cpy_r_r3;
    CPy_INCREF(cpy_r_components);
    *(PyObject * *)cpy_r_r4 = cpy_r_components;
    cpy_r_r5 = PyDict_New();
    if (cpy_r_r5 == NULL) goto CPyL14;
    cpy_r_r6 = 0;
    if (cpy_r_arrlist == NULL) goto CPyL5;
    cpy_r_r7 = PyList_Append(cpy_r_r2, cpy_r_arrlist);
    cpy_r_r8 = cpy_r_r7 >= 0;
    if (!cpy_r_r8) {
        goto CPyL15;
    } else
        goto CPyL6;
CPyL5: ;
    cpy_r_r6 = 1;
CPyL6: ;
    if (cpy_r_node == NULL) goto CPyL8;
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'node' */
    cpy_r_r10 = CPyDict_SetItem(cpy_r_r5, cpy_r_r9, cpy_r_node);
    cpy_r_r11 = cpy_r_r10 >= 0;
    if (!cpy_r_r11) goto CPyL15;
CPyL8: ;
    cpy_r_r12 = PyList_AsTuple(cpy_r_r2);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    if (cpy_r_r12 == NULL) goto CPyL16;
    cpy_r_r13 = PyObject_Call(cpy_r_r1, cpy_r_r12, cpy_r_r5);
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_r12);
    CPy_DECREF(cpy_r_r5);
    if (cpy_r_r13 == NULL) goto CPyL12;
    if (unlikely(cpy_r_r13 != Py_None)) {
        CPy_TypeError("None", cpy_r_r13); cpy_r_r14 = 2;
    } else
        cpy_r_r14 = 1;
    CPy_DECREF(cpy_r_r13);
    if (cpy_r_r14 == 2) goto CPyL12;
    return cpy_r_r14;
CPyL12: ;
    cpy_r_r15 = 2;
    return cpy_r_r15;
CPyL13: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL12;
CPyL14: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    goto CPyL12;
CPyL15: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    CPy_DECREF(cpy_r_r5);
    goto CPyL12;
CPyL16: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_r5);
    goto CPyL12;
}

PyObject *CPyPy__grammar___TupleType_____init___3__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"components", "arrlist", "node", 0};
    static CPyArg_Parser parser = {"O|O$O:__init____TupleType_glue", kwlist, 0};
    PyObject *obj_components;
    PyObject *obj_arrlist = NULL;
    PyObject *obj_node = NULL;
    if (!CPyArg_ParseStackAndKeywords(args, nargs, kwnames, &parser, &obj_components, &obj_arrlist, &obj_node)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    PyObject * arg_components;
    if (likely(PyTuple_Check(obj_components)))
        arg_components = obj_components;
    else {
        CPy_TypeError("tuple", obj_components); 
        goto fail;
    }
    PyObject *arg_arrlist;
    if (obj_arrlist == NULL) {
        arg_arrlist = NULL;
        goto __LL17;
    }
    arg_arrlist = obj_arrlist;
    if (arg_arrlist != NULL) goto __LL17;
    if (obj_arrlist == Py_None)
        arg_arrlist = obj_arrlist;
    else {
        arg_arrlist = NULL;
    }
    if (arg_arrlist != NULL) goto __LL17;
    CPy_TypeError("object or None", obj_arrlist); 
    goto fail;
__LL17: ;
    PyObject *arg_node;
    if (obj_node == NULL) {
        arg_node = NULL;
        goto __LL18;
    }
    arg_node = obj_node;
    if (arg_node != NULL) goto __LL18;
    if (obj_node == Py_None)
        arg_node = obj_node;
    else {
        arg_node = NULL;
    }
    if (arg_node != NULL) goto __LL18;
    CPy_TypeError("object or None", obj_node); 
    goto fail;
__LL18: ;
    char retval = CPyDef__grammar___TupleType_____init___3__TupleType_glue(arg_self, arg_components, arg_arrlist, arg_node);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init____TupleType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___TupleType___to_type_str(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_arrlist;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject **cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    CPyPtr cpy_r_r25;
    int64_t cpy_r_r26;
    PyObject *cpy_r_r27;
    CPyPtr cpy_r_r28;
    int64_t cpy_r_r29;
    int64_t cpy_r_r30;
    char cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    int64_t cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject *cpy_r_r40;
    cpy_r_r0 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_arrlist;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "to_type_str", "TupleType", "arrlist", 169, CPyStatic__grammar___globals);
        goto CPyL23;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_arrlist = cpy_r_r0;
    cpy_r_r1 = PyTuple_Check(cpy_r_arrlist);
    if (!cpy_r_r1) goto CPyL24;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r3 = CPyModule_builtins;
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'repr' */
    cpy_r_r5 = CPyObject_GetAttr(cpy_r_r3, cpy_r_r4);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL25;
    }
    cpy_r_r6 = (PyObject *)&PyList_Type;
    if (likely(PyTuple_Check(cpy_r_arrlist)))
        cpy_r_r7 = cpy_r_arrlist;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "to_type_str", 172, CPyStatic__grammar___globals, "tuple", cpy_r_arrlist);
        goto CPyL26;
    }
    cpy_r_r8 = CPyModule_builtins;
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    cpy_r_r10 = CPyObject_GetAttr(cpy_r_r8, cpy_r_r9);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL27;
    }
    PyObject *cpy_r_r11[2] = {cpy_r_r6, cpy_r_r7};
    cpy_r_r12 = (PyObject **)&cpy_r_r11;
    cpy_r_r13 = PyObject_Vectorcall(cpy_r_r10, cpy_r_r12, 2, 0);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL27;
    }
    CPy_DECREF(cpy_r_r7);
    cpy_r_r14 = CPyModule_builtins;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    cpy_r_r16 = CPyObject_GetAttr(cpy_r_r14, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    PyObject *cpy_r_r17[2] = {cpy_r_r5, cpy_r_r13};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_Vectorcall(cpy_r_r16, cpy_r_r18, 2, 0);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    CPy_DECREF(cpy_r_r5);
    CPy_DECREF(cpy_r_r13);
    cpy_r_r20 = PyUnicode_Join(cpy_r_r2, cpy_r_r19);
    CPy_DECREF(cpy_r_r19);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL23;
    }
    cpy_r_arrlist = cpy_r_r20;
    goto CPyL11;
CPyL10: ;
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    CPy_INCREF(cpy_r_r21);
    cpy_r_arrlist = cpy_r_r21;
CPyL11: ;
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '(' */
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ',' */
    cpy_r_r24 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components;
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "to_type_str", "TupleType", "components", 176, CPyStatic__grammar___globals);
        goto CPyL25;
    }
    CPy_INCREF(cpy_r_r24);
CPyL12: ;
    cpy_r_r25 = (CPyPtr)&((PyVarObject *)cpy_r_r24)->ob_size;
    cpy_r_r26 = *(int64_t *)cpy_r_r25;
    cpy_r_r27 = PyList_New(cpy_r_r26);
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL29;
    }
    cpy_r_r28 = (CPyPtr)&((PyVarObject *)cpy_r_r24)->ob_size;
    cpy_r_r29 = *(int64_t *)cpy_r_r28;
    cpy_r_r30 = 0;
CPyL14: ;
    cpy_r_r31 = cpy_r_r30 < cpy_r_r29;
    if (!cpy_r_r31) goto CPyL30;
    cpy_r_r32 = CPySequenceTuple_GetItemUnsafe(cpy_r_r24, cpy_r_r30);
    if (likely(PyObject_TypeCheck(cpy_r_r32, CPyType__grammar___ABIType)))
        cpy_r_r33 = cpy_r_r32;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "to_type_str", 176, CPyStatic__grammar___globals, "faster_eth_abi._grammar.ABIType", cpy_r_r32);
        goto CPyL31;
    }
    cpy_r_r34 = CPY_GET_METHOD(cpy_r_r33, CPyType__grammar___ABIType, 3, faster_eth_abi____grammar___ABITypeObject, PyObject * (*)(PyObject *))(cpy_r_r33); /* to_type_str */
    CPy_DECREF_NO_IMM(cpy_r_r33);
    if (unlikely(cpy_r_r34 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL31;
    }
    CPyList_SetItemUnsafe(cpy_r_r27, cpy_r_r30, cpy_r_r34);
    cpy_r_r35 = cpy_r_r30 + 1;
    cpy_r_r30 = cpy_r_r35;
    goto CPyL14;
CPyL19: ;
    cpy_r_r36 = PyUnicode_Join(cpy_r_r23, cpy_r_r27);
    CPy_DECREF_NO_IMM(cpy_r_r27);
    if (unlikely(cpy_r_r36 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL25;
    }
    cpy_r_r37 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ')' */
    if (likely(PyUnicode_Check(cpy_r_arrlist)))
        cpy_r_r38 = cpy_r_arrlist;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "to_type_str", 176, CPyStatic__grammar___globals, "str", cpy_r_arrlist);
        goto CPyL32;
    }
    cpy_r_r39 = CPyStr_Build(4, cpy_r_r22, cpy_r_r36, cpy_r_r37, cpy_r_r38);
    CPy_DECREF(cpy_r_r36);
    CPy_DECREF(cpy_r_r38);
    if (unlikely(cpy_r_r39 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL23;
    }
    return cpy_r_r39;
CPyL23: ;
    cpy_r_r40 = NULL;
    return cpy_r_r40;
CPyL24: ;
    CPy_DECREF(cpy_r_arrlist);
    goto CPyL10;
CPyL25: ;
    CPy_DecRef(cpy_r_arrlist);
    goto CPyL23;
CPyL26: ;
    CPy_DecRef(cpy_r_r5);
    goto CPyL23;
CPyL27: ;
    CPy_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r7);
    goto CPyL23;
CPyL28: ;
    CPy_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r13);
    goto CPyL23;
CPyL29: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r24);
    goto CPyL23;
CPyL30: ;
    CPy_DECREF(cpy_r_r24);
    goto CPyL19;
CPyL31: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r24);
    CPy_DecRef(cpy_r_r27);
    goto CPyL23;
CPyL32: ;
    CPy_DecRef(cpy_r_r36);
    goto CPyL23;
}

PyObject *CPyPy__grammar___TupleType___to_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":to_type_str", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___TupleType___to_type_str(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___TupleType___to_type_str__TupleType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'to_type_str' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (likely(PyUnicode_Check(cpy_r_r3)))
        cpy_r_r4 = cpy_r_r3;
    else {
        CPy_TypeError("str", cpy_r_r3); 
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = NULL;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___TupleType___to_type_str__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":to_type_str__TupleType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___TupleType___to_type_str__TupleType_glue(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str__TupleType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___TupleType___item_type(PyObject *cpy_r_self) {
    char cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject **cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    int32_t cpy_r_r18;
    char cpy_r_r19;
    char cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_arrlist;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    char cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject **cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r_self, CPyType__grammar___TupleType, 7, faster_eth_abi____grammar___TupleTypeObject, char); /* is_array */
    if (unlikely(cpy_r_r0 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL26;
    }
CPyL1: ;
    if (cpy_r_r0) goto CPyL8;
CPyL2: ;
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "Cannot determine item type for non-array type '" */
    cpy_r_r2 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___TupleType, 12, faster_eth_abi____grammar___TupleTypeObject, PyObject * (*)(PyObject *))(cpy_r_self); /* to_type_str */
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL26;
    }
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "'" */
    cpy_r_r4 = CPyStr_Build(3, cpy_r_r1, cpy_r_r2, cpy_r_r3);
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL26;
    }
    cpy_r_r5 = CPyModule_builtins;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r7 = CPyObject_GetAttr(cpy_r_r5, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL27;
    }
    PyObject *cpy_r_r8[1] = {cpy_r_r4};
    cpy_r_r9 = (PyObject **)&cpy_r_r8;
    cpy_r_r10 = PyObject_Vectorcall(cpy_r_r7, cpy_r_r9, 1, 0);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL27;
    }
    CPy_DECREF(cpy_r_r4);
    CPy_Raise(cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL26;
    }
    CPy_Unreachable();
CPyL8: ;
    cpy_r_r11 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_arrlist;
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "TupleType", "arrlist", 185, CPyStatic__grammar___globals);
        goto CPyL26;
    }
    CPy_INCREF(cpy_r_r11);
CPyL9: ;
    cpy_r_r12 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r13 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* -1 */
    cpy_r_r15 = PySlice_New(cpy_r_r12, cpy_r_r14, cpy_r_r13);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    cpy_r_r16 = cpy_r_r11;
    cpy_r_r17 = PyObject_GetItem(cpy_r_r16, cpy_r_r15);
    CPy_DECREF(cpy_r_r16);
    CPy_DECREF(cpy_r_r15);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL26;
    }
    cpy_r_r18 = PyObject_IsTrue(cpy_r_r17);
    cpy_r_r19 = cpy_r_r18 >= 0;
    if (unlikely(!cpy_r_r19)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", -1, CPyStatic__grammar___globals);
        goto CPyL29;
    }
    cpy_r_r20 = cpy_r_r18;
    if (!cpy_r_r20) goto CPyL30;
    cpy_r_r21 = cpy_r_r17;
    goto CPyL16;
CPyL15: ;
    cpy_r_r22 = Py_None;
    cpy_r_r21 = cpy_r_r22;
CPyL16: ;
    cpy_r_arrlist = cpy_r_r21;
    cpy_r_r23 = CPy_TYPE(cpy_r_self);
    cpy_r_r24 = (PyObject *)CPyType__grammar___TupleType;
    cpy_r_r25 = cpy_r_r23 == cpy_r_r24;
    if (cpy_r_r25) {
        goto CPyL31;
    } else
        goto CPyL21;
CPyL17: ;
    cpy_r_r26 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components;
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "TupleType", "components", 188, CPyStatic__grammar___globals);
        goto CPyL32;
    }
    CPy_INCREF(cpy_r_r26);
CPyL18: ;
    cpy_r_r27 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_node;
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "TupleType", "node", 188, CPyStatic__grammar___globals);
        goto CPyL33;
    }
    CPy_INCREF(cpy_r_r27);
CPyL19: ;
    cpy_r_r28 = CPyDef__grammar___TupleType(cpy_r_r26, cpy_r_arrlist, cpy_r_r27);
    CPy_DECREF(cpy_r_r26);
    CPy_DECREF(cpy_r_arrlist);
    CPy_DECREF(cpy_r_r27);
    if (unlikely(cpy_r_r28 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL26;
    }
    return cpy_r_r28;
CPyL21: ;
    cpy_r_r29 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components;
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "TupleType", "components", 190, CPyStatic__grammar___globals);
        goto CPyL34;
    }
    CPy_INCREF(cpy_r_r29);
CPyL22: ;
    cpy_r_r30 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_node;
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "TupleType", "node", 190, CPyStatic__grammar___globals);
        goto CPyL35;
    }
    CPy_INCREF(cpy_r_r30);
CPyL23: ;
    PyObject *cpy_r_r31[3] = {cpy_r_r29, cpy_r_arrlist, cpy_r_r30};
    cpy_r_r32 = (PyObject **)&cpy_r_r31;
    cpy_r_r33 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('node',) */
    cpy_r_r34 = PyObject_Vectorcall(cpy_r_r23, cpy_r_r32, 2, cpy_r_r33);
    CPy_DECREF(cpy_r_r23);
    if (unlikely(cpy_r_r34 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL36;
    }
    CPy_DECREF(cpy_r_r29);
    CPy_DECREF(cpy_r_arrlist);
    CPy_DECREF(cpy_r_r30);
    if (likely(PyObject_TypeCheck(cpy_r_r34, CPyType__grammar___TupleType)))
        cpy_r_r35 = cpy_r_r34;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "item_type", 190, CPyStatic__grammar___globals, "faster_eth_abi._grammar.TupleType", cpy_r_r34);
        goto CPyL26;
    }
    return cpy_r_r35;
CPyL26: ;
    cpy_r_r36 = NULL;
    return cpy_r_r36;
CPyL27: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL26;
CPyL28: ;
    CPy_DecRef(cpy_r_r11);
    goto CPyL26;
CPyL29: ;
    CPy_DecRef(cpy_r_r17);
    goto CPyL26;
CPyL30: ;
    CPy_DECREF(cpy_r_r17);
    goto CPyL15;
CPyL31: ;
    CPy_DECREF(cpy_r_r23);
    goto CPyL17;
CPyL32: ;
    CPy_DecRef(cpy_r_arrlist);
    goto CPyL26;
CPyL33: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r26);
    goto CPyL26;
CPyL34: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r23);
    goto CPyL26;
CPyL35: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r23);
    CPy_DecRef(cpy_r_r29);
    goto CPyL26;
CPyL36: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r29);
    CPy_DecRef(cpy_r_r30);
    goto CPyL26;
}

PyObject *CPyPy__grammar___TupleType___item_type(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___TupleType___item_type(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___TupleType___item_type__ABIType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r___mypyc_self__, CPyType__grammar___TupleType, 13, faster_eth_abi____grammar___TupleTypeObject, PyObject *); /* item_type */
    if (cpy_r_r0 == NULL) goto CPyL2;
CPyL1: ;
    return cpy_r_r0;
CPyL2: ;
    cpy_r_r1 = NULL;
    return cpy_r_r1;
}

PyObject *CPyPy__grammar___TupleType___item_type__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___TupleType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj___mypyc_self__); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___TupleType___item_type__ABIType_glue(arg___mypyc_self__);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___TupleType___item_type__TupleType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'item_type' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (likely(PyObject_TypeCheck(cpy_r_r1, CPyType__grammar___TupleType)))
        cpy_r_r2 = cpy_r_r1;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", cpy_r_r1); 
        cpy_r_r2 = NULL;
    }
    if (cpy_r_r2 == NULL) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___TupleType___item_type__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type__TupleType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___TupleType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj___mypyc_self__); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___TupleType___item_type__TupleType_glue(arg___mypyc_self__);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type__TupleType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___TupleType___validate(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    CPyPtr cpy_r_r1;
    int64_t cpy_r_r2;
    int64_t cpy_r_r3;
    char cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    int64_t cpy_r_r8;
    char cpy_r_r9;
    cpy_r_r0 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "validate", "TupleType", "components", 193, CPyStatic__grammar___globals);
        goto CPyL7;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = (CPyPtr)&((PyVarObject *)cpy_r_r0)->ob_size;
    cpy_r_r2 = *(int64_t *)cpy_r_r1;
    cpy_r_r3 = 0;
CPyL2: ;
    cpy_r_r4 = cpy_r_r3 < cpy_r_r2;
    if (!cpy_r_r4) goto CPyL8;
    cpy_r_r5 = CPySequenceTuple_GetItemUnsafe(cpy_r_r0, cpy_r_r3);
    if (likely(PyObject_TypeCheck(cpy_r_r5, CPyType__grammar___ABIType)))
        cpy_r_r6 = cpy_r_r5;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "validate", 193, CPyStatic__grammar___globals, "faster_eth_abi._grammar.ABIType", cpy_r_r5);
        goto CPyL9;
    }
    cpy_r_r7 = CPY_GET_METHOD(cpy_r_r6, CPyType__grammar___ABIType, 5, faster_eth_abi____grammar___ABITypeObject, char (*)(PyObject *))(cpy_r_r6); /* validate */
    CPy_DECREF_NO_IMM(cpy_r_r6);
    if (unlikely(cpy_r_r7 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL9;
    }
    cpy_r_r8 = cpy_r_r3 + 1;
    cpy_r_r3 = cpy_r_r8;
    goto CPyL2;
CPyL6: ;
    return 1;
CPyL7: ;
    cpy_r_r9 = 2;
    return cpy_r_r9;
CPyL8: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL6;
CPyL9: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL7;
}

PyObject *CPyPy__grammar___TupleType___validate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":validate", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___TupleType___validate(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___TupleType___validate__TupleType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    char cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'validate' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (unlikely(cpy_r_r3 != Py_None)) {
        CPy_TypeError("None", cpy_r_r3); cpy_r_r4 = 2;
    } else
        cpy_r_r4 = 1;
    CPy_DECREF(cpy_r_r3);
    if (cpy_r_r4 == 2) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___TupleType___validate__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":validate__TupleType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___TupleType___validate__TupleType_glue(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate__TupleType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___TupleType___is_dynamic(PyObject *cpy_r_self) {
    char cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    CPyPtr cpy_r_r3;
    int64_t cpy_r_r4;
    int64_t cpy_r_r5;
    char cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    int64_t cpy_r_r10;
    char cpy_r_r11;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r_self, CPyType__grammar___TupleType, 9, faster_eth_abi____grammar___TupleTypeObject, char); /* _has_dynamic_arrlist */
    if (unlikely(cpy_r_r0 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL12;
    }
CPyL1: ;
    if (!cpy_r_r0) goto CPyL3;
CPyL2: ;
    return 1;
CPyL3: ;
    cpy_r_r1 = 0;
    cpy_r_r2 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_self)->_components;
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "is_dynamic", "TupleType", "components", 201, CPyStatic__grammar___globals);
        goto CPyL12;
    }
    CPy_INCREF(cpy_r_r2);
CPyL4: ;
    cpy_r_r3 = (CPyPtr)&((PyVarObject *)cpy_r_r2)->ob_size;
    cpy_r_r4 = *(int64_t *)cpy_r_r3;
    cpy_r_r5 = 0;
CPyL5: ;
    cpy_r_r6 = cpy_r_r5 < cpy_r_r4;
    if (!cpy_r_r6) goto CPyL13;
    cpy_r_r7 = CPySequenceTuple_GetItemUnsafe(cpy_r_r2, cpy_r_r5);
    if (likely(PyObject_TypeCheck(cpy_r_r7, CPyType__grammar___ABIType)))
        cpy_r_r8 = cpy_r_r7;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "is_dynamic", 201, CPyStatic__grammar___globals, "faster_eth_abi._grammar.ABIType", cpy_r_r7);
        goto CPyL14;
    }
    cpy_r_r9 = CPY_GET_ATTR(cpy_r_r8, CPyType__grammar___ABIType, 8, faster_eth_abi____grammar___ABITypeObject, char); /* is_dynamic */
    CPy_DECREF_NO_IMM(cpy_r_r8);
    if (unlikely(cpy_r_r9 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL14;
    }
CPyL8: ;
    if (cpy_r_r9) {
        goto CPyL15;
    } else
        goto CPyL10;
CPyL9: ;
    cpy_r_r1 = 1;
    goto CPyL11;
CPyL10: ;
    cpy_r_r10 = cpy_r_r5 + 1;
    cpy_r_r5 = cpy_r_r10;
    goto CPyL5;
CPyL11: ;
    return cpy_r_r1;
CPyL12: ;
    cpy_r_r11 = 2;
    return cpy_r_r11;
CPyL13: ;
    CPy_DECREF(cpy_r_r2);
    goto CPyL11;
CPyL14: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL12;
CPyL15: ;
    CPy_DECREF(cpy_r_r2);
    goto CPyL9;
}

PyObject *CPyPy__grammar___TupleType___is_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_dynamic", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___TupleType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___TupleType___is_dynamic(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___TupleType___is_dynamic__TupleType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_dynamic' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (unlikely(!PyBool_Check(cpy_r_r1))) {
        CPy_TypeError("bool", cpy_r_r1); cpy_r_r2 = 2;
    } else
        cpy_r_r2 = cpy_r_r1 == Py_True;
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2 == 2) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = 2;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___TupleType___is_dynamic__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_dynamic__TupleType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___TupleType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj___mypyc_self__); 
        goto fail;
    }
    char retval = CPyDef__grammar___TupleType___is_dynamic__TupleType_glue(arg___mypyc_self__);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic__TupleType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___BasicType_____init__(PyObject *cpy_r_self, PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    char cpy_r_r3;
    char cpy_r_r4;
    char cpy_r_r5;
    char cpy_r_r6;
    if (cpy_r_sub != NULL) goto CPyL11;
    cpy_r_r0 = Py_None;
    cpy_r_sub = cpy_r_r0;
CPyL2: ;
    if (cpy_r_arrlist != NULL) goto CPyL12;
    cpy_r_r1 = Py_None;
    cpy_r_arrlist = cpy_r_r1;
CPyL4: ;
    if (cpy_r_node != NULL) goto CPyL13;
    cpy_r_r2 = Py_None;
    cpy_r_node = cpy_r_r2;
CPyL6: ;
    cpy_r_r3 = CPyDef__grammar___ABIType_____init__(cpy_r_self, cpy_r_arrlist, cpy_r_node);
    CPy_DECREF(cpy_r_arrlist);
    CPy_DECREF(cpy_r_node);
    if (unlikely(cpy_r_r3 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL14;
    }
    CPy_INCREF(cpy_r_base);
    if (((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base != NULL) {
        CPy_DECREF(((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base);
    }
    ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base = cpy_r_base;
    cpy_r_r4 = 1;
    if (unlikely(!cpy_r_r4)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL14;
    }
    if (((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub != NULL) {
        CPy_DECREF(((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub);
    }
    ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub = cpy_r_sub;
    cpy_r_r5 = 1;
    if (unlikely(!cpy_r_r5)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL10;
    }
    return 1;
CPyL10: ;
    cpy_r_r6 = 2;
    return cpy_r_r6;
CPyL11: ;
    CPy_INCREF(cpy_r_sub);
    goto CPyL2;
CPyL12: ;
    CPy_INCREF(cpy_r_arrlist);
    goto CPyL4;
CPyL13: ;
    CPy_INCREF(cpy_r_node);
    goto CPyL6;
CPyL14: ;
    CPy_DecRef(cpy_r_sub);
    goto CPyL10;
}

PyObject *CPyPy__grammar___BasicType_____init__(PyObject *self, PyObject *args, PyObject *kw) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"base", "sub", "arrlist", "node", 0};
    PyObject *obj_base;
    PyObject *obj_sub = NULL;
    PyObject *obj_arrlist = NULL;
    PyObject *obj_node = NULL;
    if (!CPyArg_ParseTupleAndKeywords(args, kw, "O|OO$O", "__init__", kwlist, &obj_base, &obj_sub, &obj_arrlist, &obj_node)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    PyObject *arg_base;
    if (likely(PyUnicode_Check(obj_base)))
        arg_base = obj_base;
    else {
        CPy_TypeError("str", obj_base); 
        goto fail;
    }
    PyObject *arg_sub;
    if (obj_sub == NULL) {
        arg_sub = NULL;
        goto __LL19;
    }
    if (PyLong_Check(obj_sub))
        arg_sub = obj_sub;
    else {
        arg_sub = NULL;
    }
    if (arg_sub != NULL) goto __LL19;
    if (PyTuple_Check(obj_sub))
        arg_sub = obj_sub;
    else {
        arg_sub = NULL;
    }
    if (arg_sub != NULL) goto __LL19;
    if (obj_sub == Py_None)
        arg_sub = obj_sub;
    else {
        arg_sub = NULL;
    }
    if (arg_sub != NULL) goto __LL19;
    CPy_TypeError("union[int, tuple, None]", obj_sub); 
    goto fail;
__LL19: ;
    PyObject *arg_arrlist;
    if (obj_arrlist == NULL) {
        arg_arrlist = NULL;
        goto __LL20;
    }
    arg_arrlist = obj_arrlist;
    if (arg_arrlist != NULL) goto __LL20;
    if (obj_arrlist == Py_None)
        arg_arrlist = obj_arrlist;
    else {
        arg_arrlist = NULL;
    }
    if (arg_arrlist != NULL) goto __LL20;
    CPy_TypeError("object or None", obj_arrlist); 
    goto fail;
__LL20: ;
    PyObject *arg_node;
    if (obj_node == NULL) {
        arg_node = NULL;
        goto __LL21;
    }
    arg_node = obj_node;
    if (arg_node != NULL) goto __LL21;
    if (obj_node == Py_None)
        arg_node = obj_node;
    else {
        arg_node = NULL;
    }
    if (arg_node != NULL) goto __LL21;
    CPy_TypeError("object or None", obj_node); 
    goto fail;
__LL21: ;
    char retval = CPyDef__grammar___BasicType_____init__(arg_self, arg_base, arg_sub, arg_arrlist, arg_node);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___BasicType_____init___3__BasicType_glue(PyObject *cpy_r_self, PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    CPyPtr cpy_r_r3;
    CPyPtr cpy_r_r4;
    PyObject *cpy_r_r5;
    char cpy_r_r6;
    int32_t cpy_r_r7;
    char cpy_r_r8;
    int32_t cpy_r_r9;
    char cpy_r_r10;
    PyObject *cpy_r_r11;
    int32_t cpy_r_r12;
    char cpy_r_r13;
    PyObject *cpy_r_r14;
    int32_t cpy_r_r15;
    char cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    char cpy_r_r19;
    char cpy_r_r20;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__init__' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r_self, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL17;
    cpy_r_r2 = PyList_New(1);
    if (cpy_r_r2 == NULL) goto CPyL18;
    cpy_r_r3 = (CPyPtr)&((PyListObject *)cpy_r_r2)->ob_item;
    cpy_r_r4 = *(CPyPtr *)cpy_r_r3;
    CPy_INCREF(cpy_r_base);
    *(PyObject * *)cpy_r_r4 = cpy_r_base;
    cpy_r_r5 = PyDict_New();
    if (cpy_r_r5 == NULL) goto CPyL19;
    cpy_r_r6 = 0;
    if (cpy_r_sub == NULL) goto CPyL5;
    cpy_r_r7 = PyList_Append(cpy_r_r2, cpy_r_sub);
    cpy_r_r8 = cpy_r_r7 >= 0;
    if (!cpy_r_r8) {
        goto CPyL20;
    } else
        goto CPyL6;
CPyL5: ;
    cpy_r_r6 = 1;
CPyL6: ;
    if (cpy_r_arrlist == NULL) goto CPyL10;
    if (cpy_r_r6) goto CPyL9;
    cpy_r_r9 = PyList_Append(cpy_r_r2, cpy_r_arrlist);
    cpy_r_r10 = cpy_r_r9 >= 0;
    if (!cpy_r_r10) {
        goto CPyL20;
    } else
        goto CPyL11;
CPyL9: ;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'arrlist' */
    cpy_r_r12 = CPyDict_SetItem(cpy_r_r5, cpy_r_r11, cpy_r_arrlist);
    cpy_r_r13 = cpy_r_r12 >= 0;
    if (!cpy_r_r13) {
        goto CPyL20;
    } else
        goto CPyL11;
CPyL10: ;
    cpy_r_r6 = 1;
CPyL11: ;
    if (cpy_r_node == NULL) goto CPyL13;
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'node' */
    cpy_r_r15 = CPyDict_SetItem(cpy_r_r5, cpy_r_r14, cpy_r_node);
    cpy_r_r16 = cpy_r_r15 >= 0;
    if (!cpy_r_r16) goto CPyL20;
CPyL13: ;
    cpy_r_r17 = PyList_AsTuple(cpy_r_r2);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    if (cpy_r_r17 == NULL) goto CPyL21;
    cpy_r_r18 = PyObject_Call(cpy_r_r1, cpy_r_r17, cpy_r_r5);
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_r17);
    CPy_DECREF(cpy_r_r5);
    if (cpy_r_r18 == NULL) goto CPyL17;
    if (unlikely(cpy_r_r18 != Py_None)) {
        CPy_TypeError("None", cpy_r_r18); cpy_r_r19 = 2;
    } else
        cpy_r_r19 = 1;
    CPy_DECREF(cpy_r_r18);
    if (cpy_r_r19 == 2) goto CPyL17;
    return cpy_r_r19;
CPyL17: ;
    cpy_r_r20 = 2;
    return cpy_r_r20;
CPyL18: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL17;
CPyL19: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    goto CPyL17;
CPyL20: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF_NO_IMM(cpy_r_r2);
    CPy_DECREF(cpy_r_r5);
    goto CPyL17;
CPyL21: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_r5);
    goto CPyL17;
}

PyObject *CPyPy__grammar___BasicType_____init___3__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"base", "sub", "arrlist", "node", 0};
    static CPyArg_Parser parser = {"O|OO$O:__init____BasicType_glue", kwlist, 0};
    PyObject *obj_base;
    PyObject *obj_sub = NULL;
    PyObject *obj_arrlist = NULL;
    PyObject *obj_node = NULL;
    if (!CPyArg_ParseStackAndKeywords(args, nargs, kwnames, &parser, &obj_base, &obj_sub, &obj_arrlist, &obj_node)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    PyObject *arg_base;
    if (likely(PyUnicode_Check(obj_base)))
        arg_base = obj_base;
    else {
        CPy_TypeError("str", obj_base); 
        goto fail;
    }
    PyObject *arg_sub;
    if (obj_sub == NULL) {
        arg_sub = NULL;
        goto __LL22;
    }
    if (PyLong_Check(obj_sub))
        arg_sub = obj_sub;
    else {
        arg_sub = NULL;
    }
    if (arg_sub != NULL) goto __LL22;
    if (PyTuple_Check(obj_sub))
        arg_sub = obj_sub;
    else {
        arg_sub = NULL;
    }
    if (arg_sub != NULL) goto __LL22;
    if (obj_sub == Py_None)
        arg_sub = obj_sub;
    else {
        arg_sub = NULL;
    }
    if (arg_sub != NULL) goto __LL22;
    CPy_TypeError("union[int, tuple, None]", obj_sub); 
    goto fail;
__LL22: ;
    PyObject *arg_arrlist;
    if (obj_arrlist == NULL) {
        arg_arrlist = NULL;
        goto __LL23;
    }
    arg_arrlist = obj_arrlist;
    if (arg_arrlist != NULL) goto __LL23;
    if (obj_arrlist == Py_None)
        arg_arrlist = obj_arrlist;
    else {
        arg_arrlist = NULL;
    }
    if (arg_arrlist != NULL) goto __LL23;
    CPy_TypeError("object or None", obj_arrlist); 
    goto fail;
__LL23: ;
    PyObject *arg_node;
    if (obj_node == NULL) {
        arg_node = NULL;
        goto __LL24;
    }
    arg_node = obj_node;
    if (arg_node != NULL) goto __LL24;
    if (obj_node == Py_None)
        arg_node = obj_node;
    else {
        arg_node = NULL;
    }
    if (arg_node != NULL) goto __LL24;
    CPy_TypeError("object or None", obj_node); 
    goto fail;
__LL24: ;
    char retval = CPyDef__grammar___BasicType_____init___3__BasicType_glue(arg_self, arg_base, arg_sub, arg_arrlist, arg_node);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__init____BasicType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___BasicType___to_type_str(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    CPyTagged cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_substr;
    char cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject **cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    char cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject **cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject **cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject *cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "to_type_str", "BasicType", "sub", 234, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_arrlist;
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "to_type_str", "BasicType", "arrlist", 234, CPyStatic__grammar___globals);
        goto CPyL29;
    }
    CPy_INCREF(cpy_r_r1);
CPyL2: ;
    cpy_r_r2 = PyLong_Check(cpy_r_r0);
    if (!cpy_r_r2) goto CPyL6;
    if (likely(PyLong_Check(cpy_r_r0)))
        cpy_r_r3 = CPyTagged_FromObject(cpy_r_r0);
    else {
        CPy_TypeError("int", cpy_r_r0); cpy_r_r3 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r3 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL30;
    }
    cpy_r_r4 = CPyTagged_Str(cpy_r_r3);
    CPyTagged_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL30;
    }
    cpy_r_substr = cpy_r_r4;
    goto CPyL13;
CPyL6: ;
    cpy_r_r5 = PyTuple_Check(cpy_r_r0);
    if (!cpy_r_r5) goto CPyL31;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'x' */
    cpy_r_r7 = (PyObject *)&PyUnicode_Type;
    if (likely(PyTuple_Check(cpy_r_r0)))
        cpy_r_r8 = cpy_r_r0;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "to_type_str", 239, CPyStatic__grammar___globals, "tuple", cpy_r_r0);
        goto CPyL30;
    }
    cpy_r_r9 = CPyModule_builtins;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    cpy_r_r11 = CPyObject_GetAttr(cpy_r_r9, cpy_r_r10);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL32;
    }
    PyObject *cpy_r_r12[2] = {cpy_r_r7, cpy_r_r8};
    cpy_r_r13 = (PyObject **)&cpy_r_r12;
    cpy_r_r14 = PyObject_Vectorcall(cpy_r_r11, cpy_r_r13, 2, 0);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r14 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL32;
    }
    CPy_DECREF(cpy_r_r8);
    cpy_r_r15 = PyUnicode_Join(cpy_r_r6, cpy_r_r14);
    CPy_DECREF(cpy_r_r14);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL30;
    }
    cpy_r_substr = cpy_r_r15;
    goto CPyL13;
CPyL12: ;
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    CPy_INCREF(cpy_r_r16);
    cpy_r_substr = cpy_r_r16;
CPyL13: ;
    cpy_r_r17 = PyTuple_Check(cpy_r_r1);
    if (!cpy_r_r17) goto CPyL33;
    cpy_r_r18 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base;
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "to_type_str", "BasicType", "base", 244, CPyStatic__grammar___globals);
        goto CPyL34;
    }
    CPy_INCREF(cpy_r_r18);
CPyL15: ;
    cpy_r_r19 = PyUnicode_Concat(cpy_r_r18, cpy_r_substr);
    CPy_DECREF(cpy_r_r18);
    CPy_DECREF(cpy_r_substr);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL30;
    }
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r21 = CPyModule_builtins;
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'repr' */
    cpy_r_r23 = CPyObject_GetAttr(cpy_r_r21, cpy_r_r22);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL35;
    }
    cpy_r_r24 = (PyObject *)&PyList_Type;
    if (likely(PyTuple_Check(cpy_r_r1)))
        cpy_r_r25 = cpy_r_r1;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "to_type_str", 244, CPyStatic__grammar___globals, "tuple", cpy_r_r1);
        goto CPyL36;
    }
    cpy_r_r26 = CPyModule_builtins;
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    cpy_r_r28 = CPyObject_GetAttr(cpy_r_r26, cpy_r_r27);
    if (unlikely(cpy_r_r28 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL37;
    }
    PyObject *cpy_r_r29[2] = {cpy_r_r24, cpy_r_r25};
    cpy_r_r30 = (PyObject **)&cpy_r_r29;
    cpy_r_r31 = PyObject_Vectorcall(cpy_r_r28, cpy_r_r30, 2, 0);
    CPy_DECREF(cpy_r_r28);
    if (unlikely(cpy_r_r31 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL37;
    }
    CPy_DECREF(cpy_r_r25);
    cpy_r_r32 = CPyModule_builtins;
    cpy_r_r33 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    cpy_r_r34 = CPyObject_GetAttr(cpy_r_r32, cpy_r_r33);
    if (unlikely(cpy_r_r34 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL38;
    }
    PyObject *cpy_r_r35[2] = {cpy_r_r23, cpy_r_r31};
    cpy_r_r36 = (PyObject **)&cpy_r_r35;
    cpy_r_r37 = PyObject_Vectorcall(cpy_r_r34, cpy_r_r36, 2, 0);
    CPy_DECREF(cpy_r_r34);
    if (unlikely(cpy_r_r37 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL38;
    }
    CPy_DECREF(cpy_r_r23);
    CPy_DECREF(cpy_r_r31);
    cpy_r_r38 = PyUnicode_Join(cpy_r_r20, cpy_r_r37);
    CPy_DECREF(cpy_r_r37);
    if (unlikely(cpy_r_r38 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL39;
    }
    cpy_r_r39 = PyUnicode_Concat(cpy_r_r19, cpy_r_r38);
    CPy_DECREF(cpy_r_r19);
    CPy_DECREF(cpy_r_r38);
    if (unlikely(cpy_r_r39 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    return cpy_r_r39;
CPyL25: ;
    cpy_r_r40 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base;
    if (unlikely(cpy_r_r40 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "to_type_str", "BasicType", "base", 246, CPyStatic__grammar___globals);
        goto CPyL40;
    }
    CPy_INCREF(cpy_r_r40);
CPyL26: ;
    cpy_r_r41 = PyUnicode_Concat(cpy_r_r40, cpy_r_substr);
    CPy_DECREF(cpy_r_r40);
    CPy_DECREF(cpy_r_substr);
    if (unlikely(cpy_r_r41 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    return cpy_r_r41;
CPyL28: ;
    cpy_r_r42 = NULL;
    return cpy_r_r42;
CPyL29: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL28;
CPyL30: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL28;
CPyL31: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL12;
CPyL32: ;
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r8);
    goto CPyL28;
CPyL33: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL25;
CPyL34: ;
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_substr);
    goto CPyL28;
CPyL35: ;
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r19);
    goto CPyL28;
CPyL36: ;
    CPy_DecRef(cpy_r_r19);
    CPy_DecRef(cpy_r_r23);
    goto CPyL28;
CPyL37: ;
    CPy_DecRef(cpy_r_r19);
    CPy_DecRef(cpy_r_r23);
    CPy_DecRef(cpy_r_r25);
    goto CPyL28;
CPyL38: ;
    CPy_DecRef(cpy_r_r19);
    CPy_DecRef(cpy_r_r23);
    CPy_DecRef(cpy_r_r31);
    goto CPyL28;
CPyL39: ;
    CPy_DecRef(cpy_r_r19);
    goto CPyL28;
CPyL40: ;
    CPy_DecRef(cpy_r_substr);
    goto CPyL28;
}

PyObject *CPyPy__grammar___BasicType___to_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":to_type_str", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___BasicType___to_type_str(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___BasicType___to_type_str__BasicType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'to_type_str' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (likely(PyUnicode_Check(cpy_r_r3)))
        cpy_r_r4 = cpy_r_r3;
    else {
        CPy_TypeError("str", cpy_r_r3); 
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = NULL;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___BasicType___to_type_str__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":to_type_str__BasicType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___BasicType___to_type_str__BasicType_glue(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "to_type_str__BasicType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___BasicType___item_type(PyObject *cpy_r_self) {
    char cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject **cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    int32_t cpy_r_r19;
    char cpy_r_r20;
    char cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_arrlist;
    PyObject *cpy_r_r24;
    char cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject **cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r_self, CPyType__grammar___BasicType, 7, faster_eth_abi____grammar___BasicTypeObject, char); /* is_array */
    if (unlikely(cpy_r_r0 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
CPyL1: ;
    if (cpy_r_r0) goto CPyL8;
CPyL2: ;
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "Cannot determine item type for non-array type '" */
    cpy_r_r2 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 12, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *))(cpy_r_self); /* to_type_str */
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "'" */
    cpy_r_r4 = CPyStr_Build(3, cpy_r_r1, cpy_r_r2, cpy_r_r3);
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    cpy_r_r5 = CPyModule_builtins;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r7 = CPyObject_GetAttr(cpy_r_r5, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL29;
    }
    PyObject *cpy_r_r8[1] = {cpy_r_r4};
    cpy_r_r9 = (PyObject **)&cpy_r_r8;
    cpy_r_r10 = PyObject_Vectorcall(cpy_r_r7, cpy_r_r9, 1, 0);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL29;
    }
    CPy_DECREF(cpy_r_r4);
    CPy_Raise(cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    CPy_Unreachable();
CPyL8: ;
    cpy_r_r11 = CPy_TYPE(cpy_r_self);
    cpy_r_r12 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_arrlist;
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "arrlist", 256, CPyStatic__grammar___globals);
        goto CPyL30;
    }
    CPy_INCREF(cpy_r_r12);
CPyL9: ;
    cpy_r_r13 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r14 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* -1 */
    cpy_r_r16 = PySlice_New(cpy_r_r13, cpy_r_r15, cpy_r_r14);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL31;
    }
    cpy_r_r17 = cpy_r_r12;
    cpy_r_r18 = PyObject_GetItem(cpy_r_r17, cpy_r_r16);
    CPy_DECREF(cpy_r_r17);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL30;
    }
    cpy_r_r19 = PyObject_IsTrue(cpy_r_r18);
    cpy_r_r20 = cpy_r_r19 >= 0;
    if (unlikely(!cpy_r_r20)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", -1, CPyStatic__grammar___globals);
        goto CPyL32;
    }
    cpy_r_r21 = cpy_r_r19;
    if (!cpy_r_r21) goto CPyL33;
    cpy_r_r22 = cpy_r_r18;
    goto CPyL16;
CPyL15: ;
    cpy_r_r23 = Py_None;
    cpy_r_r22 = cpy_r_r23;
CPyL16: ;
    cpy_r_arrlist = cpy_r_r22;
    cpy_r_r24 = (PyObject *)CPyType__grammar___BasicType;
    cpy_r_r25 = cpy_r_r11 == cpy_r_r24;
    if (cpy_r_r25) {
        goto CPyL34;
    } else
        goto CPyL22;
CPyL17: ;
    cpy_r_r26 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base;
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "base", 258, CPyStatic__grammar___globals);
        goto CPyL35;
    }
    CPy_INCREF(cpy_r_r26);
CPyL18: ;
    cpy_r_r27 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub;
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "sub", 258, CPyStatic__grammar___globals);
        goto CPyL36;
    }
    CPy_INCREF(cpy_r_r27);
CPyL19: ;
    cpy_r_r28 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_node;
    if (unlikely(cpy_r_r28 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "node", 258, CPyStatic__grammar___globals);
        goto CPyL37;
    }
    CPy_INCREF(cpy_r_r28);
CPyL20: ;
    cpy_r_r29 = CPyDef__grammar___BasicType(cpy_r_r26, cpy_r_r27, cpy_r_arrlist, cpy_r_r28);
    CPy_DECREF(cpy_r_r26);
    CPy_DECREF(cpy_r_r27);
    CPy_DECREF(cpy_r_arrlist);
    CPy_DECREF(cpy_r_r28);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL28;
    }
    return cpy_r_r29;
CPyL22: ;
    cpy_r_r30 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base;
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "base", 260, CPyStatic__grammar___globals);
        goto CPyL38;
    }
    CPy_INCREF(cpy_r_r30);
CPyL23: ;
    cpy_r_r31 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub;
    if (unlikely(cpy_r_r31 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "sub", 260, CPyStatic__grammar___globals);
        goto CPyL39;
    }
    CPy_INCREF(cpy_r_r31);
CPyL24: ;
    cpy_r_r32 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_node;
    if (unlikely(cpy_r_r32 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "item_type", "BasicType", "node", 260, CPyStatic__grammar___globals);
        goto CPyL40;
    }
    CPy_INCREF(cpy_r_r32);
CPyL25: ;
    PyObject *cpy_r_r33[4] = {cpy_r_r30, cpy_r_r31, cpy_r_arrlist, cpy_r_r32};
    cpy_r_r34 = (PyObject **)&cpy_r_r33;
    cpy_r_r35 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('node',) */
    cpy_r_r36 = PyObject_Vectorcall(cpy_r_r11, cpy_r_r34, 3, cpy_r_r35);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r36 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL41;
    }
    CPy_DECREF(cpy_r_r30);
    CPy_DECREF(cpy_r_r31);
    CPy_DECREF(cpy_r_arrlist);
    CPy_DECREF(cpy_r_r32);
    if (likely(PyObject_TypeCheck(cpy_r_r36, CPyType__grammar___BasicType)))
        cpy_r_r37 = cpy_r_r36;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "item_type", 260, CPyStatic__grammar___globals, "faster_eth_abi._grammar.BasicType", cpy_r_r36);
        goto CPyL28;
    }
    return cpy_r_r37;
CPyL28: ;
    cpy_r_r38 = NULL;
    return cpy_r_r38;
CPyL29: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL28;
CPyL30: ;
    CPy_DecRef(cpy_r_r11);
    goto CPyL28;
CPyL31: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_r12);
    goto CPyL28;
CPyL32: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_r18);
    goto CPyL28;
CPyL33: ;
    CPy_DECREF(cpy_r_r18);
    goto CPyL15;
CPyL34: ;
    CPy_DECREF(cpy_r_r11);
    goto CPyL17;
CPyL35: ;
    CPy_DecRef(cpy_r_arrlist);
    goto CPyL28;
CPyL36: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r26);
    goto CPyL28;
CPyL37: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r26);
    CPy_DecRef(cpy_r_r27);
    goto CPyL28;
CPyL38: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_arrlist);
    goto CPyL28;
CPyL39: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r30);
    goto CPyL28;
CPyL40: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r30);
    CPy_DecRef(cpy_r_r31);
    goto CPyL28;
CPyL41: ;
    CPy_DecRef(cpy_r_arrlist);
    CPy_DecRef(cpy_r_r30);
    CPy_DecRef(cpy_r_r31);
    CPy_DecRef(cpy_r_r32);
    goto CPyL28;
}

PyObject *CPyPy__grammar___BasicType___item_type(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___BasicType___item_type(arg_self);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___BasicType___item_type__ABIType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r___mypyc_self__, CPyType__grammar___BasicType, 13, faster_eth_abi____grammar___BasicTypeObject, PyObject *); /* item_type */
    if (cpy_r_r0 == NULL) goto CPyL2;
CPyL1: ;
    return cpy_r_r0;
CPyL2: ;
    cpy_r_r1 = NULL;
    return cpy_r_r1;
}

PyObject *CPyPy__grammar___BasicType___item_type__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type__ABIType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___BasicType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj___mypyc_self__); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___BasicType___item_type__ABIType_glue(arg___mypyc_self__);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type__ABIType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___BasicType___item_type__BasicType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'item_type' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (likely(PyObject_TypeCheck(cpy_r_r1, CPyType__grammar___BasicType)))
        cpy_r_r2 = cpy_r_r1;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", cpy_r_r1); 
        cpy_r_r2 = NULL;
    }
    if (cpy_r_r2 == NULL) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___BasicType___item_type__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":item_type__BasicType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___BasicType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj___mypyc_self__); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___BasicType___item_type__BasicType_glue(arg___mypyc_self__);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "item_type__BasicType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___BasicType___is_dynamic(PyObject *cpy_r_self) {
    char cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    char cpy_r_r8;
    char cpy_r_r9;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r_self, CPyType__grammar___BasicType, 9, faster_eth_abi____grammar___BasicTypeObject, char); /* _has_dynamic_arrlist */
    if (unlikely(cpy_r_r0 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL11;
    }
CPyL1: ;
    if (!cpy_r_r0) goto CPyL3;
CPyL2: ;
    return 1;
CPyL3: ;
    cpy_r_r1 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base;
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "is_dynamic", "BasicType", "base", 267, CPyStatic__grammar___globals);
        goto CPyL11;
    }
    CPy_INCREF(cpy_r_r1);
CPyL4: ;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'string' */
    cpy_r_r3 = CPyStr_Equal(cpy_r_r1, cpy_r_r2);
    if (cpy_r_r3) {
        goto CPyL12;
    } else
        goto CPyL6;
CPyL5: ;
    return 1;
CPyL6: ;
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes' */
    cpy_r_r5 = CPyStr_Equal(cpy_r_r1, cpy_r_r4);
    CPy_DECREF(cpy_r_r1);
    if (!cpy_r_r5) goto CPyL10;
    cpy_r_r6 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub;
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "is_dynamic", "BasicType", "sub", 271, CPyStatic__grammar___globals);
        goto CPyL11;
    }
CPyL8: ;
    cpy_r_r7 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r8 = cpy_r_r6 == cpy_r_r7;
    if (!cpy_r_r8) goto CPyL10;
    return 1;
CPyL10: ;
    return 0;
CPyL11: ;
    cpy_r_r9 = 2;
    return cpy_r_r9;
CPyL12: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL5;
}

PyObject *CPyPy__grammar___BasicType___is_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_dynamic", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___BasicType___is_dynamic(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___BasicType___is_dynamic__BasicType_glue(PyObject *cpy_r___mypyc_self__) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_dynamic' */
    cpy_r_r1 = CPyObject_GetAttr(cpy_r___mypyc_self__, cpy_r_r0);
    if (cpy_r_r1 == NULL) goto CPyL3;
    if (unlikely(!PyBool_Check(cpy_r_r1))) {
        CPy_TypeError("bool", cpy_r_r1); cpy_r_r2 = 2;
    } else
        cpy_r_r2 = cpy_r_r1 == Py_True;
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2 == 2) goto CPyL3;
    return cpy_r_r2;
CPyL3: ;
    cpy_r_r3 = 2;
    return cpy_r_r3;
}

PyObject *CPyPy__grammar___BasicType___is_dynamic__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":is_dynamic__BasicType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__;
    if (likely(PyObject_TypeCheck(obj___mypyc_self__, CPyType__grammar___BasicType)))
        arg___mypyc_self__ = obj___mypyc_self__;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj___mypyc_self__); 
        goto fail;
    }
    char retval = CPyDef__grammar___BasicType___is_dynamic__BasicType_glue(arg___mypyc_self__);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = retval ? Py_True : Py_False;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "is_dynamic__BasicType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___BasicType___validate(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    char cpy_r_r11;
    char cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    char cpy_r_r15;
    CPyTagged cpy_r_r16;
    int64_t cpy_r_r17;
    char cpy_r_r18;
    int64_t cpy_r_r19;
    char cpy_r_r20;
    char cpy_r_r21;
    char cpy_r_r22;
    char cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    char cpy_r_r28;
    char cpy_r_r29;
    char cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    CPyTagged cpy_r_r33;
    int64_t cpy_r_r34;
    char cpy_r_r35;
    int64_t cpy_r_r36;
    char cpy_r_r37;
    char cpy_r_r38;
    char cpy_r_r39;
    char cpy_r_r40;
    CPyTagged cpy_r_r41;
    int64_t cpy_r_r42;
    char cpy_r_r43;
    int64_t cpy_r_r44;
    char cpy_r_r45;
    char cpy_r_r46;
    char cpy_r_r47;
    char cpy_r_r48;
    PyObject *cpy_r_r49;
    PyObject *cpy_r_r50;
    CPyTagged cpy_r_r51;
    CPyTagged cpy_r_r52;
    char cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject *cpy_r_r55;
    PyObject *cpy_r_r56;
    PyObject *cpy_r_r57;
    char cpy_r_r58;
    char cpy_r_r59;
    char cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    PyObject *cpy_r_r63;
    int32_t cpy_r_r64;
    char cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject *cpy_r_r67;
    CPyTagged cpy_r_r68;
    CPyTagged cpy_r_r69;
    int64_t cpy_r_r70;
    char cpy_r_r71;
    int64_t cpy_r_r72;
    char cpy_r_r73;
    char cpy_r_r74;
    char cpy_r_r75;
    int64_t cpy_r_r76;
    char cpy_r_r77;
    int64_t cpy_r_r78;
    char cpy_r_r79;
    char cpy_r_r80;
    char cpy_r_r81;
    PyObject *cpy_r_r82;
    PyObject *cpy_r_r83;
    CPyTagged cpy_r_r84;
    char cpy_r_r85;
    PyObject *cpy_r_r86;
    PyObject *cpy_r_r87;
    int64_t cpy_r_r88;
    char cpy_r_r89;
    int64_t cpy_r_r90;
    char cpy_r_r91;
    char cpy_r_r92;
    char cpy_r_r93;
    int64_t cpy_r_r94;
    char cpy_r_r95;
    int64_t cpy_r_r96;
    char cpy_r_r97;
    char cpy_r_r98;
    char cpy_r_r99;
    PyObject *cpy_r_r100;
    PyObject *cpy_r_r101;
    PyObject *cpy_r_r102;
    PyObject *cpy_r_r103;
    PyObject *cpy_r_r104;
    PyObject *cpy_r_r105;
    char cpy_r_r106;
    char cpy_r_r107;
    PyObject *cpy_r_r108;
    PyObject *cpy_r_r109;
    PyObject *cpy_r_r110;
    char cpy_r_r111;
    PyObject *cpy_r_r112;
    char cpy_r_r113;
    PyObject *cpy_r_r114;
    PyObject *cpy_r_r115;
    char cpy_r_r116;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_base;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "validate", "BasicType", "base", 277, CPyStatic__grammar___globals);
        goto CPyL80;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_self)->_sub;
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AttributeError("faster_eth_abi/_grammar.py", "validate", "BasicType", "sub", 277, CPyStatic__grammar___globals);
        goto CPyL81;
    }
    CPy_INCREF(cpy_r_r1);
CPyL2: ;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'string' */
    cpy_r_r3 = CPyStr_Equal(cpy_r_r0, cpy_r_r2);
    if (cpy_r_r3) {
        goto CPyL82;
    } else
        goto CPyL5;
CPyL3: ;
    cpy_r_r4 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r5 = cpy_r_r1 != cpy_r_r4;
    CPy_DECREF(cpy_r_r1);
    if (!cpy_r_r5) goto CPyL79;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'string type cannot have suffix' */
    cpy_r_r7 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r6); /* invalidate */
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    } else
        goto CPyL83;
CPyL5: ;
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes' */
    cpy_r_r9 = CPyStr_Equal(cpy_r_r0, cpy_r_r8);
    if (cpy_r_r9) {
        goto CPyL84;
    } else
        goto CPyL17;
CPyL6: ;
    cpy_r_r10 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r11 = cpy_r_r1 == cpy_r_r10;
    if (cpy_r_r11) goto CPyL9;
    cpy_r_r12 = PyLong_Check(cpy_r_r1);
    if (cpy_r_r12) goto CPyL9;
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('bytes type must have either no suffix or a numerical '
                                    'suffix') */
    cpy_r_r14 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r13); /* invalidate */
    if (unlikely(cpy_r_r14 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL85;
    } else
        goto CPyL86;
CPyL9: ;
    cpy_r_r15 = PyLong_Check(cpy_r_r1);
    if (!cpy_r_r15) goto CPyL87;
    if (likely(PyLong_Check(cpy_r_r1)))
        cpy_r_r16 = CPyTagged_FromObject(cpy_r_r1);
    else {
        CPy_TypeError("int", cpy_r_r1); cpy_r_r16 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r1);
    if (unlikely(cpy_r_r16 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    }
    cpy_r_r17 = cpy_r_r16 & 1;
    cpy_r_r18 = cpy_r_r17 != 0;
    if (cpy_r_r18) goto CPyL13;
    cpy_r_r19 = 64 & 1;
    cpy_r_r20 = cpy_r_r19 != 0;
    if (!cpy_r_r20) goto CPyL14;
CPyL13: ;
    cpy_r_r21 = CPyTagged_IsLt_(64, cpy_r_r16);
    cpy_r_r22 = cpy_r_r21;
    goto CPyL15;
CPyL14: ;
    cpy_r_r23 = (Py_ssize_t)cpy_r_r16 > (Py_ssize_t)64;
    cpy_r_r22 = cpy_r_r23;
CPyL15: ;
    CPyTagged_DECREF(cpy_r_r16);
    if (!cpy_r_r22) goto CPyL79;
    cpy_r_r24 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'maximum 32 bytes for fixed-length bytes' */
    cpy_r_r25 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r24); /* invalidate */
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    } else
        goto CPyL88;
CPyL17: ;
    cpy_r_r26 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'int' */
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'uint' */
    cpy_r_r28 = CPyStr_Equal(cpy_r_r0, cpy_r_r26);
    if (cpy_r_r28) goto CPyL20;
    cpy_r_r29 = CPyStr_Equal(cpy_r_r0, cpy_r_r27);
    if (cpy_r_r29) goto CPyL20;
    if (0) {
        goto CPyL89;
    } else
        goto CPyL40;
CPyL20: ;
    if (1) {
        goto CPyL89;
    } else
        goto CPyL40;
CPyL21: ;
    cpy_r_r30 = PyLong_Check(cpy_r_r1);
    if (cpy_r_r30) goto CPyL23;
    cpy_r_r31 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'integer type must have numerical suffix' */
    cpy_r_r32 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r31); /* invalidate */
    if (unlikely(cpy_r_r32 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL85;
    } else
        goto CPyL90;
CPyL23: ;
    if (likely(PyLong_Check(cpy_r_r1)))
        cpy_r_r33 = CPyTagged_FromObject(cpy_r_r1);
    else {
        CPy_TypeError("int", cpy_r_r1); cpy_r_r33 = CPY_INT_TAG;
    }
    if (unlikely(cpy_r_r33 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL85;
    }
    cpy_r_r34 = cpy_r_r33 & 1;
    cpy_r_r35 = cpy_r_r34 != 0;
    if (cpy_r_r35) goto CPyL26;
    cpy_r_r36 = 16 & 1;
    cpy_r_r37 = cpy_r_r36 != 0;
    if (!cpy_r_r37) goto CPyL27;
CPyL26: ;
    cpy_r_r38 = CPyTagged_IsLt_(cpy_r_r33, 16);
    cpy_r_r39 = cpy_r_r38;
    goto CPyL28;
CPyL27: ;
    cpy_r_r40 = (Py_ssize_t)cpy_r_r33 < (Py_ssize_t)16;
    cpy_r_r39 = cpy_r_r40;
CPyL28: ;
    CPyTagged_DECREF(cpy_r_r33);
    if (cpy_r_r39) goto CPyL35;
    if (likely(PyLong_Check(cpy_r_r1)))
        cpy_r_r41 = CPyTagged_FromObject(cpy_r_r1);
    else {
        CPy_TypeError("int", cpy_r_r1); cpy_r_r41 = CPY_INT_TAG;
    }
    if (unlikely(cpy_r_r41 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL85;
    }
    cpy_r_r42 = cpy_r_r41 & 1;
    cpy_r_r43 = cpy_r_r42 != 0;
    if (cpy_r_r43) goto CPyL32;
    cpy_r_r44 = 512 & 1;
    cpy_r_r45 = cpy_r_r44 != 0;
    if (!cpy_r_r45) goto CPyL33;
CPyL32: ;
    cpy_r_r46 = CPyTagged_IsLt_(512, cpy_r_r41);
    cpy_r_r47 = cpy_r_r46;
    goto CPyL34;
CPyL33: ;
    cpy_r_r48 = (Py_ssize_t)cpy_r_r41 > (Py_ssize_t)512;
    cpy_r_r47 = cpy_r_r48;
CPyL34: ;
    CPyTagged_DECREF(cpy_r_r41);
    if (!cpy_r_r47) goto CPyL36;
CPyL35: ;
    cpy_r_r49 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'integer size out of bounds (max 256 bits)' */
    cpy_r_r50 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r49); /* invalidate */
    if (unlikely(cpy_r_r50 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL85;
    } else
        goto CPyL91;
CPyL36: ;
    if (likely(PyLong_Check(cpy_r_r1)))
        cpy_r_r51 = CPyTagged_FromObject(cpy_r_r1);
    else {
        CPy_TypeError("int", cpy_r_r1); cpy_r_r51 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r1);
    if (unlikely(cpy_r_r51 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    }
    cpy_r_r52 = CPyTagged_Remainder(cpy_r_r51, 16);
    CPyTagged_DECREF(cpy_r_r51);
    if (unlikely(cpy_r_r52 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    }
    cpy_r_r53 = cpy_r_r52 != 0;
    CPyTagged_DECREF(cpy_r_r52);
    if (!cpy_r_r53) goto CPyL79;
    cpy_r_r54 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'integer size must be multiple of 8' */
    cpy_r_r55 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r54); /* invalidate */
    if (unlikely(cpy_r_r55 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    } else
        goto CPyL92;
CPyL40: ;
    cpy_r_r56 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed' */
    cpy_r_r57 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ufixed' */
    cpy_r_r58 = CPyStr_Equal(cpy_r_r0, cpy_r_r56);
    if (cpy_r_r58) goto CPyL43;
    cpy_r_r59 = CPyStr_Equal(cpy_r_r0, cpy_r_r57);
    if (cpy_r_r59) goto CPyL43;
    if (0) {
        goto CPyL93;
    } else
        goto CPyL73;
CPyL43: ;
    if (1) {
        goto CPyL93;
    } else
        goto CPyL73;
CPyL44: ;
    cpy_r_r60 = PyTuple_Check(cpy_r_r1);
    if (cpy_r_r60) goto CPyL46;
    cpy_r_r61 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('fixed type must have suffix of form <bits>x<exponent>, '
                                    'e.g. 128x19') */
    cpy_r_r62 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r61); /* invalidate */
    if (unlikely(cpy_r_r62 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL85;
    } else
        goto CPyL94;
CPyL46: ;
    if (likely(PyTuple_Check(cpy_r_r1)))
        cpy_r_r63 = cpy_r_r1;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "validate", 313, CPyStatic__grammar___globals, "tuple", cpy_r_r1);
        goto CPyL80;
    }
    cpy_r_r64 = CPySequence_CheckUnpackCount(cpy_r_r63, 2);
    cpy_r_r65 = cpy_r_r64 >= 0;
    if (unlikely(!cpy_r_r65)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL95;
    }
    cpy_r_r66 = CPySequenceTuple_GetItemUnsafe(cpy_r_r63, 0);
    cpy_r_r67 = CPySequenceTuple_GetItemUnsafe(cpy_r_r63, 1);
    CPy_DECREF(cpy_r_r63);
    if (likely(PyLong_Check(cpy_r_r66)))
        cpy_r_r68 = CPyTagged_FromObject(cpy_r_r66);
    else {
        CPy_TypeError("int", cpy_r_r66); cpy_r_r68 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r66);
    if (unlikely(cpy_r_r68 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL96;
    }
    if (likely(PyLong_Check(cpy_r_r67)))
        cpy_r_r69 = CPyTagged_FromObject(cpy_r_r67);
    else {
        CPy_TypeError("int", cpy_r_r67); cpy_r_r69 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r67);
    if (unlikely(cpy_r_r69 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL97;
    }
    cpy_r_r70 = cpy_r_r68 & 1;
    cpy_r_r71 = cpy_r_r70 != 0;
    if (cpy_r_r71) goto CPyL52;
    cpy_r_r72 = 16 & 1;
    cpy_r_r73 = cpy_r_r72 != 0;
    if (!cpy_r_r73) goto CPyL53;
CPyL52: ;
    cpy_r_r74 = CPyTagged_IsLt_(cpy_r_r68, 16);
    if (cpy_r_r74) {
        goto CPyL58;
    } else
        goto CPyL54;
CPyL53: ;
    cpy_r_r75 = (Py_ssize_t)cpy_r_r68 < (Py_ssize_t)16;
    if (cpy_r_r75) goto CPyL58;
CPyL54: ;
    cpy_r_r76 = cpy_r_r68 & 1;
    cpy_r_r77 = cpy_r_r76 != 0;
    if (cpy_r_r77) goto CPyL56;
    cpy_r_r78 = 512 & 1;
    cpy_r_r79 = cpy_r_r78 != 0;
    if (!cpy_r_r79) goto CPyL57;
CPyL56: ;
    cpy_r_r80 = CPyTagged_IsLt_(512, cpy_r_r68);
    if (cpy_r_r80) {
        goto CPyL58;
    } else
        goto CPyL59;
CPyL57: ;
    cpy_r_r81 = (Py_ssize_t)cpy_r_r68 > (Py_ssize_t)512;
    if (!cpy_r_r81) goto CPyL59;
CPyL58: ;
    cpy_r_r82 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed size out of bounds (max 256 bits)' */
    cpy_r_r83 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r82); /* invalidate */
    if (unlikely(cpy_r_r83 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL98;
    } else
        goto CPyL99;
CPyL59: ;
    cpy_r_r84 = CPyTagged_Remainder(cpy_r_r68, 16);
    CPyTagged_DECREF(cpy_r_r68);
    if (unlikely(cpy_r_r84 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL100;
    }
    cpy_r_r85 = cpy_r_r84 != 0;
    CPyTagged_DECREF(cpy_r_r84);
    if (!cpy_r_r85) goto CPyL62;
    cpy_r_r86 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed size must be multiple of 8' */
    cpy_r_r87 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r86); /* invalidate */
    if (unlikely(cpy_r_r87 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL100;
    } else
        goto CPyL101;
CPyL62: ;
    cpy_r_r88 = cpy_r_r69 & 1;
    cpy_r_r89 = cpy_r_r88 != 0;
    if (cpy_r_r89) goto CPyL64;
    cpy_r_r90 = 2 & 1;
    cpy_r_r91 = cpy_r_r90 != 0;
    if (!cpy_r_r91) goto CPyL65;
CPyL64: ;
    cpy_r_r92 = CPyTagged_IsLt_(cpy_r_r69, 2);
    if (cpy_r_r92) {
        goto CPyL70;
    } else
        goto CPyL66;
CPyL65: ;
    cpy_r_r93 = (Py_ssize_t)cpy_r_r69 < (Py_ssize_t)2;
    if (cpy_r_r93) goto CPyL70;
CPyL66: ;
    cpy_r_r94 = cpy_r_r69 & 1;
    cpy_r_r95 = cpy_r_r94 != 0;
    if (cpy_r_r95) goto CPyL68;
    cpy_r_r96 = 160 & 1;
    cpy_r_r97 = cpy_r_r96 != 0;
    if (!cpy_r_r97) goto CPyL69;
CPyL68: ;
    cpy_r_r98 = CPyTagged_IsLt_(160, cpy_r_r69);
    if (cpy_r_r98) {
        goto CPyL70;
    } else
        goto CPyL102;
CPyL69: ;
    cpy_r_r99 = (Py_ssize_t)cpy_r_r69 > (Py_ssize_t)160;
    if (!cpy_r_r99) goto CPyL102;
CPyL70: ;
    cpy_r_r100 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed exponent size out of bounds, ' */
    cpy_r_r101 = CPyTagged_Str(cpy_r_r69);
    CPyTagged_DECREF(cpy_r_r69);
    if (unlikely(cpy_r_r101 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    }
    cpy_r_r102 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' must be in 1-80' */
    cpy_r_r103 = CPyStr_Build(3, cpy_r_r100, cpy_r_r101, cpy_r_r102);
    CPy_DECREF(cpy_r_r101);
    if (unlikely(cpy_r_r103 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    }
    cpy_r_r104 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r103); /* invalidate */
    CPy_DECREF(cpy_r_r103);
    if (unlikely(cpy_r_r104 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    } else
        goto CPyL103;
CPyL73: ;
    cpy_r_r105 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'hash' */
    cpy_r_r106 = CPyStr_Equal(cpy_r_r0, cpy_r_r105);
    if (cpy_r_r106) {
        goto CPyL104;
    } else
        goto CPyL76;
CPyL74: ;
    cpy_r_r107 = PyLong_Check(cpy_r_r1);
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r107) goto CPyL79;
    cpy_r_r108 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'hash type must have numerical suffix' */
    cpy_r_r109 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r108); /* invalidate */
    if (unlikely(cpy_r_r109 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    } else
        goto CPyL105;
CPyL76: ;
    cpy_r_r110 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'address' */
    cpy_r_r111 = CPyStr_Equal(cpy_r_r0, cpy_r_r110);
    CPy_DECREF(cpy_r_r0);
    if (!cpy_r_r111) goto CPyL87;
    cpy_r_r112 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r113 = cpy_r_r1 != cpy_r_r112;
    CPy_DECREF(cpy_r_r1);
    if (!cpy_r_r113) goto CPyL79;
    cpy_r_r114 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'address cannot have suffix' */
    cpy_r_r115 = CPY_GET_METHOD(cpy_r_self, CPyType__grammar___BasicType, 6, faster_eth_abi____grammar___BasicTypeObject, PyObject * (*)(PyObject *, PyObject *))(cpy_r_self, cpy_r_r114); /* invalidate */
    if (unlikely(cpy_r_r115 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL80;
    } else
        goto CPyL106;
CPyL79: ;
    return 1;
CPyL80: ;
    cpy_r_r116 = 2;
    return cpy_r_r116;
CPyL81: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL80;
CPyL82: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL3;
CPyL83: ;
    CPy_DECREF(cpy_r_r7);
    goto CPyL79;
CPyL84: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL6;
CPyL85: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL80;
CPyL86: ;
    CPy_DECREF(cpy_r_r14);
    goto CPyL9;
CPyL87: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL79;
CPyL88: ;
    CPy_DECREF(cpy_r_r25);
    goto CPyL79;
CPyL89: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL21;
CPyL90: ;
    CPy_DECREF(cpy_r_r32);
    goto CPyL23;
CPyL91: ;
    CPy_DECREF(cpy_r_r50);
    goto CPyL36;
CPyL92: ;
    CPy_DECREF(cpy_r_r55);
    goto CPyL79;
CPyL93: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL44;
CPyL94: ;
    CPy_DECREF(cpy_r_r62);
    goto CPyL46;
CPyL95: ;
    CPy_DecRef(cpy_r_r63);
    goto CPyL80;
CPyL96: ;
    CPy_DecRef(cpy_r_r67);
    goto CPyL80;
CPyL97: ;
    CPyTagged_DecRef(cpy_r_r68);
    goto CPyL80;
CPyL98: ;
    CPyTagged_DecRef(cpy_r_r68);
    CPyTagged_DecRef(cpy_r_r69);
    goto CPyL80;
CPyL99: ;
    CPy_DECREF(cpy_r_r83);
    goto CPyL59;
CPyL100: ;
    CPyTagged_DecRef(cpy_r_r69);
    goto CPyL80;
CPyL101: ;
    CPy_DECREF(cpy_r_r87);
    goto CPyL62;
CPyL102: ;
    CPyTagged_DECREF(cpy_r_r69);
    goto CPyL79;
CPyL103: ;
    CPy_DECREF(cpy_r_r104);
    goto CPyL79;
CPyL104: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL74;
CPyL105: ;
    CPy_DECREF(cpy_r_r109);
    goto CPyL79;
CPyL106: ;
    CPy_DECREF(cpy_r_r115);
    goto CPyL79;
}

PyObject *CPyPy__grammar___BasicType___validate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":validate", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___BasicType___validate(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar___BasicType___validate__BasicType_glue(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject **cpy_r_r2;
    PyObject *cpy_r_r3;
    char cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'validate' */
    PyObject *cpy_r_r1[1] = {cpy_r_self};
    cpy_r_r2 = (PyObject **)&cpy_r_r1;
    cpy_r_r3 = PyObject_VectorcallMethod(cpy_r_r0, cpy_r_r2, 9223372036854775809ULL, 0);
    if (cpy_r_r3 == NULL) goto CPyL3;
    if (unlikely(cpy_r_r3 != Py_None)) {
        CPy_TypeError("None", cpy_r_r3); cpy_r_r4 = 2;
    } else
        cpy_r_r4 = 1;
    CPy_DECREF(cpy_r_r3);
    if (cpy_r_r4 == 2) goto CPyL3;
    return cpy_r_r4;
CPyL3: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
}

PyObject *CPyPy__grammar___BasicType___validate__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    static CPyArg_Parser parser = {":validate__BasicType_glue", kwlist, 0};
    if (!CPyArg_ParseStackAndKeywordsNoArgs(args, nargs, kwnames, &parser)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(PyObject_TypeCheck(obj_self, CPyType__grammar___BasicType)))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_self); 
        goto fail;
    }
    char retval = CPyDef__grammar___BasicType___validate__BasicType_glue(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "validate__BasicType_glue", -1, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar___normalize(PyObject *cpy_r_type_str) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject **cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    cpy_r_r0 = CPyStatic__grammar___TYPE_ALIAS_RE;
    if (likely(cpy_r_r0 != NULL)) goto CPyL3;
    PyErr_SetString(PyExc_NameError, "value for final name \"TYPE_ALIAS_RE\" was not set");
    cpy_r_r1 = 0;
    if (unlikely(!cpy_r_r1)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL7;
    }
    CPy_Unreachable();
CPyL3: ;
    cpy_r_r2 = CPyStatic__grammar___globals;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__normalize' */
    cpy_r_r4 = CPyDict_GetItem(cpy_r_r2, cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL7;
    }
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'sub' */
    PyObject *cpy_r_r6[3] = {cpy_r_r0, cpy_r_r4, cpy_r_type_str};
    cpy_r_r7 = (PyObject **)&cpy_r_r6;
    cpy_r_r8 = PyObject_VectorcallMethod(cpy_r_r5, cpy_r_r7, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    CPy_DECREF(cpy_r_r4);
    if (likely(PyUnicode_Check(cpy_r_r8)))
        cpy_r_r9 = cpy_r_r8;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "normalize", 345, CPyStatic__grammar___globals, "str", cpy_r_r8);
        goto CPyL7;
    }
    return cpy_r_r9;
CPyL7: ;
    cpy_r_r10 = NULL;
    return cpy_r_r10;
CPyL8: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL7;
}

PyObject *CPyPy__grammar___normalize(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"type_str", 0};
    static CPyArg_Parser parser = {"O:normalize", kwlist, 0};
    PyObject *obj_type_str;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_type_str)) {
        return NULL;
    }
    PyObject *arg_type_str;
    if (likely(PyUnicode_Check(obj_type_str)))
        arg_type_str = obj_type_str;
    else {
        CPy_TypeError("str", obj_type_str); 
        goto fail;
    }
    PyObject *retval = CPyDef__grammar___normalize(arg_type_str);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

PyObject *CPyDef__grammar_____normalize(PyObject *cpy_r_match) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    cpy_r_r0 = CPyStatic__grammar___TYPE_ALIASES;
    if (likely(cpy_r_r0 != NULL)) goto CPyL3;
    PyErr_SetString(PyExc_NameError, "value for final name \"TYPE_ALIASES\" was not set");
    cpy_r_r1 = 0;
    if (unlikely(!cpy_r_r1)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    CPy_Unreachable();
CPyL3: ;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'group' */
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    PyObject *cpy_r_r4[2] = {cpy_r_match, cpy_r_r3};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_VectorcallMethod(cpy_r_r2, cpy_r_r5, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    if (likely(PyUnicode_Check(cpy_r_r6)))
        cpy_r_r7 = cpy_r_r6;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "__normalize", 349, CPyStatic__grammar___globals, "str", cpy_r_r6);
        goto CPyL8;
    }
    cpy_r_r8 = CPyDict_GetItem(cpy_r_r0, cpy_r_r7);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "__normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL8;
    }
    if (likely(PyUnicode_Check(cpy_r_r8)))
        cpy_r_r9 = cpy_r_r8;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/_grammar.py", "__normalize", 349, CPyStatic__grammar___globals, "str", cpy_r_r8);
        goto CPyL8;
    }
    return cpy_r_r9;
CPyL8: ;
    cpy_r_r10 = NULL;
    return cpy_r_r10;
}

PyObject *CPyPy__grammar_____normalize(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"match", 0};
    static CPyArg_Parser parser = {"O:__normalize", kwlist, 0};
    PyObject *obj_match;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_match)) {
        return NULL;
    }
    PyObject *arg_match = obj_match;
    PyObject *retval = CPyDef__grammar_____normalize(arg_match);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/_grammar.py", "__normalize", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
    return NULL;
}

char CPyDef__grammar_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject **cpy_r_r5;
    void *cpy_r_r7;
    void *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    char cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject *cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject *cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject *cpy_r_r46;
    PyObject *cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject *cpy_r_r49;
    PyObject *cpy_r_r50;
    PyObject *cpy_r_r51;
    PyObject *cpy_r_r52;
    PyObject *cpy_r_r53;
    int32_t cpy_r_r54;
    char cpy_r_r55;
    PyObject *cpy_r_r56;
    PyObject *cpy_r_r57;
    PyObject *cpy_r_r58;
    PyObject *cpy_r_r59;
    PyObject *cpy_r_r60;
    PyObject *cpy_r_r61;
    char cpy_r_r62;
    PyObject *cpy_r_r63;
    PyObject *cpy_r_r64;
    PyObject *cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject **cpy_r_r68;
    PyObject *cpy_r_r69;
    PyObject *cpy_r_r70;
    PyObject *cpy_r_r71;
    PyObject *cpy_r_r72;
    PyObject *cpy_r_r73;
    PyObject *cpy_r_r74;
    PyObject *cpy_r_r75;
    PyObject **cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    PyObject *cpy_r_r80;
    int32_t cpy_r_r81;
    char cpy_r_r82;
    PyObject *cpy_r_r83;
    PyObject *cpy_r_r84;
    PyObject *cpy_r_r85;
    PyObject *cpy_r_r86;
    PyObject *cpy_r_r87;
    PyObject **cpy_r_r89;
    PyObject *cpy_r_r90;
    PyObject *cpy_r_r91;
    PyObject *cpy_r_r92;
    int32_t cpy_r_r93;
    char cpy_r_r94;
    PyObject *cpy_r_r95;
    PyObject *cpy_r_r96;
    PyObject *cpy_r_r97;
    PyObject *cpy_r_r98;
    PyObject *cpy_r_r99;
    PyObject *cpy_r_r100;
    tuple_T2OO cpy_r_r101;
    PyObject *cpy_r_r102;
    PyObject *cpy_r_r103;
    PyObject *cpy_r_r104;
    PyObject *cpy_r_r105;
    PyObject *cpy_r_r106;
    PyObject **cpy_r_r108;
    PyObject *cpy_r_r109;
    PyObject *cpy_r_r110;
    PyObject *cpy_r_r111;
    int32_t cpy_r_r112;
    char cpy_r_r113;
    PyObject *cpy_r_r114;
    PyObject *cpy_r_r115;
    PyObject *cpy_r_r116;
    PyObject *cpy_r_r117;
    PyObject *cpy_r_r118;
    PyObject *cpy_r_r119;
    PyObject *cpy_r_r120;
    PyObject *cpy_r_r121;
    PyObject *cpy_r_r122;
    tuple_T2OO cpy_r_r123;
    PyObject *cpy_r_r124;
    PyObject *cpy_r_r125;
    PyObject *cpy_r_r126;
    PyObject *cpy_r_r127;
    int32_t cpy_r_r128;
    char cpy_r_r129;
    PyObject *cpy_r_r130;
    PyObject *cpy_r_r131;
    PyObject *cpy_r_r132;
    PyObject *cpy_r_r133;
    char cpy_r_r134;
    PyObject *cpy_r_r135;
    PyObject *cpy_r_r136;
    PyObject *cpy_r_r137;
    PyObject *cpy_r_r138;
    int32_t cpy_r_r139;
    char cpy_r_r140;
    PyObject *cpy_r_r141;
    PyObject *cpy_r_r142;
    int32_t cpy_r_r143;
    char cpy_r_r144;
    PyObject *cpy_r_r145;
    PyObject *cpy_r_r146;
    PyObject *cpy_r_r147;
    PyObject *cpy_r_r148;
    PyObject *cpy_r_r149;
    PyObject **cpy_r_r151;
    PyObject *cpy_r_r152;
    PyObject *cpy_r_r153;
    PyObject *cpy_r_r154;
    PyObject *cpy_r_r155;
    int32_t cpy_r_r156;
    char cpy_r_r157;
    PyObject *cpy_r_r158;
    PyObject *cpy_r_r159;
    PyObject *cpy_r_r160;
    PyObject *cpy_r_r161;
    PyObject *cpy_r_r162;
    char cpy_r_r163;
    PyObject *cpy_r_r164;
    PyObject *cpy_r_r165;
    PyObject *cpy_r_r166;
    PyObject *cpy_r_r167;
    PyObject *cpy_r_r168;
    int32_t cpy_r_r169;
    char cpy_r_r170;
    PyObject *cpy_r_r171;
    PyObject *cpy_r_r172;
    int32_t cpy_r_r173;
    char cpy_r_r174;
    PyObject *cpy_r_r175;
    PyObject *cpy_r_r176;
    PyObject *cpy_r_r177;
    PyObject *cpy_r_r178;
    PyObject *cpy_r_r179;
    char cpy_r_r180;
    PyObject *cpy_r_r181;
    PyObject *cpy_r_r182;
    PyObject *cpy_r_r183;
    PyObject *cpy_r_r184;
    PyObject *cpy_r_r185;
    PyObject *cpy_r_r186;
    int32_t cpy_r_r187;
    char cpy_r_r188;
    PyObject *cpy_r_r189;
    PyObject *cpy_r_r190;
    int32_t cpy_r_r191;
    char cpy_r_r192;
    char cpy_r_r193;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", -1, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = (PyObject **)&CPyModule_re;
    PyObject **cpy_r_r6[1] = {cpy_r_r5};
    cpy_r_r7 = (void *)&cpy_r_r6;
    int64_t cpy_r_r8[1] = {1};
    cpy_r_r9 = (void *)&cpy_r_r8;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* (('re', 're', 're'),) */
    cpy_r_r11 = CPyStatic__grammar___globals;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi/_grammar.py' */
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '<module>' */
    cpy_r_r14 = CPyImport_ImportMany(cpy_r_r10, cpy_r_r7, cpy_r_r11, cpy_r_r12, cpy_r_r13, cpy_r_r9);
    if (!cpy_r_r14) goto CPyL58;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Any', 'Final', 'NewType', 'NoReturn', 'Optional',
                                    'Sequence', 'Tuple', 'TypeVar', 'Union', 'final') */
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r17 = CPyStatic__grammar___globals;
    cpy_r_r18 = CPyImport_ImportFromMany(cpy_r_r16, cpy_r_r15, cpy_r_r15, cpy_r_r17);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_typing = cpy_r_r18;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r18);
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TypeStr',) */
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'eth_typing.abi' */
    cpy_r_r21 = CPyStatic__grammar___globals;
    cpy_r_r22 = CPyImport_ImportFromMany(cpy_r_r20, cpy_r_r19, cpy_r_r19, cpy_r_r21);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_eth_typing___abi = cpy_r_r22;
    CPy_INCREF(CPyModule_eth_typing___abi);
    CPy_DECREF(cpy_r_r22);
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('mypyc_attr',) */
    cpy_r_r24 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'mypy_extensions' */
    cpy_r_r25 = CPyStatic__grammar___globals;
    cpy_r_r26 = CPyImport_ImportFromMany(cpy_r_r24, cpy_r_r23, cpy_r_r23, cpy_r_r25);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_mypy_extensions = cpy_r_r26;
    CPy_INCREF(CPyModule_mypy_extensions);
    CPy_DECREF(cpy_r_r26);
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Node',) */
    cpy_r_r28 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'parsimonious.nodes' */
    cpy_r_r29 = CPyStatic__grammar___globals;
    cpy_r_r30 = CPyImport_ImportFromMany(cpy_r_r28, cpy_r_r27, cpy_r_r27, cpy_r_r29);
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_parsimonious___nodes = cpy_r_r30;
    CPy_INCREF(CPyModule_parsimonious___nodes);
    CPy_DECREF(cpy_r_r30);
    cpy_r_r31 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Self',) */
    cpy_r_r32 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing_extensions' */
    cpy_r_r33 = CPyStatic__grammar___globals;
    cpy_r_r34 = CPyImport_ImportFromMany(cpy_r_r32, cpy_r_r31, cpy_r_r31, cpy_r_r33);
    if (unlikely(cpy_r_r34 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_typing_extensions = cpy_r_r34;
    CPy_INCREF(CPyModule_typing_extensions);
    CPy_DECREF(cpy_r_r34);
    cpy_r_r35 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('ABITypeError',) */
    cpy_r_r36 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.exceptions' */
    cpy_r_r37 = CPyStatic__grammar___globals;
    cpy_r_r38 = CPyImport_ImportFromMany(cpy_r_r36, cpy_r_r35, cpy_r_r35, cpy_r_r37);
    if (unlikely(cpy_r_r38 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyModule_faster_eth_abi___exceptions = cpy_r_r38;
    CPy_INCREF(CPyModule_faster_eth_abi___exceptions);
    CPy_DECREF(cpy_r_r38);
    cpy_r_r39 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'int' */
    cpy_r_r40 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'int256' */
    cpy_r_r41 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'uint' */
    cpy_r_r42 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'uint256' */
    cpy_r_r43 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed' */
    cpy_r_r44 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed128x18' */
    cpy_r_r45 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ufixed' */
    cpy_r_r46 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ufixed128x18' */
    cpy_r_r47 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'function' */
    cpy_r_r48 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes24' */
    cpy_r_r49 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'byte' */
    cpy_r_r50 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes1' */
    cpy_r_r51 = CPyDict_Build(6, cpy_r_r39, cpy_r_r40, cpy_r_r41, cpy_r_r42, cpy_r_r43, cpy_r_r44, cpy_r_r45, cpy_r_r46, cpy_r_r47, cpy_r_r48, cpy_r_r49, cpy_r_r50);
    if (unlikely(cpy_r_r51 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPyStatic__grammar___TYPE_ALIASES = cpy_r_r51;
    CPy_INCREF(CPyStatic__grammar___TYPE_ALIASES);
    cpy_r_r52 = CPyStatic__grammar___globals;
    cpy_r_r53 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TYPE_ALIASES' */
    cpy_r_r54 = CPyDict_SetItem(cpy_r_r52, cpy_r_r53, cpy_r_r51);
    CPy_DECREF(cpy_r_r51);
    cpy_r_r55 = cpy_r_r54 >= 0;
    if (unlikely(!cpy_r_r55)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r56 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '\\b(' */
    cpy_r_r57 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '|' */
    cpy_r_r58 = CPyModule_re;
    cpy_r_r59 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'escape' */
    cpy_r_r60 = CPyObject_GetAttr(cpy_r_r58, cpy_r_r59);
    if (unlikely(cpy_r_r60 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r61 = CPyStatic__grammar___TYPE_ALIASES;
    if (unlikely(cpy_r_r61 == NULL)) {
        goto CPyL59;
    } else
        goto CPyL16;
CPyL14: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"TYPE_ALIASES\" was not set");
    cpy_r_r62 = 0;
    if (unlikely(!cpy_r_r62)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    CPy_Unreachable();
CPyL16: ;
    cpy_r_r63 = CPyDict_KeysView(cpy_r_r61);
    if (unlikely(cpy_r_r63 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL60;
    }
    cpy_r_r64 = CPyModule_builtins;
    cpy_r_r65 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    cpy_r_r66 = CPyObject_GetAttr(cpy_r_r64, cpy_r_r65);
    if (unlikely(cpy_r_r66 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL61;
    }
    PyObject *cpy_r_r67[2] = {cpy_r_r60, cpy_r_r63};
    cpy_r_r68 = (PyObject **)&cpy_r_r67;
    cpy_r_r69 = PyObject_Vectorcall(cpy_r_r66, cpy_r_r68, 2, 0);
    CPy_DECREF(cpy_r_r66);
    if (unlikely(cpy_r_r69 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL61;
    }
    CPy_DECREF(cpy_r_r60);
    CPy_DECREF(cpy_r_r63);
    cpy_r_r70 = PyUnicode_Join(cpy_r_r57, cpy_r_r69);
    CPy_DECREF(cpy_r_r69);
    if (unlikely(cpy_r_r70 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r71 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ')\\b' */
    cpy_r_r72 = CPyStr_Build(3, cpy_r_r56, cpy_r_r70, cpy_r_r71);
    CPy_DECREF(cpy_r_r70);
    if (unlikely(cpy_r_r72 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r73 = CPyModule_re;
    cpy_r_r74 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'compile' */
    cpy_r_r75 = CPyObject_GetAttr(cpy_r_r73, cpy_r_r74);
    if (unlikely(cpy_r_r75 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL62;
    }
    PyObject *cpy_r_r76[1] = {cpy_r_r72};
    cpy_r_r77 = (PyObject **)&cpy_r_r76;
    cpy_r_r78 = PyObject_Vectorcall(cpy_r_r75, cpy_r_r77, 1, 0);
    CPy_DECREF(cpy_r_r75);
    if (unlikely(cpy_r_r78 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL62;
    }
    CPy_DECREF(cpy_r_r72);
    CPyStatic__grammar___TYPE_ALIAS_RE = cpy_r_r78;
    CPy_INCREF(CPyStatic__grammar___TYPE_ALIAS_RE);
    cpy_r_r79 = CPyStatic__grammar___globals;
    cpy_r_r80 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TYPE_ALIAS_RE' */
    cpy_r_r81 = CPyDict_SetItem(cpy_r_r79, cpy_r_r80, cpy_r_r78);
    CPy_DECREF(cpy_r_r78);
    cpy_r_r82 = cpy_r_r81 >= 0;
    if (unlikely(!cpy_r_r82)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r83 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'IntSubtype' */
    cpy_r_r84 = (PyObject *)&PyLong_Type;
    cpy_r_r85 = CPyStatic__grammar___globals;
    cpy_r_r86 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NewType' */
    cpy_r_r87 = CPyDict_GetItem(cpy_r_r85, cpy_r_r86);
    if (unlikely(cpy_r_r87 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    PyObject *cpy_r_r88[2] = {cpy_r_r83, cpy_r_r84};
    cpy_r_r89 = (PyObject **)&cpy_r_r88;
    cpy_r_r90 = PyObject_Vectorcall(cpy_r_r87, cpy_r_r89, 2, 0);
    CPy_DECREF(cpy_r_r87);
    if (unlikely(cpy_r_r90 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r91 = CPyStatic__grammar___globals;
    cpy_r_r92 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'IntSubtype' */
    cpy_r_r93 = CPyDict_SetItem(cpy_r_r91, cpy_r_r92, cpy_r_r90);
    CPy_DECREF(cpy_r_r90);
    cpy_r_r94 = cpy_r_r93 >= 0;
    if (unlikely(!cpy_r_r94)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r95 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'FixedSubtype' */
    cpy_r_r96 = CPyStatic__grammar___globals;
    cpy_r_r97 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Tuple' */
    cpy_r_r98 = CPyDict_GetItem(cpy_r_r96, cpy_r_r97);
    if (unlikely(cpy_r_r98 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r99 = (PyObject *)&PyLong_Type;
    cpy_r_r100 = (PyObject *)&PyLong_Type;
    CPy_INCREF(cpy_r_r99);
    CPy_INCREF(cpy_r_r100);
    cpy_r_r101.f0 = cpy_r_r99;
    cpy_r_r101.f1 = cpy_r_r100;
    cpy_r_r102 = PyTuple_New(2);
    if (unlikely(cpy_r_r102 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp25 = cpy_r_r101.f0;
    PyTuple_SET_ITEM(cpy_r_r102, 0, __tmp25);
    PyObject *__tmp26 = cpy_r_r101.f1;
    PyTuple_SET_ITEM(cpy_r_r102, 1, __tmp26);
    cpy_r_r103 = PyObject_GetItem(cpy_r_r98, cpy_r_r102);
    CPy_DECREF(cpy_r_r98);
    CPy_DECREF(cpy_r_r102);
    if (unlikely(cpy_r_r103 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r104 = CPyStatic__grammar___globals;
    cpy_r_r105 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NewType' */
    cpy_r_r106 = CPyDict_GetItem(cpy_r_r104, cpy_r_r105);
    if (unlikely(cpy_r_r106 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL63;
    }
    PyObject *cpy_r_r107[2] = {cpy_r_r95, cpy_r_r103};
    cpy_r_r108 = (PyObject **)&cpy_r_r107;
    cpy_r_r109 = PyObject_Vectorcall(cpy_r_r106, cpy_r_r108, 2, 0);
    CPy_DECREF(cpy_r_r106);
    if (unlikely(cpy_r_r109 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL63;
    }
    CPy_DECREF(cpy_r_r103);
    cpy_r_r110 = CPyStatic__grammar___globals;
    cpy_r_r111 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'FixedSubtype' */
    cpy_r_r112 = CPyDict_SetItem(cpy_r_r110, cpy_r_r111, cpy_r_r109);
    CPy_DECREF(cpy_r_r109);
    cpy_r_r113 = cpy_r_r112 >= 0;
    if (unlikely(!cpy_r_r113)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r114 = CPyStatic__grammar___globals;
    cpy_r_r115 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Union' */
    cpy_r_r116 = CPyDict_GetItem(cpy_r_r114, cpy_r_r115);
    if (unlikely(cpy_r_r116 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r117 = CPyStatic__grammar___globals;
    cpy_r_r118 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'IntSubtype' */
    cpy_r_r119 = CPyDict_GetItem(cpy_r_r117, cpy_r_r118);
    if (unlikely(cpy_r_r119 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL64;
    }
    cpy_r_r120 = CPyStatic__grammar___globals;
    cpy_r_r121 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'FixedSubtype' */
    cpy_r_r122 = CPyDict_GetItem(cpy_r_r120, cpy_r_r121);
    if (unlikely(cpy_r_r122 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL65;
    }
    cpy_r_r123.f0 = cpy_r_r119;
    cpy_r_r123.f1 = cpy_r_r122;
    cpy_r_r124 = PyTuple_New(2);
    if (unlikely(cpy_r_r124 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp27 = cpy_r_r123.f0;
    PyTuple_SET_ITEM(cpy_r_r124, 0, __tmp27);
    PyObject *__tmp28 = cpy_r_r123.f1;
    PyTuple_SET_ITEM(cpy_r_r124, 1, __tmp28);
    cpy_r_r125 = PyObject_GetItem(cpy_r_r116, cpy_r_r124);
    CPy_DECREF(cpy_r_r116);
    CPy_DECREF(cpy_r_r124);
    if (unlikely(cpy_r_r125 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r126 = CPyStatic__grammar___globals;
    cpy_r_r127 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Subtype' */
    cpy_r_r128 = CPyDict_SetItem(cpy_r_r126, cpy_r_r127, cpy_r_r125);
    CPy_DECREF(cpy_r_r125);
    cpy_r_r129 = cpy_r_r128 >= 0;
    if (unlikely(!cpy_r_r129)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r130 = NULL;
    cpy_r_r131 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi._grammar' */
    cpy_r_r132 = (PyObject *)CPyType__grammar___ABIType_template;
    cpy_r_r133 = CPyType_FromTemplate(cpy_r_r132, cpy_r_r130, cpy_r_r131);
    if (unlikely(cpy_r_r133 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r134 = CPyDef__grammar___ABIType_trait_vtable_setup();
    if (unlikely(cpy_r_r134 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", -1, CPyStatic__grammar___globals);
        goto CPyL66;
    }
    cpy_r_r135 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__mypyc_attrs__' */
    cpy_r_r136 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'arrlist' */
    cpy_r_r137 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'node' */
    cpy_r_r138 = PyTuple_Pack(2, cpy_r_r136, cpy_r_r137);
    if (unlikely(cpy_r_r138 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL66;
    }
    cpy_r_r139 = PyObject_SetAttr(cpy_r_r133, cpy_r_r135, cpy_r_r138);
    CPy_DECREF(cpy_r_r138);
    cpy_r_r140 = cpy_r_r139 >= 0;
    if (unlikely(!cpy_r_r140)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL66;
    }
    CPyType__grammar___ABIType = (PyTypeObject *)cpy_r_r133;
    CPy_INCREF(CPyType__grammar___ABIType);
    cpy_r_r141 = CPyStatic__grammar___globals;
    cpy_r_r142 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ABIType' */
    cpy_r_r143 = PyDict_SetItem(cpy_r_r141, cpy_r_r142, cpy_r_r133);
    CPy_DECREF(cpy_r_r133);
    cpy_r_r144 = cpy_r_r143 >= 0;
    if (unlikely(!cpy_r_r144)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r145 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TComp' */
    cpy_r_r146 = (PyObject *)CPyType__grammar___ABIType;
    cpy_r_r147 = CPyStatic__grammar___globals;
    cpy_r_r148 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TypeVar' */
    cpy_r_r149 = CPyDict_GetItem(cpy_r_r147, cpy_r_r148);
    if (unlikely(cpy_r_r149 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    PyObject *cpy_r_r150[2] = {cpy_r_r145, cpy_r_r146};
    cpy_r_r151 = (PyObject **)&cpy_r_r150;
    cpy_r_r152 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('bound',) */
    cpy_r_r153 = PyObject_Vectorcall(cpy_r_r149, cpy_r_r151, 1, cpy_r_r152);
    CPy_DECREF(cpy_r_r149);
    if (unlikely(cpy_r_r153 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r154 = CPyStatic__grammar___globals;
    cpy_r_r155 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TComp' */
    cpy_r_r156 = CPyDict_SetItem(cpy_r_r154, cpy_r_r155, cpy_r_r153);
    CPy_DECREF(cpy_r_r153);
    cpy_r_r157 = cpy_r_r156 >= 0;
    if (unlikely(!cpy_r_r157)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r158 = (PyObject *)CPyType__grammar___ABIType;
    cpy_r_r159 = PyTuple_Pack(1, cpy_r_r158);
    if (unlikely(cpy_r_r159 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r160 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi._grammar' */
    cpy_r_r161 = (PyObject *)CPyType__grammar___TupleType_template;
    cpy_r_r162 = CPyType_FromTemplate(cpy_r_r161, cpy_r_r159, cpy_r_r160);
    CPy_DECREF(cpy_r_r159);
    if (unlikely(cpy_r_r162 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r163 = CPyDef__grammar___TupleType_trait_vtable_setup();
    if (unlikely(cpy_r_r163 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", -1, CPyStatic__grammar___globals);
        goto CPyL67;
    }
    cpy_r_r164 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__mypyc_attrs__' */
    cpy_r_r165 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'components' */
    cpy_r_r166 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'arrlist' */
    cpy_r_r167 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'node' */
    cpy_r_r168 = PyTuple_Pack(3, cpy_r_r165, cpy_r_r166, cpy_r_r167);
    if (unlikely(cpy_r_r168 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL67;
    }
    cpy_r_r169 = PyObject_SetAttr(cpy_r_r162, cpy_r_r164, cpy_r_r168);
    CPy_DECREF(cpy_r_r168);
    cpy_r_r170 = cpy_r_r169 >= 0;
    if (unlikely(!cpy_r_r170)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL67;
    }
    CPyType__grammar___TupleType = (PyTypeObject *)cpy_r_r162;
    CPy_INCREF(CPyType__grammar___TupleType);
    cpy_r_r171 = CPyStatic__grammar___globals;
    cpy_r_r172 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TupleType' */
    cpy_r_r173 = PyDict_SetItem(cpy_r_r171, cpy_r_r172, cpy_r_r162);
    CPy_DECREF(cpy_r_r162);
    cpy_r_r174 = cpy_r_r173 >= 0;
    if (unlikely(!cpy_r_r174)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r175 = (PyObject *)CPyType__grammar___ABIType;
    cpy_r_r176 = PyTuple_Pack(1, cpy_r_r175);
    if (unlikely(cpy_r_r176 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r177 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi._grammar' */
    cpy_r_r178 = (PyObject *)CPyType__grammar___BasicType_template;
    cpy_r_r179 = CPyType_FromTemplate(cpy_r_r178, cpy_r_r176, cpy_r_r177);
    CPy_DECREF(cpy_r_r176);
    if (unlikely(cpy_r_r179 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    cpy_r_r180 = CPyDef__grammar___BasicType_trait_vtable_setup();
    if (unlikely(cpy_r_r180 == 2)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", -1, CPyStatic__grammar___globals);
        goto CPyL68;
    }
    cpy_r_r181 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__mypyc_attrs__' */
    cpy_r_r182 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'base' */
    cpy_r_r183 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'sub' */
    cpy_r_r184 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'arrlist' */
    cpy_r_r185 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'node' */
    cpy_r_r186 = PyTuple_Pack(4, cpy_r_r182, cpy_r_r183, cpy_r_r184, cpy_r_r185);
    if (unlikely(cpy_r_r186 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL68;
    }
    cpy_r_r187 = PyObject_SetAttr(cpy_r_r179, cpy_r_r181, cpy_r_r186);
    CPy_DECREF(cpy_r_r186);
    cpy_r_r188 = cpy_r_r187 >= 0;
    if (unlikely(!cpy_r_r188)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL68;
    }
    CPyType__grammar___BasicType = (PyTypeObject *)cpy_r_r179;
    CPy_INCREF(CPyType__grammar___BasicType);
    cpy_r_r189 = CPyStatic__grammar___globals;
    cpy_r_r190 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BasicType' */
    cpy_r_r191 = PyDict_SetItem(cpy_r_r189, cpy_r_r190, cpy_r_r179);
    CPy_DECREF(cpy_r_r179);
    cpy_r_r192 = cpy_r_r191 >= 0;
    if (unlikely(!cpy_r_r192)) {
        CPy_AddTraceback("faster_eth_abi/_grammar.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__grammar___globals);
        goto CPyL58;
    }
    return 1;
CPyL58: ;
    cpy_r_r193 = 2;
    return cpy_r_r193;
CPyL59: ;
    CPy_DecRef(cpy_r_r60);
    goto CPyL14;
CPyL60: ;
    CPy_DecRef(cpy_r_r60);
    goto CPyL58;
CPyL61: ;
    CPy_DecRef(cpy_r_r60);
    CPy_DecRef(cpy_r_r63);
    goto CPyL58;
CPyL62: ;
    CPy_DecRef(cpy_r_r72);
    goto CPyL58;
CPyL63: ;
    CPy_DecRef(cpy_r_r103);
    goto CPyL58;
CPyL64: ;
    CPy_DecRef(cpy_r_r116);
    goto CPyL58;
CPyL65: ;
    CPy_DecRef(cpy_r_r116);
    CPy_DecRef(cpy_r_r119);
    goto CPyL58;
CPyL66: ;
    CPy_DecRef(cpy_r_r133);
    goto CPyL58;
CPyL67: ;
    CPy_DecRef(cpy_r_r162);
    goto CPyL58;
CPyL68: ;
    CPy_DecRef(cpy_r_r179);
    goto CPyL58;
}
static PyMethodDef abimodule_methods[] = {
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___abi(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___abi__internal, "__name__");
    CPyStatic_abi___globals = PyModule_GetDict(CPyModule_faster_eth_abi___abi__internal);
    if (unlikely(CPyStatic_abi___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_abi_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___abi__internal);
    Py_CLEAR(modname);
    CPy_XDECREF(CPyStatic_abi___default_codec);
    CPyStatic_abi___default_codec = NULL;
    CPy_XDECREF(CPyStatic_abi___encode);
    CPyStatic_abi___encode = NULL;
    CPy_XDECREF(CPyStatic_abi___decode);
    CPyStatic_abi___decode = NULL;
    CPy_XDECREF(CPyStatic_abi___is_encodable);
    CPyStatic_abi___is_encodable = NULL;
    CPy_XDECREF(CPyStatic_abi___is_encodable_type);
    CPyStatic_abi___is_encodable_type = NULL;
    return -1;
}
static struct PyModuleDef abimodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.abi",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    abimodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___abi(void)
{
    if (CPyModule_faster_eth_abi___abi__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___abi__internal);
        return CPyModule_faster_eth_abi___abi__internal;
    }
    CPyModule_faster_eth_abi___abi__internal = PyModule_Create(&abimodule);
    if (unlikely(CPyModule_faster_eth_abi___abi__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___abi(CPyModule_faster_eth_abi___abi__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___abi__internal;
    fail:
    return NULL;
}

char CPyDef_abi_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject **cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    int32_t cpy_r_r28;
    char cpy_r_r29;
    PyObject *cpy_r_r30;
    char cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    int32_t cpy_r_r36;
    char cpy_r_r37;
    PyObject *cpy_r_r38;
    char cpy_r_r39;
    PyObject *cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    int32_t cpy_r_r44;
    char cpy_r_r45;
    PyObject *cpy_r_r46;
    char cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject *cpy_r_r49;
    PyObject *cpy_r_r50;
    PyObject *cpy_r_r51;
    int32_t cpy_r_r52;
    char cpy_r_r53;
    PyObject *cpy_r_r54;
    char cpy_r_r55;
    PyObject *cpy_r_r56;
    PyObject *cpy_r_r57;
    PyObject *cpy_r_r58;
    PyObject *cpy_r_r59;
    int32_t cpy_r_r60;
    char cpy_r_r61;
    char cpy_r_r62;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", -1, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Final',) */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic_abi___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('ABICodec',) */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.codec' */
    cpy_r_r11 = CPyStatic_abi___globals;
    cpy_r_r12 = CPyImport_ImportFromMany(cpy_r_r10, cpy_r_r9, cpy_r_r9, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyModule_faster_eth_abi___codec = cpy_r_r12;
    CPy_INCREF(CPyModule_faster_eth_abi___codec);
    CPy_DECREF(cpy_r_r12);
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('registry',) */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.registry' */
    cpy_r_r15 = CPyStatic_abi___globals;
    cpy_r_r16 = CPyImport_ImportFromMany(cpy_r_r14, cpy_r_r13, cpy_r_r13, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyModule_faster_eth_abi___registry = cpy_r_r16;
    CPy_INCREF(CPyModule_faster_eth_abi___registry);
    CPy_DECREF(cpy_r_r16);
    cpy_r_r17 = CPyStatic_abi___globals;
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'registry' */
    cpy_r_r19 = CPyDict_GetItem(cpy_r_r17, cpy_r_r18);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    cpy_r_r20 = CPyStatic_abi___globals;
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ABICodec' */
    cpy_r_r22 = CPyDict_GetItem(cpy_r_r20, cpy_r_r21);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL32;
    }
    PyObject *cpy_r_r23[1] = {cpy_r_r19};
    cpy_r_r24 = (PyObject **)&cpy_r_r23;
    cpy_r_r25 = PyObject_Vectorcall(cpy_r_r22, cpy_r_r24, 1, 0);
    CPy_DECREF(cpy_r_r22);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL32;
    }
    CPy_DECREF(cpy_r_r19);
    CPyStatic_abi___default_codec = cpy_r_r25;
    CPy_INCREF(CPyStatic_abi___default_codec);
    cpy_r_r26 = CPyStatic_abi___globals;
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'default_codec' */
    cpy_r_r28 = CPyDict_SetItem(cpy_r_r26, cpy_r_r27, cpy_r_r25);
    CPy_DECREF(cpy_r_r25);
    cpy_r_r29 = cpy_r_r28 >= 0;
    if (unlikely(!cpy_r_r29)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    cpy_r_r30 = CPyStatic_abi___default_codec;
    if (likely(cpy_r_r30 != NULL)) goto CPyL13;
    PyErr_SetString(PyExc_NameError, "value for final name \"default_codec\" was not set");
    cpy_r_r31 = 0;
    if (unlikely(!cpy_r_r31)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPy_Unreachable();
CPyL13: ;
    cpy_r_r32 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'encode' */
    cpy_r_r33 = CPyObject_GetAttr(cpy_r_r30, cpy_r_r32);
    if (unlikely(cpy_r_r33 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyStatic_abi___encode = cpy_r_r33;
    CPy_INCREF(CPyStatic_abi___encode);
    cpy_r_r34 = CPyStatic_abi___globals;
    cpy_r_r35 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'encode' */
    cpy_r_r36 = CPyDict_SetItem(cpy_r_r34, cpy_r_r35, cpy_r_r33);
    CPy_DECREF(cpy_r_r33);
    cpy_r_r37 = cpy_r_r36 >= 0;
    if (unlikely(!cpy_r_r37)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    cpy_r_r38 = CPyStatic_abi___default_codec;
    if (likely(cpy_r_r38 != NULL)) goto CPyL18;
    PyErr_SetString(PyExc_NameError, "value for final name \"default_codec\" was not set");
    cpy_r_r39 = 0;
    if (unlikely(!cpy_r_r39)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPy_Unreachable();
CPyL18: ;
    cpy_r_r40 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decode' */
    cpy_r_r41 = CPyObject_GetAttr(cpy_r_r38, cpy_r_r40);
    if (unlikely(cpy_r_r41 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyStatic_abi___decode = cpy_r_r41;
    CPy_INCREF(CPyStatic_abi___decode);
    cpy_r_r42 = CPyStatic_abi___globals;
    cpy_r_r43 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decode' */
    cpy_r_r44 = CPyDict_SetItem(cpy_r_r42, cpy_r_r43, cpy_r_r41);
    CPy_DECREF(cpy_r_r41);
    cpy_r_r45 = cpy_r_r44 >= 0;
    if (unlikely(!cpy_r_r45)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    cpy_r_r46 = CPyStatic_abi___default_codec;
    if (likely(cpy_r_r46 != NULL)) goto CPyL23;
    PyErr_SetString(PyExc_NameError, "value for final name \"default_codec\" was not set");
    cpy_r_r47 = 0;
    if (unlikely(!cpy_r_r47)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPy_Unreachable();
CPyL23: ;
    cpy_r_r48 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_encodable' */
    cpy_r_r49 = CPyObject_GetAttr(cpy_r_r46, cpy_r_r48);
    if (unlikely(cpy_r_r49 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyStatic_abi___is_encodable = cpy_r_r49;
    CPy_INCREF(CPyStatic_abi___is_encodable);
    cpy_r_r50 = CPyStatic_abi___globals;
    cpy_r_r51 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_encodable' */
    cpy_r_r52 = CPyDict_SetItem(cpy_r_r50, cpy_r_r51, cpy_r_r49);
    CPy_DECREF(cpy_r_r49);
    cpy_r_r53 = cpy_r_r52 >= 0;
    if (unlikely(!cpy_r_r53)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    cpy_r_r54 = CPyStatic_abi___default_codec;
    if (likely(cpy_r_r54 != NULL)) goto CPyL28;
    PyErr_SetString(PyExc_NameError, "value for final name \"default_codec\" was not set");
    cpy_r_r55 = 0;
    if (unlikely(!cpy_r_r55)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPy_Unreachable();
CPyL28: ;
    cpy_r_r56 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_encodable_type' */
    cpy_r_r57 = CPyObject_GetAttr(cpy_r_r54, cpy_r_r56);
    if (unlikely(cpy_r_r57 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    CPyStatic_abi___is_encodable_type = cpy_r_r57;
    CPy_INCREF(CPyStatic_abi___is_encodable_type);
    cpy_r_r58 = CPyStatic_abi___globals;
    cpy_r_r59 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_encodable_type' */
    cpy_r_r60 = CPyDict_SetItem(cpy_r_r58, cpy_r_r59, cpy_r_r57);
    CPy_DECREF(cpy_r_r57);
    cpy_r_r61 = cpy_r_r60 >= 0;
    if (unlikely(!cpy_r_r61)) {
        CPy_AddTraceback("faster_eth_abi/abi.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_abi___globals);
        goto CPyL31;
    }
    return 1;
CPyL31: ;
    cpy_r_r62 = 2;
    return cpy_r_r62;
CPyL32: ;
    CPy_DecRef(cpy_r_r19);
    goto CPyL31;
}
static PyMethodDef constantsmodule_methods[] = {
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___constants(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___constants__internal, "__name__");
    CPyStatic_constants___globals = PyModule_GetDict(CPyModule_faster_eth_abi___constants__internal);
    if (unlikely(CPyStatic_constants___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_constants_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___constants__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef constantsmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.constants",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    constantsmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___constants(void)
{
    if (CPyModule_faster_eth_abi___constants__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___constants__internal);
        return CPyModule_faster_eth_abi___constants__internal;
    }
    CPyModule_faster_eth_abi___constants__internal = PyModule_Create(&constantsmodule);
    if (unlikely(CPyModule_faster_eth_abi___constants__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___constants(CPyModule_faster_eth_abi___constants__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___constants__internal;
    fail:
    return NULL;
}

char CPyDef_constants_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    CPyTagged cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    int32_t cpy_r_r13;
    char cpy_r_r14;
    CPyTagged cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    int32_t cpy_r_r19;
    char cpy_r_r20;
    CPyTagged cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    int32_t cpy_r_r25;
    char cpy_r_r26;
    char cpy_r_r27;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/constants.py", "<module>", -1, CPyStatic_constants___globals);
        goto CPyL8;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Final',) */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic_constants___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/constants.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_constants___globals);
        goto CPyL8;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = (CPyTagged)CPyStatics[DIFFCHECK_PLACEHOLDER] | 1; /* 115792089237316195423570985008687907853269984665640564039457584007913129639936 */
    cpy_r_r10 = CPyStatic_constants___globals;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TT256' */
    CPyTagged_INCREF(cpy_r_r9);
    cpy_r_r12 = CPyTagged_StealAsObject(cpy_r_r9);
    cpy_r_r13 = CPyDict_SetItem(cpy_r_r10, cpy_r_r11, cpy_r_r12);
    CPy_DECREF(cpy_r_r12);
    cpy_r_r14 = cpy_r_r13 >= 0;
    if (unlikely(!cpy_r_r14)) {
        CPy_AddTraceback("faster_eth_abi/constants.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_constants___globals);
        goto CPyL8;
    }
    cpy_r_r15 = (CPyTagged)CPyStatics[DIFFCHECK_PLACEHOLDER] | 1; /* 115792089237316195423570985008687907853269984665640564039457584007913129639935 */
    cpy_r_r16 = CPyStatic_constants___globals;
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TT256M1' */
    CPyTagged_INCREF(cpy_r_r15);
    cpy_r_r18 = CPyTagged_StealAsObject(cpy_r_r15);
    cpy_r_r19 = CPyDict_SetItem(cpy_r_r16, cpy_r_r17, cpy_r_r18);
    CPy_DECREF(cpy_r_r18);
    cpy_r_r20 = cpy_r_r19 >= 0;
    if (unlikely(!cpy_r_r20)) {
        CPy_AddTraceback("faster_eth_abi/constants.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_constants___globals);
        goto CPyL8;
    }
    cpy_r_r21 = (CPyTagged)CPyStatics[DIFFCHECK_PLACEHOLDER] | 1; /* 57896044618658097711785492504343953926634992332820282019728792003956564819968 */
    cpy_r_r22 = CPyStatic_constants___globals;
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TT255' */
    CPyTagged_INCREF(cpy_r_r21);
    cpy_r_r24 = CPyTagged_StealAsObject(cpy_r_r21);
    cpy_r_r25 = CPyDict_SetItem(cpy_r_r22, cpy_r_r23, cpy_r_r24);
    CPy_DECREF(cpy_r_r24);
    cpy_r_r26 = cpy_r_r25 >= 0;
    if (unlikely(!cpy_r_r26)) {
        CPy_AddTraceback("faster_eth_abi/constants.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_constants___globals);
        goto CPyL8;
    }
    return 1;
CPyL8: ;
    cpy_r_r27 = 2;
    return cpy_r_r27;
}

PyObject *CPyDef_from_type_str_____mypyc__parse_type_str_env_setup(PyObject *cpy_r_type);
PyObject *CPyDef_from_type_str___parse_type_str_env(void);

static PyObject *
from_type_str___parse_type_str_env_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_from_type_str___parse_type_str_env) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_from_type_str_____mypyc__parse_type_str_env_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
from_type_str___parse_type_str_env_traverse(faster_eth_abi___from_type_str___parse_type_str_envObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_self__);
    Py_VISIT(self->_expected_base);
    Py_VISIT(self->_decorator);
    return 0;
}

static int
from_type_str___parse_type_str_env_clear(faster_eth_abi___from_type_str___parse_type_str_envObject *self)
{
    Py_CLEAR(self->___mypyc_self__);
    Py_CLEAR(self->_expected_base);
    Py_CLEAR(self->_decorator);
    return 0;
}

static void
from_type_str___parse_type_str_env_dealloc(faster_eth_abi___from_type_str___parse_type_str_envObject *self)
{
    PyObject_GC_UnTrack(self);
    if (from_type_str___parse_type_str_env_free_instance == NULL) {
        from_type_str___parse_type_str_env_free_instance = self;
        Py_CLEAR(self->___mypyc_self__);
        Py_CLEAR(self->_expected_base);
        self->_with_arrlist = 2;
        self->_None = 2;
        Py_CLEAR(self->_decorator);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, from_type_str___parse_type_str_env_dealloc)
    from_type_str___parse_type_str_env_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem from_type_str___parse_type_str_env_vtable[1];
static bool
CPyDef_from_type_str___parse_type_str_env_trait_vtable_setup(void)
{
    CPyVTableItem from_type_str___parse_type_str_env_vtable_scratch[] = {
        NULL
    };
    memcpy(from_type_str___parse_type_str_env_vtable, from_type_str___parse_type_str_env_vtable_scratch, sizeof(from_type_str___parse_type_str_env_vtable));
    return 1;
}

static PyMethodDef from_type_str___parse_type_str_env_methods[] = {
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_from_type_str___parse_type_str_env_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "parse_type_str_env",
    .tp_new = from_type_str___parse_type_str_env_new,
    .tp_dealloc = (destructor)from_type_str___parse_type_str_env_dealloc,
    .tp_traverse = (traverseproc)from_type_str___parse_type_str_env_traverse,
    .tp_clear = (inquiry)from_type_str___parse_type_str_env_clear,
    .tp_methods = from_type_str___parse_type_str_env_methods,
    .tp_basicsize = sizeof(faster_eth_abi___from_type_str___parse_type_str_envObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("parse_type_str_env()\n--\n\n"),
};
static PyTypeObject *CPyType_from_type_str___parse_type_str_env_template = &CPyType_from_type_str___parse_type_str_env_template_;

PyObject *CPyDef_from_type_str_____mypyc__parse_type_str_env_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___from_type_str___parse_type_str_envObject *self;
    if (from_type_str___parse_type_str_env_free_instance != NULL) {
        self = from_type_str___parse_type_str_env_free_instance;
        from_type_str___parse_type_str_env_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___from_type_str___parse_type_str_envObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = from_type_str___parse_type_str_env_vtable;
    self->_with_arrlist = 2;
    self->_None = 2;
    return (PyObject *)self;
}

PyObject *CPyDef_from_type_str___parse_type_str_env(void)
{
    PyObject *self = CPyDef_from_type_str_____mypyc__parse_type_str_env_setup((PyObject *)CPyType_from_type_str___parse_type_str_env);
    if (self == NULL)
        return NULL;
    return self;
}


PyObject *CPyDef_from_type_str_____mypyc__decorator_parse_type_str_env_setup(PyObject *cpy_r_type);
PyObject *CPyDef_from_type_str___decorator_parse_type_str_env(void);

static PyObject *
from_type_str___decorator_parse_type_str_env_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_from_type_str___decorator_parse_type_str_env) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_from_type_str_____mypyc__decorator_parse_type_str_env_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
from_type_str___decorator_parse_type_str_env_traverse(faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_self__);
    Py_VISIT(self->___mypyc_env__);
    Py_VISIT(self->_old_from_type_str);
    Py_VISIT(self->_new_from_type_str);
    Py_VISIT(self->_expected_base);
    Py_VISIT(self->_decorator);
    return 0;
}

static int
from_type_str___decorator_parse_type_str_env_clear(faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *self)
{
    Py_CLEAR(self->___mypyc_self__);
    Py_CLEAR(self->___mypyc_env__);
    Py_CLEAR(self->_old_from_type_str);
    Py_CLEAR(self->_new_from_type_str);
    Py_CLEAR(self->_expected_base);
    Py_CLEAR(self->_decorator);
    return 0;
}

static void
from_type_str___decorator_parse_type_str_env_dealloc(faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *self)
{
    PyObject_GC_UnTrack(self);
    if (from_type_str___decorator_parse_type_str_env_free_instance == NULL) {
        from_type_str___decorator_parse_type_str_env_free_instance = self;
        Py_CLEAR(self->___mypyc_self__);
        Py_CLEAR(self->___mypyc_env__);
        Py_CLEAR(self->_old_from_type_str);
        Py_CLEAR(self->_new_from_type_str);
        Py_CLEAR(self->_expected_base);
        self->_with_arrlist = 2;
        self->_None = 2;
        Py_CLEAR(self->_decorator);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, from_type_str___decorator_parse_type_str_env_dealloc)
    from_type_str___decorator_parse_type_str_env_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem from_type_str___decorator_parse_type_str_env_vtable[1];
static bool
CPyDef_from_type_str___decorator_parse_type_str_env_trait_vtable_setup(void)
{
    CPyVTableItem from_type_str___decorator_parse_type_str_env_vtable_scratch[] = {
        NULL
    };
    memcpy(from_type_str___decorator_parse_type_str_env_vtable, from_type_str___decorator_parse_type_str_env_vtable_scratch, sizeof(from_type_str___decorator_parse_type_str_env_vtable));
    return 1;
}

static PyMethodDef from_type_str___decorator_parse_type_str_env_methods[] = {
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_from_type_str___decorator_parse_type_str_env_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "decorator_parse_type_str_env",
    .tp_new = from_type_str___decorator_parse_type_str_env_new,
    .tp_dealloc = (destructor)from_type_str___decorator_parse_type_str_env_dealloc,
    .tp_traverse = (traverseproc)from_type_str___decorator_parse_type_str_env_traverse,
    .tp_clear = (inquiry)from_type_str___decorator_parse_type_str_env_clear,
    .tp_methods = from_type_str___decorator_parse_type_str_env_methods,
    .tp_basicsize = sizeof(faster_eth_abi___from_type_str___decorator_parse_type_str_envObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("decorator_parse_type_str_env()\n--\n\n"),
};
static PyTypeObject *CPyType_from_type_str___decorator_parse_type_str_env_template = &CPyType_from_type_str___decorator_parse_type_str_env_template_;

PyObject *CPyDef_from_type_str_____mypyc__decorator_parse_type_str_env_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *self;
    if (from_type_str___decorator_parse_type_str_env_free_instance != NULL) {
        self = from_type_str___decorator_parse_type_str_env_free_instance;
        from_type_str___decorator_parse_type_str_env_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = from_type_str___decorator_parse_type_str_env_vtable;
    self->_with_arrlist = 2;
    self->_None = 2;
    return (PyObject *)self;
}

PyObject *CPyDef_from_type_str___decorator_parse_type_str_env(void)
{
    PyObject *self = CPyDef_from_type_str_____mypyc__decorator_parse_type_str_env_setup((PyObject *)CPyType_from_type_str___decorator_parse_type_str_env);
    if (self == NULL)
        return NULL;
    return self;
}


static PyObject *CPyDunder___get__from_type_str___decorator_parse_type_str_obj(PyObject *self, PyObject *instance, PyObject *owner) {
    instance = instance ? instance : Py_None;
    return CPyDef_from_type_str___decorator_parse_type_str_obj_____get__(self, instance, owner);
}
PyObject *CPyDef_from_type_str_____mypyc__decorator_parse_type_str_obj_setup(PyObject *cpy_r_type);
PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj(void);

static PyObject *
from_type_str___decorator_parse_type_str_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_from_type_str___decorator_parse_type_str_obj) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_from_type_str_____mypyc__decorator_parse_type_str_obj_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
from_type_str___decorator_parse_type_str_obj_traverse(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_env__);
    PyObject_VisitManagedDict((PyObject *)self, visit, arg);
    return 0;
}

static int
from_type_str___decorator_parse_type_str_obj_clear(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self)
{
    Py_CLEAR(self->___mypyc_env__);
    PyObject_ClearManagedDict((PyObject *)self);
    return 0;
}

static void
from_type_str___decorator_parse_type_str_obj_dealloc(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self)
{
    PyObject_GC_UnTrack(self);
    if (from_type_str___decorator_parse_type_str_obj_free_instance == NULL) {
        from_type_str___decorator_parse_type_str_obj_free_instance = self;
        Py_CLEAR(self->___mypyc_env__);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, from_type_str___decorator_parse_type_str_obj_dealloc)
    from_type_str___decorator_parse_type_str_obj_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem from_type_str___decorator_parse_type_str_obj_vtable[2];
static bool
CPyDef_from_type_str___decorator_parse_type_str_obj_trait_vtable_setup(void)
{
    CPyVTableItem from_type_str___decorator_parse_type_str_obj_vtable_scratch[] = {
        (CPyVTableItem)CPyDef_from_type_str___decorator_parse_type_str_obj_____call__,
        (CPyVTableItem)CPyDef_from_type_str___decorator_parse_type_str_obj_____get__,
    };
    memcpy(from_type_str___decorator_parse_type_str_obj_vtable, from_type_str___decorator_parse_type_str_obj_vtable_scratch, sizeof(from_type_str___decorator_parse_type_str_obj_vtable));
    return 1;
}

static PyObject *
from_type_str___decorator_parse_type_str_obj_get___3_mypyc_env__(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self, void *closure);
static int
from_type_str___decorator_parse_type_str_obj_set___3_mypyc_env__(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self, PyObject *value, void *closure);

static PyGetSetDef from_type_str___decorator_parse_type_str_obj_getseters[] = {
    {"__mypyc_env__",
     (getter)from_type_str___decorator_parse_type_str_obj_get___3_mypyc_env__, (setter)from_type_str___decorator_parse_type_str_obj_set___3_mypyc_env__,
     NULL, NULL},
    {"__dict__", PyObject_GenericGetDict, PyObject_GenericSetDict},
    {NULL}  /* Sentinel */
};

static PyMethodDef from_type_str___decorator_parse_type_str_obj_methods[] = {
    {"__call__",
     (PyCFunction)CPyPy_from_type_str___decorator_parse_type_str_obj_____call__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__call__($old_from_type_str)\n--\n\n")},
    {"__get__",
     (PyCFunction)CPyPy_from_type_str___decorator_parse_type_str_obj_____get__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__get__($instance, owner)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_from_type_str___decorator_parse_type_str_obj_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "decorator_parse_type_str_obj",
    .tp_new = from_type_str___decorator_parse_type_str_obj_new,
    .tp_dealloc = (destructor)from_type_str___decorator_parse_type_str_obj_dealloc,
    .tp_traverse = (traverseproc)from_type_str___decorator_parse_type_str_obj_traverse,
    .tp_clear = (inquiry)from_type_str___decorator_parse_type_str_obj_clear,
    .tp_getset = from_type_str___decorator_parse_type_str_obj_getseters,
    .tp_methods = from_type_str___decorator_parse_type_str_obj_methods,
    .tp_call = PyVectorcall_Call,
    .tp_descr_get = CPyDunder___get__from_type_str___decorator_parse_type_str_obj,
    .tp_basicsize = sizeof(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject),
    .tp_vectorcall_offset = offsetof(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject, vectorcall),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | _Py_TPFLAGS_HAVE_VECTORCALL | Py_TPFLAGS_MANAGED_DICT,
    .tp_doc = PyDoc_STR("decorator_parse_type_str_obj()\n--\n\n"),
};
static PyTypeObject *CPyType_from_type_str___decorator_parse_type_str_obj_template = &CPyType_from_type_str___decorator_parse_type_str_obj_template_;

PyObject *CPyDef_from_type_str_____mypyc__decorator_parse_type_str_obj_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self;
    if (from_type_str___decorator_parse_type_str_obj_free_instance != NULL) {
        self = from_type_str___decorator_parse_type_str_obj_free_instance;
        from_type_str___decorator_parse_type_str_obj_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = from_type_str___decorator_parse_type_str_obj_vtable;
    self->vectorcall = CPyPy_from_type_str___decorator_parse_type_str_obj_____call__;
    return (PyObject *)self;
}

PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj(void)
{
    PyObject *self = CPyDef_from_type_str_____mypyc__decorator_parse_type_str_obj_setup((PyObject *)CPyType_from_type_str___decorator_parse_type_str_obj);
    if (self == NULL)
        return NULL;
    return self;
}

static PyObject *
from_type_str___decorator_parse_type_str_obj_get___3_mypyc_env__(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self, void *closure)
{
    if (unlikely(self->___mypyc_env__ == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute '__mypyc_env__' of 'decorator_parse_type_str_obj' undefined");
        return NULL;
    }
    CPy_INCREF_NO_IMM(self->___mypyc_env__);
    PyObject *retval = self->___mypyc_env__;
    return retval;
}

static int
from_type_str___decorator_parse_type_str_obj_set___3_mypyc_env__(faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'decorator_parse_type_str_obj' object attribute '__mypyc_env__' cannot be deleted");
        return -1;
    }
    if (self->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(self->___mypyc_env__);
    }
    PyObject *tmp;
    if (likely(Py_TYPE(value) == CPyType_from_type_str___parse_type_str_env))
        tmp = value;
    else {
        CPy_TypeError("faster_eth_abi.from_type_str.parse_type_str_env", value); 
        tmp = NULL;
    }
    if (!tmp)
        return -1;
    CPy_INCREF_NO_IMM(tmp);
    self->___mypyc_env__ = tmp;
    return 0;
}

static PyObject *CPyDunder___get__from_type_str___new_from_type_str_parse_type_str_decorator_obj(PyObject *self, PyObject *instance, PyObject *owner) {
    instance = instance ? instance : Py_None;
    return CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__(self, instance, owner);
}
PyObject *CPyDef_from_type_str_____mypyc__new_from_type_str_parse_type_str_decorator_obj_setup(PyObject *cpy_r_type);
PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj(void);

static PyObject *
from_type_str___new_from_type_str_parse_type_str_decorator_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_from_type_str_____mypyc__new_from_type_str_parse_type_str_decorator_obj_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
from_type_str___new_from_type_str_parse_type_str_decorator_obj_traverse(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_env__);
    PyObject_VisitManagedDict((PyObject *)self, visit, arg);
    return 0;
}

static int
from_type_str___new_from_type_str_parse_type_str_decorator_obj_clear(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self)
{
    Py_CLEAR(self->___mypyc_env__);
    PyObject_ClearManagedDict((PyObject *)self);
    return 0;
}

static void
from_type_str___new_from_type_str_parse_type_str_decorator_obj_dealloc(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self)
{
    PyObject_GC_UnTrack(self);
    if (from_type_str___new_from_type_str_parse_type_str_decorator_obj_free_instance == NULL) {
        from_type_str___new_from_type_str_parse_type_str_decorator_obj_free_instance = self;
        Py_CLEAR(self->___mypyc_env__);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, from_type_str___new_from_type_str_parse_type_str_decorator_obj_dealloc)
    from_type_str___new_from_type_str_parse_type_str_decorator_obj_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem from_type_str___new_from_type_str_parse_type_str_decorator_obj_vtable[2];
static bool
CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_trait_vtable_setup(void)
{
    CPyVTableItem from_type_str___new_from_type_str_parse_type_str_decorator_obj_vtable_scratch[] = {
        (CPyVTableItem)CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__,
        (CPyVTableItem)CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__,
    };
    memcpy(from_type_str___new_from_type_str_parse_type_str_decorator_obj_vtable, from_type_str___new_from_type_str_parse_type_str_decorator_obj_vtable_scratch, sizeof(from_type_str___new_from_type_str_parse_type_str_decorator_obj_vtable));
    return 1;
}

static PyObject *
from_type_str___new_from_type_str_parse_type_str_decorator_obj_get___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self, void *closure);
static int
from_type_str___new_from_type_str_parse_type_str_decorator_obj_set___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self, PyObject *value, void *closure);

static PyGetSetDef from_type_str___new_from_type_str_parse_type_str_decorator_obj_getseters[] = {
    {"__mypyc_env__",
     (getter)from_type_str___new_from_type_str_parse_type_str_decorator_obj_get___3_mypyc_env__, (setter)from_type_str___new_from_type_str_parse_type_str_decorator_obj_set___3_mypyc_env__,
     NULL, NULL},
    {"__dict__", PyObject_GenericGetDict, PyObject_GenericSetDict},
    {NULL}  /* Sentinel */
};

static PyMethodDef from_type_str___new_from_type_str_parse_type_str_decorator_obj_methods[] = {
    {"__call__",
     (PyCFunction)CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__call__($cls, type_str, registry)\n--\n\n")},
    {"__get__",
     (PyCFunction)CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__get__($instance, owner)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "new_from_type_str_parse_type_str_decorator_obj",
    .tp_new = from_type_str___new_from_type_str_parse_type_str_decorator_obj_new,
    .tp_dealloc = (destructor)from_type_str___new_from_type_str_parse_type_str_decorator_obj_dealloc,
    .tp_traverse = (traverseproc)from_type_str___new_from_type_str_parse_type_str_decorator_obj_traverse,
    .tp_clear = (inquiry)from_type_str___new_from_type_str_parse_type_str_decorator_obj_clear,
    .tp_getset = from_type_str___new_from_type_str_parse_type_str_decorator_obj_getseters,
    .tp_methods = from_type_str___new_from_type_str_parse_type_str_decorator_obj_methods,
    .tp_call = PyVectorcall_Call,
    .tp_descr_get = CPyDunder___get__from_type_str___new_from_type_str_parse_type_str_decorator_obj,
    .tp_basicsize = sizeof(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject),
    .tp_vectorcall_offset = offsetof(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject, vectorcall),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | _Py_TPFLAGS_HAVE_VECTORCALL | Py_TPFLAGS_MANAGED_DICT,
    .tp_doc = PyDoc_STR("new_from_type_str_parse_type_str_decorator_obj()\n--\n\n"),
};
static PyTypeObject *CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj_template = &CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj_template_;

PyObject *CPyDef_from_type_str_____mypyc__new_from_type_str_parse_type_str_decorator_obj_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self;
    if (from_type_str___new_from_type_str_parse_type_str_decorator_obj_free_instance != NULL) {
        self = from_type_str___new_from_type_str_parse_type_str_decorator_obj_free_instance;
        from_type_str___new_from_type_str_parse_type_str_decorator_obj_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = from_type_str___new_from_type_str_parse_type_str_decorator_obj_vtable;
    self->vectorcall = CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__;
    return (PyObject *)self;
}

PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj(void)
{
    PyObject *self = CPyDef_from_type_str_____mypyc__new_from_type_str_parse_type_str_decorator_obj_setup((PyObject *)CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj);
    if (self == NULL)
        return NULL;
    return self;
}

static PyObject *
from_type_str___new_from_type_str_parse_type_str_decorator_obj_get___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self, void *closure)
{
    if (unlikely(self->___mypyc_env__ == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute '__mypyc_env__' of 'new_from_type_str_parse_type_str_decorator_obj' undefined");
        return NULL;
    }
    CPy_INCREF_NO_IMM(self->___mypyc_env__);
    PyObject *retval = self->___mypyc_env__;
    return retval;
}

static int
from_type_str___new_from_type_str_parse_type_str_decorator_obj_set___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'new_from_type_str_parse_type_str_decorator_obj' object attribute '__mypyc_env__' cannot be deleted");
        return -1;
    }
    if (self->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(self->___mypyc_env__);
    }
    PyObject *tmp;
    if (likely(Py_TYPE(value) == CPyType_from_type_str___decorator_parse_type_str_env))
        tmp = value;
    else {
        CPy_TypeError("faster_eth_abi.from_type_str.decorator_parse_type_str_env", value); 
        tmp = NULL;
    }
    if (!tmp)
        return -1;
    CPy_INCREF_NO_IMM(tmp);
    self->___mypyc_env__ = tmp;
    return 0;
}

PyObject *CPyDef_from_type_str_____mypyc__parse_tuple_type_str_env_setup(PyObject *cpy_r_type);
PyObject *CPyDef_from_type_str___parse_tuple_type_str_env(void);

static PyObject *
from_type_str___parse_tuple_type_str_env_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_from_type_str___parse_tuple_type_str_env) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_from_type_str_____mypyc__parse_tuple_type_str_env_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
from_type_str___parse_tuple_type_str_env_traverse(faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_self__);
    Py_VISIT(self->_old_from_type_str);
    Py_VISIT(self->_new_from_type_str);
    return 0;
}

static int
from_type_str___parse_tuple_type_str_env_clear(faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *self)
{
    Py_CLEAR(self->___mypyc_self__);
    Py_CLEAR(self->_old_from_type_str);
    Py_CLEAR(self->_new_from_type_str);
    return 0;
}

static void
from_type_str___parse_tuple_type_str_env_dealloc(faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *self)
{
    PyObject_GC_UnTrack(self);
    if (from_type_str___parse_tuple_type_str_env_free_instance == NULL) {
        from_type_str___parse_tuple_type_str_env_free_instance = self;
        Py_CLEAR(self->___mypyc_self__);
        Py_CLEAR(self->_old_from_type_str);
        Py_CLEAR(self->_new_from_type_str);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, from_type_str___parse_tuple_type_str_env_dealloc)
    from_type_str___parse_tuple_type_str_env_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem from_type_str___parse_tuple_type_str_env_vtable[1];
static bool
CPyDef_from_type_str___parse_tuple_type_str_env_trait_vtable_setup(void)
{
    CPyVTableItem from_type_str___parse_tuple_type_str_env_vtable_scratch[] = {
        NULL
    };
    memcpy(from_type_str___parse_tuple_type_str_env_vtable, from_type_str___parse_tuple_type_str_env_vtable_scratch, sizeof(from_type_str___parse_tuple_type_str_env_vtable));
    return 1;
}

static PyMethodDef from_type_str___parse_tuple_type_str_env_methods[] = {
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_from_type_str___parse_tuple_type_str_env_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "parse_tuple_type_str_env",
    .tp_new = from_type_str___parse_tuple_type_str_env_new,
    .tp_dealloc = (destructor)from_type_str___parse_tuple_type_str_env_dealloc,
    .tp_traverse = (traverseproc)from_type_str___parse_tuple_type_str_env_traverse,
    .tp_clear = (inquiry)from_type_str___parse_tuple_type_str_env_clear,
    .tp_methods = from_type_str___parse_tuple_type_str_env_methods,
    .tp_basicsize = sizeof(faster_eth_abi___from_type_str___parse_tuple_type_str_envObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("parse_tuple_type_str_env()\n--\n\n"),
};
static PyTypeObject *CPyType_from_type_str___parse_tuple_type_str_env_template = &CPyType_from_type_str___parse_tuple_type_str_env_template_;

PyObject *CPyDef_from_type_str_____mypyc__parse_tuple_type_str_env_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *self;
    if (from_type_str___parse_tuple_type_str_env_free_instance != NULL) {
        self = from_type_str___parse_tuple_type_str_env_free_instance;
        from_type_str___parse_tuple_type_str_env_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = from_type_str___parse_tuple_type_str_env_vtable;
    return (PyObject *)self;
}

PyObject *CPyDef_from_type_str___parse_tuple_type_str_env(void)
{
    PyObject *self = CPyDef_from_type_str_____mypyc__parse_tuple_type_str_env_setup((PyObject *)CPyType_from_type_str___parse_tuple_type_str_env);
    if (self == NULL)
        return NULL;
    return self;
}


static PyObject *CPyDunder___get__from_type_str___new_from_type_str_parse_tuple_type_str_obj(PyObject *self, PyObject *instance, PyObject *owner) {
    instance = instance ? instance : Py_None;
    return CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__(self, instance, owner);
}
PyObject *CPyDef_from_type_str_____mypyc__new_from_type_str_parse_tuple_type_str_obj_setup(PyObject *cpy_r_type);
PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj(void);

static PyObject *
from_type_str___new_from_type_str_parse_tuple_type_str_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_from_type_str_____mypyc__new_from_type_str_parse_tuple_type_str_obj_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
from_type_str___new_from_type_str_parse_tuple_type_str_obj_traverse(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_env__);
    PyObject_VisitManagedDict((PyObject *)self, visit, arg);
    return 0;
}

static int
from_type_str___new_from_type_str_parse_tuple_type_str_obj_clear(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self)
{
    Py_CLEAR(self->___mypyc_env__);
    PyObject_ClearManagedDict((PyObject *)self);
    return 0;
}

static void
from_type_str___new_from_type_str_parse_tuple_type_str_obj_dealloc(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self)
{
    PyObject_GC_UnTrack(self);
    if (from_type_str___new_from_type_str_parse_tuple_type_str_obj_free_instance == NULL) {
        from_type_str___new_from_type_str_parse_tuple_type_str_obj_free_instance = self;
        Py_CLEAR(self->___mypyc_env__);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, from_type_str___new_from_type_str_parse_tuple_type_str_obj_dealloc)
    from_type_str___new_from_type_str_parse_tuple_type_str_obj_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem from_type_str___new_from_type_str_parse_tuple_type_str_obj_vtable[2];
static bool
CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_trait_vtable_setup(void)
{
    CPyVTableItem from_type_str___new_from_type_str_parse_tuple_type_str_obj_vtable_scratch[] = {
        (CPyVTableItem)CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__,
        (CPyVTableItem)CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__,
    };
    memcpy(from_type_str___new_from_type_str_parse_tuple_type_str_obj_vtable, from_type_str___new_from_type_str_parse_tuple_type_str_obj_vtable_scratch, sizeof(from_type_str___new_from_type_str_parse_tuple_type_str_obj_vtable));
    return 1;
}

static PyObject *
from_type_str___new_from_type_str_parse_tuple_type_str_obj_get___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self, void *closure);
static int
from_type_str___new_from_type_str_parse_tuple_type_str_obj_set___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self, PyObject *value, void *closure);

static PyGetSetDef from_type_str___new_from_type_str_parse_tuple_type_str_obj_getseters[] = {
    {"__mypyc_env__",
     (getter)from_type_str___new_from_type_str_parse_tuple_type_str_obj_get___3_mypyc_env__, (setter)from_type_str___new_from_type_str_parse_tuple_type_str_obj_set___3_mypyc_env__,
     NULL, NULL},
    {"__dict__", PyObject_GenericGetDict, PyObject_GenericSetDict},
    {NULL}  /* Sentinel */
};

static PyMethodDef from_type_str___new_from_type_str_parse_tuple_type_str_obj_methods[] = {
    {"__call__",
     (PyCFunction)CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__call__($cls, type_str, registry)\n--\n\n")},
    {"__get__",
     (PyCFunction)CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__get__($instance, owner)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "new_from_type_str_parse_tuple_type_str_obj",
    .tp_new = from_type_str___new_from_type_str_parse_tuple_type_str_obj_new,
    .tp_dealloc = (destructor)from_type_str___new_from_type_str_parse_tuple_type_str_obj_dealloc,
    .tp_traverse = (traverseproc)from_type_str___new_from_type_str_parse_tuple_type_str_obj_traverse,
    .tp_clear = (inquiry)from_type_str___new_from_type_str_parse_tuple_type_str_obj_clear,
    .tp_getset = from_type_str___new_from_type_str_parse_tuple_type_str_obj_getseters,
    .tp_methods = from_type_str___new_from_type_str_parse_tuple_type_str_obj_methods,
    .tp_call = PyVectorcall_Call,
    .tp_descr_get = CPyDunder___get__from_type_str___new_from_type_str_parse_tuple_type_str_obj,
    .tp_basicsize = sizeof(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject),
    .tp_vectorcall_offset = offsetof(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject, vectorcall),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | _Py_TPFLAGS_HAVE_VECTORCALL | Py_TPFLAGS_MANAGED_DICT,
    .tp_doc = PyDoc_STR("new_from_type_str_parse_tuple_type_str_obj()\n--\n\n"),
};
static PyTypeObject *CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj_template = &CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj_template_;

PyObject *CPyDef_from_type_str_____mypyc__new_from_type_str_parse_tuple_type_str_obj_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self;
    if (from_type_str___new_from_type_str_parse_tuple_type_str_obj_free_instance != NULL) {
        self = from_type_str___new_from_type_str_parse_tuple_type_str_obj_free_instance;
        from_type_str___new_from_type_str_parse_tuple_type_str_obj_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = from_type_str___new_from_type_str_parse_tuple_type_str_obj_vtable;
    self->vectorcall = CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__;
    return (PyObject *)self;
}

PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj(void)
{
    PyObject *self = CPyDef_from_type_str_____mypyc__new_from_type_str_parse_tuple_type_str_obj_setup((PyObject *)CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj);
    if (self == NULL)
        return NULL;
    return self;
}

static PyObject *
from_type_str___new_from_type_str_parse_tuple_type_str_obj_get___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self, void *closure)
{
    if (unlikely(self->___mypyc_env__ == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute '__mypyc_env__' of 'new_from_type_str_parse_tuple_type_str_obj' undefined");
        return NULL;
    }
    CPy_INCREF_NO_IMM(self->___mypyc_env__);
    PyObject *retval = self->___mypyc_env__;
    return retval;
}

static int
from_type_str___new_from_type_str_parse_tuple_type_str_obj_set___3_mypyc_env__(faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'new_from_type_str_parse_tuple_type_str_obj' object attribute '__mypyc_env__' cannot be deleted");
        return -1;
    }
    if (self->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(self->___mypyc_env__);
    }
    PyObject *tmp;
    if (likely(Py_TYPE(value) == CPyType_from_type_str___parse_tuple_type_str_env))
        tmp = value;
    else {
        CPy_TypeError("faster_eth_abi.from_type_str.parse_tuple_type_str_env", value); 
        tmp = NULL;
    }
    if (!tmp)
        return -1;
    CPy_INCREF_NO_IMM(tmp);
    self->___mypyc_env__ = tmp;
    return 0;
}
static PyMethodDef from_type_strmodule_methods[] = {
    {"parse_type_str", (PyCFunction)CPyPy_from_type_str___parse_type_str, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("parse_type_str(expected_base=None, with_arrlist=False)\n--\n\n") /* docstring */},
    {"parse_tuple_type_str", (PyCFunction)CPyPy_from_type_str___parse_tuple_type_str, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("parse_tuple_type_str(old_from_type_str)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___from_type_str(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___from_type_str__internal, "__name__");
    CPyStatic_from_type_str___globals = PyModule_GetDict(CPyModule_faster_eth_abi___from_type_str__internal);
    if (unlikely(CPyStatic_from_type_str___globals == NULL))
        goto fail;
    CPyType_from_type_str___parse_type_str_env = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_from_type_str___parse_type_str_env_template, NULL, modname);
    if (unlikely(!CPyType_from_type_str___parse_type_str_env))
        goto fail;
    CPyType_from_type_str___decorator_parse_type_str_env = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_from_type_str___decorator_parse_type_str_env_template, NULL, modname);
    if (unlikely(!CPyType_from_type_str___decorator_parse_type_str_env))
        goto fail;
    CPyType_from_type_str___decorator_parse_type_str_obj = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_from_type_str___decorator_parse_type_str_obj_template, NULL, modname);
    if (unlikely(!CPyType_from_type_str___decorator_parse_type_str_obj))
        goto fail;
    CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj_template, NULL, modname);
    if (unlikely(!CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj))
        goto fail;
    CPyType_from_type_str___parse_tuple_type_str_env = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_from_type_str___parse_tuple_type_str_env_template, NULL, modname);
    if (unlikely(!CPyType_from_type_str___parse_tuple_type_str_env))
        goto fail;
    CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj_template, NULL, modname);
    if (unlikely(!CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_from_type_str_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___from_type_str__internal);
    Py_CLEAR(modname);
    Py_CLEAR(CPyType_from_type_str___parse_type_str_env);
    Py_CLEAR(CPyType_from_type_str___decorator_parse_type_str_env);
    Py_CLEAR(CPyType_from_type_str___decorator_parse_type_str_obj);
    Py_CLEAR(CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj);
    Py_CLEAR(CPyType_from_type_str___parse_tuple_type_str_env);
    Py_CLEAR(CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj);
    return -1;
}
static struct PyModuleDef from_type_strmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.from_type_str",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    from_type_strmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___from_type_str(void)
{
    if (CPyModule_faster_eth_abi___from_type_str__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___from_type_str__internal);
        return CPyModule_faster_eth_abi___from_type_str__internal;
    }
    CPyModule_faster_eth_abi___from_type_str__internal = PyModule_Create(&from_type_strmodule);
    if (unlikely(CPyModule_faster_eth_abi___from_type_str__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___from_type_str(CPyModule_faster_eth_abi___from_type_str__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___from_type_str__internal;
    fail:
    return NULL;
}

PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r1 = cpy_r_instance == cpy_r_r0;
    if (!cpy_r_r1) goto CPyL2;
    CPy_INCREF(cpy_r___mypyc_self__);
    return cpy_r___mypyc_self__;
CPyL2: ;
    cpy_r_r2 = PyMethod_New(cpy_r___mypyc_self__, cpy_r_instance);
    if (cpy_r_r2 == NULL) goto CPyL4;
    return cpy_r_r2;
CPyL4: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"instance", "owner", 0};
    static CPyArg_Parser parser = {"OO:__get__", kwlist, 0};
    PyObject *obj_instance;
    PyObject *obj_owner;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_instance, &obj_owner)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_instance = obj_instance;
    PyObject *arg_owner = obj_owner;
    PyObject *retval = CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__(arg___mypyc_self__, arg_instance, arg_owner);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "__get__", -1, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_cls, PyObject *cpy_r_type_str, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject **cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_type_str_repr;
    char cpy_r_r10;
    char cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject **cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject **cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    CPyPtr cpy_r_r30;
    CPyPtr cpy_r_r31;
    CPyPtr cpy_r_r32;
    CPyPtr cpy_r_r33;
    CPyPtr cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    char cpy_r_r38;
    PyObject *cpy_r_r39;
    char cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject *cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject *cpy_r_r46;
    PyObject *cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject **cpy_r_r50;
    PyObject *cpy_r_r51;
    PyObject *cpy_r_r52;
    PyObject *cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject *cpy_r_r55;
    char cpy_r_r56;
    char cpy_r_r57;
    PyObject *cpy_r_r58;
    PyObject *cpy_r_r59;
    PyObject *cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    PyObject *cpy_r_r63;
    PyObject *cpy_r_r64;
    PyObject *cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject *cpy_r_r67;
    PyObject *cpy_r_r68;
    PyObject *cpy_r_r69;
    PyObject **cpy_r_r71;
    PyObject *cpy_r_r72;
    char cpy_r_r73;
    PyObject *cpy_r_r74;
    PyObject *cpy_r_r75;
    PyObject *cpy_r_r76;
    char cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    PyObject *cpy_r_r80;
    PyObject *cpy_r_r81;
    PyObject *cpy_r_r82;
    PyObject *cpy_r_r83;
    PyObject *cpy_r_r84;
    PyObject *cpy_r_r85;
    PyObject *cpy_r_r86;
    PyObject **cpy_r_r88;
    PyObject *cpy_r_r89;
    char cpy_r_r90;
    PyObject *cpy_r_r91;
    PyObject *cpy_r_r92;
    PyObject *cpy_r_r93;
    char cpy_r_r94;
    PyObject *cpy_r_r95;
    PyObject *cpy_r_r96;
    PyObject *cpy_r_r97;
    PyObject *cpy_r_r98;
    PyObject *cpy_r_r99;
    PyObject *cpy_r_r100;
    PyObject *cpy_r_r101;
    PyObject *cpy_r_r102;
    PyObject *cpy_r_r103;
    PyObject **cpy_r_r105;
    PyObject *cpy_r_r106;
    PyObject *cpy_r_r107;
    PyObject **cpy_r_r109;
    PyObject *cpy_r_r110;
    PyObject *cpy_r_r111;
    PyObject **cpy_r_r113;
    PyObject *cpy_r_r114;
    PyObject *cpy_r_r115;
    cpy_r_r0 = ((faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *)cpy_r___mypyc_self__)->___mypyc_env__;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "new_from_type_str_parse_type_str_decorator_obj", "__mypyc_env__", 50, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    CPy_INCREF_NO_IMM(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = ((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r0)->___mypyc_env__;
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "decorator_parse_type_str_env", "__mypyc_env__", 50, CPyStatic_from_type_str___globals);
        goto CPyL65;
    }
    CPy_INCREF_NO_IMM(cpy_r_r1);
CPyL2: ;
    cpy_r_r2 = CPyDef__grammar___normalize(cpy_r_type_str);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL66;
    }
    cpy_r_r3 = CPyStatic_from_type_str___globals;
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'parse' */
    cpy_r_r5 = CPyDict_GetItem(cpy_r_r3, cpy_r_r4);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL67;
    }
    PyObject *cpy_r_r6[1] = {cpy_r_r2};
    cpy_r_r7 = (PyObject **)&cpy_r_r6;
    cpy_r_r8 = PyObject_Vectorcall(cpy_r_r5, cpy_r_r7, 1, 0);
    CPy_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL67;
    }
    cpy_r_r9 = PyObject_Repr(cpy_r_type_str);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL68;
    }
    cpy_r_type_str_repr = cpy_r_r9;
    cpy_r_r10 = CPyStr_Equal(cpy_r_type_str, cpy_r_r2);
    cpy_r_r11 = cpy_r_r10 == 0;
    if (!cpy_r_r11) goto CPyL69;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{:{}}' */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r16[3] = {cpy_r_r13, cpy_r_type_str_repr, cpy_r_r14};
    cpy_r_r17 = (PyObject **)&cpy_r_r16;
    cpy_r_r18 = PyObject_VectorcallMethod(cpy_r_r15, cpy_r_r17, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL70;
    }
    CPy_DECREF(cpy_r_type_str_repr);
    if (likely(PyUnicode_Check(cpy_r_r18)))
        cpy_r_r19 = cpy_r_r18;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 57, CPyStatic_from_type_str___globals, "str", cpy_r_r18);
        goto CPyL68;
    }
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' (normalized to ' */
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{!r:{}}' */
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r24[3] = {cpy_r_r21, cpy_r_r2, cpy_r_r22};
    cpy_r_r25 = (PyObject **)&cpy_r_r24;
    cpy_r_r26 = PyObject_VectorcallMethod(cpy_r_r23, cpy_r_r25, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL71;
    }
    CPy_DECREF(cpy_r_r2);
    if (likely(PyUnicode_Check(cpy_r_r26)))
        cpy_r_r27 = cpy_r_r26;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 57, CPyStatic_from_type_str___globals, "str", cpy_r_r26);
        goto CPyL72;
    }
    cpy_r_r28 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ')' */
    cpy_r_r29 = PyList_New(4);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL73;
    }
    cpy_r_r30 = (CPyPtr)&((PyListObject *)cpy_r_r29)->ob_item;
    cpy_r_r31 = *(CPyPtr *)cpy_r_r30;
    *(PyObject * *)cpy_r_r31 = cpy_r_r19;
    CPy_INCREF(cpy_r_r20);
    cpy_r_r32 = cpy_r_r31 + 8;
    *(PyObject * *)cpy_r_r32 = cpy_r_r20;
    cpy_r_r33 = cpy_r_r31 + 16;
    *(PyObject * *)cpy_r_r33 = cpy_r_r27;
    CPy_INCREF(cpy_r_r28);
    cpy_r_r34 = cpy_r_r31 + 24;
    *(PyObject * *)cpy_r_r34 = cpy_r_r28;
    cpy_r_r35 = PyUnicode_Join(cpy_r_r12, cpy_r_r29);
    CPy_DECREF_NO_IMM(cpy_r_r29);
    if (unlikely(cpy_r_r35 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL74;
    }
    cpy_r_type_str_repr = cpy_r_r35;
CPyL14: ;
    cpy_r_r36 = ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_expected_base;
    if (unlikely(cpy_r_r36 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "parse_type_str_env", "expected_base", 60, CPyStatic_from_type_str___globals);
        goto CPyL75;
    }
    CPy_INCREF(cpy_r_r36);
CPyL15: ;
    cpy_r_r37 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r38 = cpy_r_r36 != cpy_r_r37;
    CPy_DECREF(cpy_r_r36);
    if (!cpy_r_r38) goto CPyL38;
    cpy_r_r39 = (PyObject *)CPyType__grammar___BasicType;
    cpy_r_r40 = CPy_TypeCheck(cpy_r_r8, cpy_r_r39);
    if (cpy_r_r40) {
        goto CPyL24;
    } else
        goto CPyL76;
CPyL17: ;
    cpy_r_r41 = CPy_GetName(cpy_r_cls);
    if (unlikely(cpy_r_r41 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL77;
    }
    if (likely(PyUnicode_Check(cpy_r_r41)))
        cpy_r_r42 = cpy_r_r41;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 64, CPyStatic_from_type_str___globals, "str", cpy_r_r41);
        goto CPyL77;
    }
    cpy_r_r43 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Cannot create ' */
    cpy_r_r44 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' for non-basic type ' */
    cpy_r_r45 = CPyStr_Build(4, cpy_r_r43, cpy_r_r42, cpy_r_r44, cpy_r_type_str_repr);
    CPy_DECREF(cpy_r_r42);
    CPy_DECREF(cpy_r_type_str_repr);
    if (unlikely(cpy_r_r45 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    cpy_r_r46 = CPyModule_builtins;
    cpy_r_r47 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r48 = CPyObject_GetAttr(cpy_r_r46, cpy_r_r47);
    if (unlikely(cpy_r_r48 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL78;
    }
    PyObject *cpy_r_r49[1] = {cpy_r_r45};
    cpy_r_r50 = (PyObject **)&cpy_r_r49;
    cpy_r_r51 = PyObject_Vectorcall(cpy_r_r48, cpy_r_r50, 1, 0);
    CPy_DECREF(cpy_r_r48);
    if (unlikely(cpy_r_r51 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL78;
    }
    CPy_DECREF(cpy_r_r45);
    CPy_Raise(cpy_r_r51);
    CPy_DECREF(cpy_r_r51);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    CPy_Unreachable();
CPyL24: ;
    if (likely(PyObject_TypeCheck(cpy_r_r8, CPyType__grammar___BasicType)))
        cpy_r_r52 = cpy_r_r8;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 68, CPyStatic_from_type_str___globals, "faster_eth_abi._grammar.BasicType", cpy_r_r8);
        goto CPyL75;
    }
    cpy_r_r53 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_r52)->_base;
    if (unlikely(cpy_r_r53 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "BasicType", "base", 68, CPyStatic_from_type_str___globals);
        goto CPyL75;
    }
    CPy_INCREF(cpy_r_r53);
CPyL26: ;
    cpy_r_r54 = ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_expected_base;
    if (unlikely(cpy_r_r54 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "parse_type_str_env", "expected_base", 68, CPyStatic_from_type_str___globals);
        goto CPyL79;
    }
    CPy_INCREF(cpy_r_r54);
CPyL27: ;
    if (likely(cpy_r_r54 != Py_None))
        cpy_r_r55 = cpy_r_r54;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 68, CPyStatic_from_type_str___globals, "str", cpy_r_r54);
        goto CPyL79;
    }
    cpy_r_r56 = CPyStr_Equal(cpy_r_r53, cpy_r_r55);
    CPy_DECREF(cpy_r_r53);
    CPy_DECREF(cpy_r_r55);
    cpy_r_r57 = cpy_r_r56 == 0;
    if (cpy_r_r57) {
        goto CPyL80;
    } else
        goto CPyL38;
CPyL29: ;
    cpy_r_r58 = CPy_GetName(cpy_r_cls);
    if (unlikely(cpy_r_r58 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL81;
    }
    if (likely(PyUnicode_Check(cpy_r_r58)))
        cpy_r_r59 = cpy_r_r58;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 72, CPyStatic_from_type_str___globals, "str", cpy_r_r58);
        goto CPyL81;
    }
    cpy_r_r60 = ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_expected_base;
    if (unlikely(cpy_r_r60 == NULL)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'expected_base' of 'parse_type_str_env' undefined");
    } else {
        CPy_INCREF(cpy_r_r60);
    }
    CPy_DECREF_NO_IMM(cpy_r_r1);
    if (unlikely(cpy_r_r60 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL82;
    }
CPyL32: ;
    if (likely(cpy_r_r60 != Py_None))
        cpy_r_r61 = cpy_r_r60;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 74, CPyStatic_from_type_str___globals, "str", cpy_r_r60);
        goto CPyL82;
    }
    cpy_r_r62 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Cannot create ' */
    cpy_r_r63 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' for type ' */
    cpy_r_r64 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ": expected type with base '" */
    cpy_r_r65 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* "'" */
    cpy_r_r66 = CPyStr_Build(7, cpy_r_r62, cpy_r_r59, cpy_r_r63, cpy_r_type_str_repr, cpy_r_r64, cpy_r_r61, cpy_r_r65);
    CPy_DECREF(cpy_r_r59);
    CPy_DECREF(cpy_r_type_str_repr);
    CPy_DECREF(cpy_r_r61);
    if (unlikely(cpy_r_r66 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    cpy_r_r67 = CPyModule_builtins;
    cpy_r_r68 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r69 = CPyObject_GetAttr(cpy_r_r67, cpy_r_r68);
    if (unlikely(cpy_r_r69 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL83;
    }
    PyObject *cpy_r_r70[1] = {cpy_r_r66};
    cpy_r_r71 = (PyObject **)&cpy_r_r70;
    cpy_r_r72 = PyObject_Vectorcall(cpy_r_r69, cpy_r_r71, 1, 0);
    CPy_DECREF(cpy_r_r69);
    if (unlikely(cpy_r_r72 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL83;
    }
    CPy_DECREF(cpy_r_r66);
    CPy_Raise(cpy_r_r72);
    CPy_DECREF(cpy_r_r72);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    CPy_Unreachable();
CPyL38: ;
    cpy_r_r73 = ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_with_arrlist;
    if (unlikely(cpy_r_r73 == 2)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "parse_type_str_env", "with_arrlist", 78, CPyStatic_from_type_str___globals);
        goto CPyL75;
    }
CPyL39: ;
    if (cpy_r_r73) goto CPyL49;
CPyL40: ;
    cpy_r_r74 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'arrlist' */
    cpy_r_r75 = CPyObject_GetAttr(cpy_r_r8, cpy_r_r74);
    if (unlikely(cpy_r_r75 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL75;
    }
    cpy_r_r76 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r77 = cpy_r_r75 != cpy_r_r76;
    CPy_DECREF(cpy_r_r75);
    if (cpy_r_r77) {
        goto CPyL84;
    } else
        goto CPyL49;
CPyL42: ;
    cpy_r_r78 = CPy_GetName(cpy_r_cls);
    if (unlikely(cpy_r_r78 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL77;
    }
    if (likely(PyUnicode_Check(cpy_r_r78)))
        cpy_r_r79 = cpy_r_r78;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 82, CPyStatic_from_type_str___globals, "str", cpy_r_r78);
        goto CPyL77;
    }
    cpy_r_r80 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Cannot create ' */
    cpy_r_r81 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' for type ' */
    cpy_r_r82 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ': expected type with no array dimension list' */
    cpy_r_r83 = CPyStr_Build(5, cpy_r_r80, cpy_r_r79, cpy_r_r81, cpy_r_type_str_repr, cpy_r_r82);
    CPy_DECREF(cpy_r_r79);
    CPy_DECREF(cpy_r_type_str_repr);
    if (unlikely(cpy_r_r83 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    cpy_r_r84 = CPyModule_builtins;
    cpy_r_r85 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r86 = CPyObject_GetAttr(cpy_r_r84, cpy_r_r85);
    if (unlikely(cpy_r_r86 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL85;
    }
    PyObject *cpy_r_r87[1] = {cpy_r_r83};
    cpy_r_r88 = (PyObject **)&cpy_r_r87;
    cpy_r_r89 = PyObject_Vectorcall(cpy_r_r86, cpy_r_r88, 1, 0);
    CPy_DECREF(cpy_r_r86);
    if (unlikely(cpy_r_r89 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL85;
    }
    CPy_DECREF(cpy_r_r83);
    CPy_Raise(cpy_r_r89);
    CPy_DECREF(cpy_r_r89);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    CPy_Unreachable();
CPyL49: ;
    cpy_r_r90 = ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_with_arrlist;
    if (unlikely(cpy_r_r90 == 2)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'with_arrlist' of 'parse_type_str_env' undefined");
    }
    CPy_DECREF_NO_IMM(cpy_r_r1);
    if (unlikely(cpy_r_r90 == 2)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL86;
    }
CPyL50: ;
    if (!cpy_r_r90) goto CPyL87;
CPyL51: ;
    cpy_r_r91 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'arrlist' */
    cpy_r_r92 = CPyObject_GetAttr(cpy_r_r8, cpy_r_r91);
    if (unlikely(cpy_r_r92 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL86;
    }
    cpy_r_r93 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r94 = cpy_r_r92 == cpy_r_r93;
    CPy_DECREF(cpy_r_r92);
    if (cpy_r_r94) {
        goto CPyL88;
    } else
        goto CPyL87;
CPyL53: ;
    cpy_r_r95 = CPy_GetName(cpy_r_cls);
    if (unlikely(cpy_r_r95 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL77;
    }
    if (likely(PyUnicode_Check(cpy_r_r95)))
        cpy_r_r96 = cpy_r_r95;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 90, CPyStatic_from_type_str___globals, "str", cpy_r_r95);
        goto CPyL77;
    }
    cpy_r_r97 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Cannot create ' */
    cpy_r_r98 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' for type ' */
    cpy_r_r99 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ': expected type with array dimension list' */
    cpy_r_r100 = CPyStr_Build(5, cpy_r_r97, cpy_r_r96, cpy_r_r98, cpy_r_type_str_repr, cpy_r_r99);
    CPy_DECREF(cpy_r_r96);
    CPy_DECREF(cpy_r_type_str_repr);
    if (unlikely(cpy_r_r100 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    cpy_r_r101 = CPyModule_builtins;
    cpy_r_r102 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r103 = CPyObject_GetAttr(cpy_r_r101, cpy_r_r102);
    if (unlikely(cpy_r_r103 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL89;
    }
    PyObject *cpy_r_r104[1] = {cpy_r_r100};
    cpy_r_r105 = (PyObject **)&cpy_r_r104;
    cpy_r_r106 = PyObject_Vectorcall(cpy_r_r103, cpy_r_r105, 1, 0);
    CPy_DECREF(cpy_r_r103);
    if (unlikely(cpy_r_r106 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL89;
    }
    CPy_DECREF(cpy_r_r100);
    CPy_Raise(cpy_r_r106);
    CPy_DECREF(cpy_r_r106);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL64;
    }
    CPy_Unreachable();
CPyL60: ;
    cpy_r_r107 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'validate' */
    PyObject *cpy_r_r108[1] = {cpy_r_r8};
    cpy_r_r109 = (PyObject **)&cpy_r_r108;
    cpy_r_r110 = PyObject_VectorcallMethod(cpy_r_r107, cpy_r_r109, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r110 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL90;
    } else
        goto CPyL91;
CPyL61: ;
    cpy_r_r111 = ((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r0)->_old_from_type_str;
    if (unlikely(cpy_r_r111 == NULL)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'old_from_type_str' of 'decorator_parse_type_str_env' undefined");
    } else {
        CPy_INCREF(cpy_r_r111);
    }
    CPy_DECREF_NO_IMM(cpy_r_r0);
    if (unlikely(cpy_r_r111 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL92;
    }
CPyL62: ;
    PyObject *cpy_r_r112[3] = {cpy_r_cls, cpy_r_r8, cpy_r_registry};
    cpy_r_r113 = (PyObject **)&cpy_r_r112;
    cpy_r_r114 = PyObject_Vectorcall(cpy_r_r111, cpy_r_r113, 3, 0);
    CPy_DECREF(cpy_r_r111);
    if (unlikely(cpy_r_r114 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL92;
    }
    CPy_DECREF(cpy_r_r8);
    return cpy_r_r114;
CPyL64: ;
    cpy_r_r115 = NULL;
    return cpy_r_r115;
CPyL65: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL64;
CPyL66: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    goto CPyL64;
CPyL67: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    goto CPyL64;
CPyL68: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r8);
    goto CPyL64;
CPyL69: ;
    CPy_DECREF(cpy_r_r2);
    goto CPyL14;
CPyL70: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_type_str_repr);
    goto CPyL64;
CPyL71: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_r19);
    goto CPyL64;
CPyL72: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_r19);
    goto CPyL64;
CPyL73: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_r19);
    CPy_DecRef(cpy_r_r27);
    goto CPyL64;
CPyL74: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r8);
    goto CPyL64;
CPyL75: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_type_str_repr);
    goto CPyL64;
CPyL76: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    CPy_DECREF_NO_IMM(cpy_r_r1);
    CPy_DECREF(cpy_r_r8);
    goto CPyL17;
CPyL77: ;
    CPy_DecRef(cpy_r_type_str_repr);
    goto CPyL64;
CPyL78: ;
    CPy_DecRef(cpy_r_r45);
    goto CPyL64;
CPyL79: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_type_str_repr);
    CPy_DecRef(cpy_r_r53);
    goto CPyL64;
CPyL80: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    CPy_DECREF(cpy_r_r8);
    goto CPyL29;
CPyL81: ;
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_type_str_repr);
    goto CPyL64;
CPyL82: ;
    CPy_DecRef(cpy_r_type_str_repr);
    CPy_DecRef(cpy_r_r59);
    goto CPyL64;
CPyL83: ;
    CPy_DecRef(cpy_r_r66);
    goto CPyL64;
CPyL84: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    CPy_DECREF_NO_IMM(cpy_r_r1);
    CPy_DECREF(cpy_r_r8);
    goto CPyL42;
CPyL85: ;
    CPy_DecRef(cpy_r_r83);
    goto CPyL64;
CPyL86: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_type_str_repr);
    goto CPyL64;
CPyL87: ;
    CPy_DECREF(cpy_r_type_str_repr);
    goto CPyL60;
CPyL88: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    CPy_DECREF(cpy_r_r8);
    goto CPyL53;
CPyL89: ;
    CPy_DecRef(cpy_r_r100);
    goto CPyL64;
CPyL90: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r8);
    goto CPyL64;
CPyL91: ;
    CPy_DECREF(cpy_r_r110);
    goto CPyL61;
CPyL92: ;
    CPy_DecRef(cpy_r_r8);
    goto CPyL64;
}

PyObject *CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"cls", "type_str", "registry", 0};
    static CPyArg_Parser parser = {"OOO:__call__", kwlist, 0};
    PyObject *obj_cls;
    PyObject *obj_type_str;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, PyVectorcall_NARGS(nargs), kwnames, &parser, &obj_cls, &obj_type_str, &obj_registry)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_cls = obj_cls;
    PyObject *arg_type_str;
    if (likely(PyUnicode_Check(obj_type_str)))
        arg_type_str = obj_type_str;
    else {
        CPy_TypeError("str", obj_type_str); 
        goto fail;
    }
    PyObject *arg_registry = obj_registry;
    PyObject *retval = CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__(arg___mypyc_self__, arg_cls, arg_type_str, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r1 = cpy_r_instance == cpy_r_r0;
    if (!cpy_r_r1) goto CPyL2;
    CPy_INCREF(cpy_r___mypyc_self__);
    return cpy_r___mypyc_self__;
CPyL2: ;
    cpy_r_r2 = PyMethod_New(cpy_r___mypyc_self__, cpy_r_instance);
    if (cpy_r_r2 == NULL) goto CPyL4;
    return cpy_r_r2;
CPyL4: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy_from_type_str___decorator_parse_type_str_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"instance", "owner", 0};
    static CPyArg_Parser parser = {"OO:__get__", kwlist, 0};
    PyObject *obj_instance;
    PyObject *obj_owner;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_instance, &obj_owner)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_instance = obj_instance;
    PyObject *arg_owner = obj_owner;
    PyObject *retval = CPyDef_from_type_str___decorator_parse_type_str_obj_____get__(arg___mypyc_self__, arg_instance, arg_owner);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "__get__", -1, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_old_from_type_str) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject **cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject **cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    int32_t cpy_r_r18;
    char cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject **cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    cpy_r_r0 = ((faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *)cpy_r___mypyc_self__)->___mypyc_env__;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "decorator", "decorator_parse_type_str_obj", "__mypyc_env__", 48, CPyStatic_from_type_str___globals);
        goto CPyL14;
    }
    CPy_INCREF_NO_IMM(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyDef_from_type_str___decorator_parse_type_str_env();
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL15;
    }
    if (((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->___mypyc_env__);
    }
    ((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->___mypyc_env__ = cpy_r_r0;
    cpy_r_r2 = 1;
    if (unlikely(!cpy_r_r2)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL16;
    }
    CPy_INCREF(cpy_r_old_from_type_str);
    if (((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->_old_from_type_str != NULL) {
        CPy_DECREF(((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->_old_from_type_str);
    }
    ((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->_old_from_type_str = cpy_r_old_from_type_str;
    cpy_r_r3 = 1;
    if (unlikely(!cpy_r_r3)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL16;
    }
    cpy_r_r4 = CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj();
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL16;
    }
    CPy_INCREF_NO_IMM(cpy_r_r1);
    if (((faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *)cpy_r_r4)->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(((faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *)cpy_r_r4)->___mypyc_env__);
    }
    ((faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *)cpy_r_r4)->___mypyc_env__ = cpy_r_r1;
    cpy_r_r5 = 1;
    if (unlikely(!cpy_r_r5)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL17;
    }
    cpy_r_r6 = ((faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *)cpy_r_r1)->_old_from_type_str;
    if (unlikely(cpy_r_r6 == NULL)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'old_from_type_str' of 'decorator_parse_type_str_env' undefined");
    } else {
        CPy_INCREF(cpy_r_r6);
    }
    CPy_DECREF_NO_IMM(cpy_r_r1);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL18;
    }
CPyL7: ;
    cpy_r_r7 = CPyModule_functools;
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'wraps' */
    cpy_r_r9 = CPyObject_GetAttr(cpy_r_r7, cpy_r_r8);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL19;
    }
    PyObject *cpy_r_r10[1] = {cpy_r_r6};
    cpy_r_r11 = (PyObject **)&cpy_r_r10;
    cpy_r_r12 = PyObject_Vectorcall(cpy_r_r9, cpy_r_r11, 1, 0);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL19;
    }
    CPy_DECREF(cpy_r_r6);
    PyObject *cpy_r_r13[1] = {cpy_r_r4};
    cpy_r_r14 = (PyObject **)&cpy_r_r13;
    cpy_r_r15 = PyObject_Vectorcall(cpy_r_r12, cpy_r_r14, 1, 0);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL18;
    }
    CPy_DECREF_NO_IMM(cpy_r_r4);
    CPy_INCREF(cpy_r_r15);
    cpy_r_r16 = CPyStatic_from_type_str___globals;
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'new_from_type_str' */
    cpy_r_r18 = PyDict_SetItem(cpy_r_r16, cpy_r_r17, cpy_r_r15);
    CPy_DECREF(cpy_r_r15);
    cpy_r_r19 = cpy_r_r18 >= 0;
    if (unlikely(!cpy_r_r19)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL20;
    }
    cpy_r_r20 = CPyModule_builtins;
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'classmethod' */
    cpy_r_r22 = CPyObject_GetAttr(cpy_r_r20, cpy_r_r21);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL20;
    }
    PyObject *cpy_r_r23[1] = {cpy_r_r15};
    cpy_r_r24 = (PyObject **)&cpy_r_r23;
    cpy_r_r25 = PyObject_Vectorcall(cpy_r_r22, cpy_r_r24, 1, 0);
    CPy_DECREF(cpy_r_r22);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL20;
    }
    CPy_DECREF(cpy_r_r15);
    return cpy_r_r25;
CPyL14: ;
    cpy_r_r26 = NULL;
    return cpy_r_r26;
CPyL15: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL14;
CPyL16: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL14;
CPyL17: ;
    CPy_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r4);
    goto CPyL14;
CPyL18: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL14;
CPyL19: ;
    CPy_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r6);
    goto CPyL14;
CPyL20: ;
    CPy_DecRef(cpy_r_r15);
    goto CPyL14;
}

PyObject *CPyPy_from_type_str___decorator_parse_type_str_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"old_from_type_str", 0};
    static CPyArg_Parser parser = {"O:__call__", kwlist, 0};
    PyObject *obj_old_from_type_str;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, PyVectorcall_NARGS(nargs), kwnames, &parser, &obj_old_from_type_str)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_old_from_type_str = obj_old_from_type_str;
    PyObject *retval = CPyDef_from_type_str___decorator_parse_type_str_obj_____call__(arg___mypyc_self__, arg_old_from_type_str);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "decorator", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___parse_type_str(PyObject *cpy_r_expected_base, char cpy_r_with_arrlist) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    PyObject *cpy_r_decorator;
    PyObject *cpy_r_r6;
    if (cpy_r_expected_base != NULL) goto CPyL11;
    cpy_r_r0 = Py_None;
    cpy_r_expected_base = cpy_r_r0;
CPyL2: ;
    if (cpy_r_with_arrlist != 2) goto CPyL4;
    cpy_r_with_arrlist = 0;
CPyL4: ;
    cpy_r_r1 = CPyDef_from_type_str___parse_type_str_env();
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL12;
    }
    if (((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_expected_base != NULL) {
        CPy_DECREF(((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_expected_base);
    }
    ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_expected_base = cpy_r_expected_base;
    cpy_r_r2 = 1;
    if (unlikely(!cpy_r_r2)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL13;
    }
    ((faster_eth_abi___from_type_str___parse_type_str_envObject *)cpy_r_r1)->_with_arrlist = cpy_r_with_arrlist;
    cpy_r_r3 = 1;
    if (unlikely(!cpy_r_r3)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL13;
    }
    cpy_r_r4 = CPyDef_from_type_str___decorator_parse_type_str_obj();
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL13;
    }
    if (((faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *)cpy_r_r4)->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(((faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *)cpy_r_r4)->___mypyc_env__);
    }
    ((faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *)cpy_r_r4)->___mypyc_env__ = cpy_r_r1;
    cpy_r_r5 = 1;
    if (unlikely(!cpy_r_r5)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL14;
    }
    cpy_r_decorator = cpy_r_r4;
    return cpy_r_decorator;
CPyL10: ;
    cpy_r_r6 = NULL;
    return cpy_r_r6;
CPyL11: ;
    CPy_INCREF(cpy_r_expected_base);
    goto CPyL2;
CPyL12: ;
    CPy_DecRef(cpy_r_expected_base);
    goto CPyL10;
CPyL13: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL10;
CPyL14: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL10;
}

PyObject *CPyPy_from_type_str___parse_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"expected_base", "with_arrlist", 0};
    static CPyArg_Parser parser = {"|OO:parse_type_str", kwlist, 0};
    PyObject *obj_expected_base = NULL;
    PyObject *obj_with_arrlist = NULL;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_expected_base, &obj_with_arrlist)) {
        return NULL;
    }
    PyObject *arg_expected_base;
    if (obj_expected_base == NULL) {
        arg_expected_base = NULL;
        goto __LL29;
    }
    if (PyUnicode_Check(obj_expected_base))
        arg_expected_base = obj_expected_base;
    else {
        arg_expected_base = NULL;
    }
    if (arg_expected_base != NULL) goto __LL29;
    if (obj_expected_base == Py_None)
        arg_expected_base = obj_expected_base;
    else {
        arg_expected_base = NULL;
    }
    if (arg_expected_base != NULL) goto __LL29;
    CPy_TypeError("str or None", obj_expected_base); 
    goto fail;
__LL29: ;
    char arg_with_arrlist;
    if (obj_with_arrlist == NULL) {
        arg_with_arrlist = 2;
    } else if (unlikely(!PyBool_Check(obj_with_arrlist))) {
        CPy_TypeError("bool", obj_with_arrlist); goto fail;
    } else
        arg_with_arrlist = obj_with_arrlist == Py_True;
    PyObject *retval = CPyDef_from_type_str___parse_type_str(arg_expected_base, arg_with_arrlist);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r1 = cpy_r_instance == cpy_r_r0;
    if (!cpy_r_r1) goto CPyL2;
    CPy_INCREF(cpy_r___mypyc_self__);
    return cpy_r___mypyc_self__;
CPyL2: ;
    cpy_r_r2 = PyMethod_New(cpy_r___mypyc_self__, cpy_r_instance);
    if (cpy_r_r2 == NULL) goto CPyL4;
    return cpy_r_r2;
CPyL4: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"instance", "owner", 0};
    static CPyArg_Parser parser = {"OO:__get__", kwlist, 0};
    PyObject *obj_instance;
    PyObject *obj_owner;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_instance, &obj_owner)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_instance = obj_instance;
    PyObject *arg_owner = obj_owner;
    PyObject *retval = CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__(arg___mypyc_self__, arg_instance, arg_owner);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "__get__", -1, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_cls, PyObject *cpy_r_type_str, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject **cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_type_str_repr;
    char cpy_r_r11;
    char cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject **cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    char cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject **cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    cpy_r_r0 = ((faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *)cpy_r___mypyc_self__)->___mypyc_env__;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/from_type_str.py", "new_from_type_str", "new_from_type_str_parse_tuple_type_str_obj", "__mypyc_env__", 115, CPyStatic_from_type_str___globals);
        goto CPyL23;
    }
    CPy_INCREF_NO_IMM(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyDef__grammar___normalize(cpy_r_type_str);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL24;
    }
    cpy_r_r2 = CPyStatic_from_type_str___globals;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'parse' */
    cpy_r_r4 = CPyDict_GetItem(cpy_r_r2, cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL25;
    }
    PyObject *cpy_r_r5[1] = {cpy_r_r1};
    cpy_r_r6 = (PyObject **)&cpy_r_r5;
    cpy_r_r7 = PyObject_Vectorcall(cpy_r_r4, cpy_r_r6, 1, 0);
    CPy_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL25;
    }
    cpy_r_r8 = (PyObject *)CPyType__grammar___TupleType;
    cpy_r_r9 = CPy_TypeCheck(cpy_r_r7, cpy_r_r8);
    if (cpy_r_r9) {
        goto CPyL26;
    } else
        goto CPyL27;
CPyL5: ;
    cpy_r_r10 = PyObject_Repr(cpy_r_type_str);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL28;
    }
    cpy_r_type_str_repr = cpy_r_r10;
    cpy_r_r11 = CPyStr_Equal(cpy_r_type_str, cpy_r_r1);
    cpy_r_r12 = cpy_r_r11 == 0;
    if (!cpy_r_r12) goto CPyL29;
    cpy_r_r13 = PyObject_Repr(cpy_r_r1);
    CPy_DECREF(cpy_r_r1);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' (normalized to ' */
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ')' */
    cpy_r_r16 = CPyStr_Build(4, cpy_r_type_str_repr, cpy_r_r14, cpy_r_r13, cpy_r_r15);
    CPy_DECREF(cpy_r_type_str_repr);
    CPy_DECREF(cpy_r_r13);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL23;
    }
    cpy_r_type_str_repr = cpy_r_r16;
CPyL10: ;
    cpy_r_r17 = CPy_GetName(cpy_r_cls);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    if (likely(PyUnicode_Check(cpy_r_r17)))
        cpy_r_r18 = cpy_r_r17;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 128, CPyStatic_from_type_str___globals, "str", cpy_r_r17);
        goto CPyL30;
    }
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Cannot create ' */
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' for non-tuple type ' */
    cpy_r_r21 = CPyStr_Build(4, cpy_r_r19, cpy_r_r18, cpy_r_r20, cpy_r_type_str_repr);
    CPy_DECREF(cpy_r_r18);
    CPy_DECREF(cpy_r_type_str_repr);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL23;
    }
    cpy_r_r22 = CPyModule_builtins;
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r24 = CPyObject_GetAttr(cpy_r_r22, cpy_r_r23);
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL31;
    }
    PyObject *cpy_r_r25[1] = {cpy_r_r21};
    cpy_r_r26 = (PyObject **)&cpy_r_r25;
    cpy_r_r27 = PyObject_Vectorcall(cpy_r_r24, cpy_r_r26, 1, 0);
    CPy_DECREF(cpy_r_r24);
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL31;
    }
    CPy_DECREF(cpy_r_r21);
    CPy_Raise(cpy_r_r27);
    CPy_DECREF(cpy_r_r27);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL23;
    }
    CPy_Unreachable();
CPyL17: ;
    CPy_INCREF(cpy_r_r7);
    if (likely(PyObject_TypeCheck(cpy_r_r7, CPyType__grammar___TupleType)))
        cpy_r_r28 = cpy_r_r7;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 133, CPyStatic_from_type_str___globals, "faster_eth_abi._grammar.TupleType", cpy_r_r7);
        goto CPyL32;
    }
    cpy_r_r29 = CPY_GET_METHOD(cpy_r_r28, CPyType__grammar___TupleType, 14, faster_eth_abi____grammar___TupleTypeObject, char (*)(PyObject *))(cpy_r_r28); /* validate */
    CPy_DECREF_NO_IMM(cpy_r_r28);
    if (unlikely(cpy_r_r29 == 2)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL32;
    }
    if (likely(PyObject_TypeCheck(cpy_r_r7, CPyType__grammar___TupleType)))
        cpy_r_r30 = cpy_r_r7;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", 135, CPyStatic_from_type_str___globals, "faster_eth_abi._grammar.TupleType", cpy_r_r7);
        goto CPyL24;
    }
    cpy_r_r31 = ((faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *)cpy_r_r0)->_old_from_type_str;
    if (unlikely(cpy_r_r31 == NULL)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'old_from_type_str' of 'parse_tuple_type_str_env' undefined");
    } else {
        CPy_INCREF(cpy_r_r31);
    }
    CPy_DECREF_NO_IMM(cpy_r_r0);
    if (unlikely(cpy_r_r31 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL33;
    }
CPyL21: ;
    PyObject *cpy_r_r32[3] = {cpy_r_cls, cpy_r_r30, cpy_r_registry};
    cpy_r_r33 = (PyObject **)&cpy_r_r32;
    cpy_r_r34 = PyObject_Vectorcall(cpy_r_r31, cpy_r_r33, 3, 0);
    CPy_DECREF(cpy_r_r31);
    if (unlikely(cpy_r_r34 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL33;
    }
    CPy_DECREF_NO_IMM(cpy_r_r30);
    return cpy_r_r34;
CPyL23: ;
    cpy_r_r35 = NULL;
    return cpy_r_r35;
CPyL24: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL23;
CPyL25: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r1);
    goto CPyL23;
CPyL26: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL17;
CPyL27: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    CPy_DECREF(cpy_r_r7);
    goto CPyL5;
CPyL28: ;
    CPy_DecRef(cpy_r_r1);
    goto CPyL23;
CPyL29: ;
    CPy_DECREF(cpy_r_r1);
    goto CPyL10;
CPyL30: ;
    CPy_DecRef(cpy_r_type_str_repr);
    goto CPyL23;
CPyL31: ;
    CPy_DecRef(cpy_r_r21);
    goto CPyL23;
CPyL32: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r7);
    goto CPyL23;
CPyL33: ;
    CPy_DecRef(cpy_r_r30);
    goto CPyL23;
}

PyObject *CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"cls", "type_str", "registry", 0};
    static CPyArg_Parser parser = {"OOO:__call__", kwlist, 0};
    PyObject *obj_cls;
    PyObject *obj_type_str;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, PyVectorcall_NARGS(nargs), kwnames, &parser, &obj_cls, &obj_type_str, &obj_registry)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_cls = obj_cls;
    PyObject *arg_type_str;
    if (likely(PyUnicode_Check(obj_type_str)))
        arg_type_str = obj_type_str;
    else {
        CPy_TypeError("str", obj_type_str); 
        goto fail;
    }
    PyObject *arg_registry = obj_registry;
    PyObject *retval = CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__(arg___mypyc_self__, arg_cls, arg_type_str, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "new_from_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
    return NULL;
}

PyObject *CPyDef_from_type_str___parse_tuple_type_str(PyObject *cpy_r_old_from_type_str) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    char cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject **cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject **cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    int32_t cpy_r_r16;
    char cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject **cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    cpy_r_r0 = CPyDef_from_type_str___parse_tuple_type_str_env();
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL12;
    }
    CPy_INCREF(cpy_r_old_from_type_str);
    if (((faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *)cpy_r_r0)->_old_from_type_str != NULL) {
        CPy_DECREF(((faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *)cpy_r_r0)->_old_from_type_str);
    }
    ((faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *)cpy_r_r0)->_old_from_type_str = cpy_r_old_from_type_str;
    cpy_r_r1 = 1;
    if (unlikely(!cpy_r_r1)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL13;
    }
    cpy_r_r2 = CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj();
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL13;
    }
    CPy_INCREF_NO_IMM(cpy_r_r0);
    if (((faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *)cpy_r_r2)->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(((faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *)cpy_r_r2)->___mypyc_env__);
    }
    ((faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *)cpy_r_r2)->___mypyc_env__ = cpy_r_r0;
    cpy_r_r3 = 1;
    if (unlikely(!cpy_r_r3)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL14;
    }
    cpy_r_r4 = ((faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *)cpy_r_r0)->_old_from_type_str;
    if (unlikely(cpy_r_r4 == NULL)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'old_from_type_str' of 'parse_tuple_type_str_env' undefined");
    } else {
        CPy_INCREF(cpy_r_r4);
    }
    CPy_DECREF_NO_IMM(cpy_r_r0);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL15;
    }
CPyL5: ;
    cpy_r_r5 = CPyModule_functools;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'wraps' */
    cpy_r_r7 = CPyObject_GetAttr(cpy_r_r5, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL16;
    }
    PyObject *cpy_r_r8[1] = {cpy_r_r4};
    cpy_r_r9 = (PyObject **)&cpy_r_r8;
    cpy_r_r10 = PyObject_Vectorcall(cpy_r_r7, cpy_r_r9, 1, 0);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL16;
    }
    CPy_DECREF(cpy_r_r4);
    PyObject *cpy_r_r11[1] = {cpy_r_r2};
    cpy_r_r12 = (PyObject **)&cpy_r_r11;
    cpy_r_r13 = PyObject_Vectorcall(cpy_r_r10, cpy_r_r12, 1, 0);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL15;
    }
    CPy_DECREF_NO_IMM(cpy_r_r2);
    CPy_INCREF(cpy_r_r13);
    cpy_r_r14 = CPyStatic_from_type_str___globals;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'new_from_type_str' */
    cpy_r_r16 = PyDict_SetItem(cpy_r_r14, cpy_r_r15, cpy_r_r13);
    CPy_DECREF(cpy_r_r13);
    cpy_r_r17 = cpy_r_r16 >= 0;
    if (unlikely(!cpy_r_r17)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL17;
    }
    cpy_r_r18 = CPyModule_builtins;
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'classmethod' */
    cpy_r_r20 = CPyObject_GetAttr(cpy_r_r18, cpy_r_r19);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL17;
    }
    PyObject *cpy_r_r21[1] = {cpy_r_r13};
    cpy_r_r22 = (PyObject **)&cpy_r_r21;
    cpy_r_r23 = PyObject_Vectorcall(cpy_r_r20, cpy_r_r22, 1, 0);
    CPy_DECREF(cpy_r_r20);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL17;
    }
    CPy_DECREF(cpy_r_r13);
    return cpy_r_r23;
CPyL12: ;
    cpy_r_r24 = NULL;
    return cpy_r_r24;
CPyL13: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL12;
CPyL14: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r2);
    goto CPyL12;
CPyL15: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL12;
CPyL16: ;
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r4);
    goto CPyL12;
CPyL17: ;
    CPy_DecRef(cpy_r_r13);
    goto CPyL12;
}

PyObject *CPyPy_from_type_str___parse_tuple_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"old_from_type_str", 0};
    static CPyArg_Parser parser = {"O:parse_tuple_type_str", kwlist, 0};
    PyObject *obj_old_from_type_str;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_old_from_type_str)) {
        return NULL;
    }
    PyObject *arg_old_from_type_str = obj_old_from_type_str;
    PyObject *retval = CPyDef_from_type_str___parse_tuple_type_str(arg_old_from_type_str);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/from_type_str.py", "parse_tuple_type_str", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
    return NULL;
}

char CPyDef_from_type_str_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject **cpy_r_r5;
    void *cpy_r_r7;
    void *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    char cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject **cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject *cpy_r_r44;
    PyObject *cpy_r_r45;
    int32_t cpy_r_r46;
    char cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject *cpy_r_r49;
    PyObject *cpy_r_r50;
    PyObject *cpy_r_r51;
    PyObject *cpy_r_r52;
    PyObject *cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject *cpy_r_r55;
    PyObject *cpy_r_r56;
    CPyPtr cpy_r_r57;
    CPyPtr cpy_r_r58;
    CPyPtr cpy_r_r59;
    CPyPtr cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    PyObject *cpy_r_r63;
    tuple_T2OO cpy_r_r64;
    PyObject *cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject *cpy_r_r67;
    PyObject *cpy_r_r68;
    int32_t cpy_r_r69;
    char cpy_r_r70;
    PyObject *cpy_r_r71;
    PyObject *cpy_r_r72;
    PyObject *cpy_r_r73;
    PyObject *cpy_r_r74;
    PyObject *cpy_r_r75;
    PyObject *cpy_r_r76;
    PyObject *cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    PyObject *cpy_r_r80;
    PyObject *cpy_r_r81;
    PyObject *cpy_r_r82;
    PyObject *cpy_r_r83;
    CPyPtr cpy_r_r84;
    CPyPtr cpy_r_r85;
    CPyPtr cpy_r_r86;
    PyObject *cpy_r_r87;
    PyObject *cpy_r_r88;
    PyObject *cpy_r_r89;
    tuple_T3OOO cpy_r_r90;
    PyObject *cpy_r_r91;
    PyObject *cpy_r_r92;
    PyObject *cpy_r_r93;
    PyObject *cpy_r_r94;
    int32_t cpy_r_r95;
    char cpy_r_r96;
    char cpy_r_r97;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", -1, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = (PyObject **)&CPyModule_functools;
    PyObject **cpy_r_r6[1] = {cpy_r_r5};
    cpy_r_r7 = (void *)&cpy_r_r6;
    int64_t cpy_r_r8[1] = {1};
    cpy_r_r9 = (void *)&cpy_r_r8;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* (('functools', 'functools', 'functools'),) */
    cpy_r_r11 = CPyStatic_from_type_str___globals;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi/from_type_str.py' */
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '<module>' */
    cpy_r_r14 = CPyImport_ImportMany(cpy_r_r10, cpy_r_r7, cpy_r_r11, cpy_r_r12, cpy_r_r13, cpy_r_r9);
    if (!cpy_r_r14) goto CPyL30;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TYPE_CHECKING', 'Any', 'Callable', 'Optional', 'Type',
                                    'TypeVar') */
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r17 = CPyStatic_from_type_str___globals;
    cpy_r_r18 = CPyImport_ImportFromMany(cpy_r_r16, cpy_r_r15, cpy_r_r15, cpy_r_r17);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    CPyModule_typing = cpy_r_r18;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r18);
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TypeStr',) */
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'eth_typing' */
    cpy_r_r21 = CPyStatic_from_type_str___globals;
    cpy_r_r22 = CPyImport_ImportFromMany(cpy_r_r20, cpy_r_r19, cpy_r_r19, cpy_r_r21);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    CPyModule_eth_typing = cpy_r_r22;
    CPy_INCREF(CPyModule_eth_typing);
    CPy_DECREF(cpy_r_r22);
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('ABIType', 'BasicType', 'TupleType', 'normalize') */
    cpy_r_r24 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi._grammar' */
    cpy_r_r25 = CPyStatic_from_type_str___globals;
    cpy_r_r26 = CPyImport_ImportFromMany(cpy_r_r24, cpy_r_r23, cpy_r_r23, cpy_r_r25);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    CPyModule_faster_eth_abi____grammar = cpy_r_r26;
    CPy_INCREF(CPyModule_faster_eth_abi____grammar);
    CPy_DECREF(cpy_r_r26);
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('parse',) */
    cpy_r_r28 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.grammar' */
    cpy_r_r29 = CPyStatic_from_type_str___globals;
    cpy_r_r30 = CPyImport_ImportFromMany(cpy_r_r28, cpy_r_r27, cpy_r_r27, cpy_r_r29);
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    CPyModule_faster_eth_abi___grammar = cpy_r_r30;
    CPy_INCREF(CPyModule_faster_eth_abi___grammar);
    CPy_DECREF(cpy_r_r30);
    cpy_r_r31 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TType' */
    cpy_r_r32 = CPyStatic_from_type_str___globals;
    cpy_r_r33 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Type' */
    cpy_r_r34 = CPyDict_GetItem(cpy_r_r32, cpy_r_r33);
    if (unlikely(cpy_r_r34 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r35 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseCoder' */
    cpy_r_r36 = PyObject_GetItem(cpy_r_r34, cpy_r_r35);
    CPy_DECREF(cpy_r_r34);
    if (unlikely(cpy_r_r36 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r37 = CPyStatic_from_type_str___globals;
    cpy_r_r38 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TypeVar' */
    cpy_r_r39 = CPyDict_GetItem(cpy_r_r37, cpy_r_r38);
    if (unlikely(cpy_r_r39 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL31;
    }
    PyObject *cpy_r_r40[2] = {cpy_r_r31, cpy_r_r36};
    cpy_r_r41 = (PyObject **)&cpy_r_r40;
    cpy_r_r42 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('bound',) */
    cpy_r_r43 = PyObject_Vectorcall(cpy_r_r39, cpy_r_r41, 1, cpy_r_r42);
    CPy_DECREF(cpy_r_r39);
    if (unlikely(cpy_r_r43 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL31;
    }
    CPy_DECREF(cpy_r_r36);
    cpy_r_r44 = CPyStatic_from_type_str___globals;
    cpy_r_r45 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TType' */
    cpy_r_r46 = CPyDict_SetItem(cpy_r_r44, cpy_r_r45, cpy_r_r43);
    CPy_DECREF(cpy_r_r43);
    cpy_r_r47 = cpy_r_r46 >= 0;
    if (unlikely(!cpy_r_r47)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r48 = CPyStatic_from_type_str___globals;
    cpy_r_r49 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Callable' */
    cpy_r_r50 = CPyDict_GetItem(cpy_r_r48, cpy_r_r49);
    if (unlikely(cpy_r_r50 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r51 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseCoder' */
    cpy_r_r52 = (PyObject *)CPyType__grammar___ABIType;
    cpy_r_r53 = CPyStatic_from_type_str___globals;
    cpy_r_r54 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Any' */
    cpy_r_r55 = CPyDict_GetItem(cpy_r_r53, cpy_r_r54);
    if (unlikely(cpy_r_r55 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL32;
    }
    cpy_r_r56 = PyList_New(3);
    if (unlikely(cpy_r_r56 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL33;
    }
    cpy_r_r57 = (CPyPtr)&((PyListObject *)cpy_r_r56)->ob_item;
    cpy_r_r58 = *(CPyPtr *)cpy_r_r57;
    CPy_INCREF(cpy_r_r51);
    *(PyObject * *)cpy_r_r58 = cpy_r_r51;
    CPy_INCREF(cpy_r_r52);
    cpy_r_r59 = cpy_r_r58 + 8;
    *(PyObject * *)cpy_r_r59 = cpy_r_r52;
    cpy_r_r60 = cpy_r_r58 + 16;
    *(PyObject * *)cpy_r_r60 = cpy_r_r55;
    cpy_r_r61 = CPyStatic_from_type_str___globals;
    cpy_r_r62 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TType' */
    cpy_r_r63 = CPyDict_GetItem(cpy_r_r61, cpy_r_r62);
    if (unlikely(cpy_r_r63 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL34;
    }
    cpy_r_r64.f0 = cpy_r_r56;
    cpy_r_r64.f1 = cpy_r_r63;
    cpy_r_r65 = PyTuple_New(2);
    if (unlikely(cpy_r_r65 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp30 = cpy_r_r64.f0;
    PyTuple_SET_ITEM(cpy_r_r65, 0, __tmp30);
    PyObject *__tmp31 = cpy_r_r64.f1;
    PyTuple_SET_ITEM(cpy_r_r65, 1, __tmp31);
    cpy_r_r66 = PyObject_GetItem(cpy_r_r50, cpy_r_r65);
    CPy_DECREF(cpy_r_r50);
    CPy_DECREF(cpy_r_r65);
    if (unlikely(cpy_r_r66 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r67 = CPyStatic_from_type_str___globals;
    cpy_r_r68 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'OldFromTypeStr' */
    cpy_r_r69 = CPyDict_SetItem(cpy_r_r67, cpy_r_r68, cpy_r_r66);
    CPy_DECREF(cpy_r_r66);
    cpy_r_r70 = cpy_r_r69 >= 0;
    if (unlikely(!cpy_r_r70)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    if (!0) goto CPyL29;
    cpy_r_r71 = CPyModule_builtins;
    cpy_r_r72 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'classmethod' */
    cpy_r_r73 = CPyObject_GetAttr(cpy_r_r71, cpy_r_r72);
    if (unlikely(cpy_r_r73 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r74 = CPyStatic_from_type_str___globals;
    cpy_r_r75 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TType' */
    cpy_r_r76 = CPyDict_GetItem(cpy_r_r74, cpy_r_r75);
    if (unlikely(cpy_r_r76 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL35;
    }
    cpy_r_r77 = CPyStatic_from_type_str___globals;
    cpy_r_r78 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TypeStr' */
    cpy_r_r79 = CPyDict_GetItem(cpy_r_r77, cpy_r_r78);
    if (unlikely(cpy_r_r79 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL36;
    }
    cpy_r_r80 = CPyStatic_from_type_str___globals;
    cpy_r_r81 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Any' */
    cpy_r_r82 = CPyDict_GetItem(cpy_r_r80, cpy_r_r81);
    if (unlikely(cpy_r_r82 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL37;
    }
    cpy_r_r83 = PyList_New(2);
    if (unlikely(cpy_r_r83 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL38;
    }
    cpy_r_r84 = (CPyPtr)&((PyListObject *)cpy_r_r83)->ob_item;
    cpy_r_r85 = *(CPyPtr *)cpy_r_r84;
    *(PyObject * *)cpy_r_r85 = cpy_r_r79;
    cpy_r_r86 = cpy_r_r85 + 8;
    *(PyObject * *)cpy_r_r86 = cpy_r_r82;
    cpy_r_r87 = CPyStatic_from_type_str___globals;
    cpy_r_r88 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TType' */
    cpy_r_r89 = CPyDict_GetItem(cpy_r_r87, cpy_r_r88);
    if (unlikely(cpy_r_r89 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL39;
    }
    cpy_r_r90.f0 = cpy_r_r76;
    cpy_r_r90.f1 = cpy_r_r83;
    cpy_r_r90.f2 = cpy_r_r89;
    cpy_r_r91 = PyTuple_New(3);
    if (unlikely(cpy_r_r91 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp32 = cpy_r_r90.f0;
    PyTuple_SET_ITEM(cpy_r_r91, 0, __tmp32);
    PyObject *__tmp33 = cpy_r_r90.f1;
    PyTuple_SET_ITEM(cpy_r_r91, 1, __tmp33);
    PyObject *__tmp34 = cpy_r_r90.f2;
    PyTuple_SET_ITEM(cpy_r_r91, 2, __tmp34);
    cpy_r_r92 = PyObject_GetItem(cpy_r_r73, cpy_r_r91);
    CPy_DECREF(cpy_r_r73);
    CPy_DECREF(cpy_r_r91);
    if (unlikely(cpy_r_r92 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
    cpy_r_r93 = CPyStatic_from_type_str___globals;
    cpy_r_r94 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'NewFromTypeStr' */
    cpy_r_r95 = CPyDict_SetItem(cpy_r_r93, cpy_r_r94, cpy_r_r92);
    CPy_DECREF(cpy_r_r92);
    cpy_r_r96 = cpy_r_r95 >= 0;
    if (unlikely(!cpy_r_r96)) {
        CPy_AddTraceback("faster_eth_abi/from_type_str.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_from_type_str___globals);
        goto CPyL30;
    }
CPyL29: ;
    return 1;
CPyL30: ;
    cpy_r_r97 = 2;
    return cpy_r_r97;
CPyL31: ;
    CPy_DecRef(cpy_r_r36);
    goto CPyL30;
CPyL32: ;
    CPy_DecRef(cpy_r_r50);
    goto CPyL30;
CPyL33: ;
    CPy_DecRef(cpy_r_r50);
    CPy_DecRef(cpy_r_r55);
    goto CPyL30;
CPyL34: ;
    CPy_DecRef(cpy_r_r50);
    CPy_DecRef(cpy_r_r56);
    goto CPyL30;
CPyL35: ;
    CPy_DecRef(cpy_r_r73);
    goto CPyL30;
CPyL36: ;
    CPy_DecRef(cpy_r_r73);
    CPy_DecRef(cpy_r_r76);
    goto CPyL30;
CPyL37: ;
    CPy_DecRef(cpy_r_r73);
    CPy_DecRef(cpy_r_r76);
    CPy_DecRef(cpy_r_r79);
    goto CPyL30;
CPyL38: ;
    CPy_DecRef(cpy_r_r73);
    CPy_DecRef(cpy_r_r76);
    CPy_DecRef(cpy_r_r79);
    CPy_DecRef(cpy_r_r82);
    goto CPyL30;
CPyL39: ;
    CPy_DecRef(cpy_r_r73);
    CPy_DecRef(cpy_r_r76);
    CPy_DecRef(cpy_r_r83);
    goto CPyL30;
}
static PyMethodDef packedmodule_methods[] = {
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___packed(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___packed__internal, "__name__");
    CPyStatic_packed___globals = PyModule_GetDict(CPyModule_faster_eth_abi___packed__internal);
    if (unlikely(CPyStatic_packed___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_packed_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___packed__internal);
    Py_CLEAR(modname);
    CPy_XDECREF(CPyStatic_packed___default_encoder_packed);
    CPyStatic_packed___default_encoder_packed = NULL;
    CPy_XDECREF(CPyStatic_packed___encode_packed);
    CPyStatic_packed___encode_packed = NULL;
    CPy_XDECREF(CPyStatic_packed___is_encodable_packed);
    CPyStatic_packed___is_encodable_packed = NULL;
    return -1;
}
static struct PyModuleDef packedmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.packed",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    packedmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___packed(void)
{
    if (CPyModule_faster_eth_abi___packed__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___packed__internal);
        return CPyModule_faster_eth_abi___packed__internal;
    }
    CPyModule_faster_eth_abi___packed__internal = PyModule_Create(&packedmodule);
    if (unlikely(CPyModule_faster_eth_abi___packed__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___packed(CPyModule_faster_eth_abi___packed__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___packed__internal;
    fail:
    return NULL;
}

char CPyDef_packed_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject **cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    int32_t cpy_r_r28;
    char cpy_r_r29;
    PyObject *cpy_r_r30;
    char cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    int32_t cpy_r_r36;
    char cpy_r_r37;
    PyObject *cpy_r_r38;
    char cpy_r_r39;
    PyObject *cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    int32_t cpy_r_r44;
    char cpy_r_r45;
    char cpy_r_r46;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", -1, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Final',) */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic_packed___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('ABIEncoder',) */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.codec' */
    cpy_r_r11 = CPyStatic_packed___globals;
    cpy_r_r12 = CPyImport_ImportFromMany(cpy_r_r10, cpy_r_r9, cpy_r_r9, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPyModule_faster_eth_abi___codec = cpy_r_r12;
    CPy_INCREF(CPyModule_faster_eth_abi___codec);
    CPy_DECREF(cpy_r_r12);
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('registry_packed',) */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.registry' */
    cpy_r_r15 = CPyStatic_packed___globals;
    cpy_r_r16 = CPyImport_ImportFromMany(cpy_r_r14, cpy_r_r13, cpy_r_r13, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPyModule_faster_eth_abi___registry = cpy_r_r16;
    CPy_INCREF(CPyModule_faster_eth_abi___registry);
    CPy_DECREF(cpy_r_r16);
    cpy_r_r17 = CPyStatic_packed___globals;
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'registry_packed' */
    cpy_r_r19 = CPyDict_GetItem(cpy_r_r17, cpy_r_r18);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    cpy_r_r20 = CPyStatic_packed___globals;
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ABIEncoder' */
    cpy_r_r22 = CPyDict_GetItem(cpy_r_r20, cpy_r_r21);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL22;
    }
    PyObject *cpy_r_r23[1] = {cpy_r_r19};
    cpy_r_r24 = (PyObject **)&cpy_r_r23;
    cpy_r_r25 = PyObject_Vectorcall(cpy_r_r22, cpy_r_r24, 1, 0);
    CPy_DECREF(cpy_r_r22);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL22;
    }
    CPy_DECREF(cpy_r_r19);
    CPyStatic_packed___default_encoder_packed = cpy_r_r25;
    CPy_INCREF(CPyStatic_packed___default_encoder_packed);
    cpy_r_r26 = CPyStatic_packed___globals;
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'default_encoder_packed' */
    cpy_r_r28 = CPyDict_SetItem(cpy_r_r26, cpy_r_r27, cpy_r_r25);
    CPy_DECREF(cpy_r_r25);
    cpy_r_r29 = cpy_r_r28 >= 0;
    if (unlikely(!cpy_r_r29)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    cpy_r_r30 = CPyStatic_packed___default_encoder_packed;
    if (likely(cpy_r_r30 != NULL)) goto CPyL13;
    PyErr_SetString(PyExc_NameError, "value for final name \"default_encoder_packed\" was not set");
    cpy_r_r31 = 0;
    if (unlikely(!cpy_r_r31)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPy_Unreachable();
CPyL13: ;
    cpy_r_r32 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'encode' */
    cpy_r_r33 = CPyObject_GetAttr(cpy_r_r30, cpy_r_r32);
    if (unlikely(cpy_r_r33 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPyStatic_packed___encode_packed = cpy_r_r33;
    CPy_INCREF(CPyStatic_packed___encode_packed);
    cpy_r_r34 = CPyStatic_packed___globals;
    cpy_r_r35 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'encode_packed' */
    cpy_r_r36 = CPyDict_SetItem(cpy_r_r34, cpy_r_r35, cpy_r_r33);
    CPy_DECREF(cpy_r_r33);
    cpy_r_r37 = cpy_r_r36 >= 0;
    if (unlikely(!cpy_r_r37)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    cpy_r_r38 = CPyStatic_packed___default_encoder_packed;
    if (likely(cpy_r_r38 != NULL)) goto CPyL18;
    PyErr_SetString(PyExc_NameError, "value for final name \"default_encoder_packed\" was not set");
    cpy_r_r39 = 0;
    if (unlikely(!cpy_r_r39)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPy_Unreachable();
CPyL18: ;
    cpy_r_r40 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_encodable' */
    cpy_r_r41 = CPyObject_GetAttr(cpy_r_r38, cpy_r_r40);
    if (unlikely(cpy_r_r41 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    CPyStatic_packed___is_encodable_packed = cpy_r_r41;
    CPy_INCREF(CPyStatic_packed___is_encodable_packed);
    cpy_r_r42 = CPyStatic_packed___globals;
    cpy_r_r43 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_encodable_packed' */
    cpy_r_r44 = CPyDict_SetItem(cpy_r_r42, cpy_r_r43, cpy_r_r41);
    CPy_DECREF(cpy_r_r41);
    cpy_r_r45 = cpy_r_r44 >= 0;
    if (unlikely(!cpy_r_r45)) {
        CPy_AddTraceback("faster_eth_abi/packed.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_packed___globals);
        goto CPyL21;
    }
    return 1;
CPyL21: ;
    cpy_r_r46 = 2;
    return cpy_r_r46;
CPyL22: ;
    CPy_DecRef(cpy_r_r19);
    goto CPyL21;
}
static PyMethodDef toolsmodule_methods[] = {
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___tools(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___tools__internal, "__name__");
    CPyStatic_tools___globals = PyModule_GetDict(CPyModule_faster_eth_abi___tools__internal);
    if (unlikely(CPyStatic_tools___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_tools_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___tools__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef toolsmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.tools",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    toolsmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___tools(void)
{
    if (CPyModule_faster_eth_abi___tools__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___tools__internal);
        return CPyModule_faster_eth_abi___tools__internal;
    }
    CPyModule_faster_eth_abi___tools__internal = PyModule_Create(&toolsmodule);
    if (unlikely(CPyModule_faster_eth_abi___tools__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___tools(CPyModule_faster_eth_abi___tools__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___tools__internal;
    fail:
    return NULL;
}

char CPyDef_tools_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/__init__.py", "<module>", -1, CPyStatic_tools___globals);
        goto CPyL5;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('get_abi_strategy',) */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.tools._strategies' */
    cpy_r_r7 = CPyStatic_tools___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/__init__.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_tools___globals);
        goto CPyL5;
    }
    CPyModule_faster_eth_abi___tools____strategies = cpy_r_r8;
    CPy_INCREF(CPyModule_faster_eth_abi___tools____strategies);
    CPy_DECREF(cpy_r_r8);
    return 1;
CPyL5: ;
    cpy_r_r9 = 2;
    return cpy_r_r9;
}

static int
_strategies___StrategyRegistry_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    return 0;
}
PyObject *CPyDef__strategies_____mypyc__StrategyRegistry_setup(PyObject *cpy_r_type);
PyObject *CPyDef__strategies___StrategyRegistry(void);

static PyObject *
_strategies___StrategyRegistry_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType__strategies___StrategyRegistry) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef__strategies_____mypyc__StrategyRegistry_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    PyObject *ret = CPyPy__strategies___StrategyRegistry_____init__(self, args, kwds);
    if (ret == NULL)
        return NULL;
    return self;
}

static int
_strategies___StrategyRegistry_traverse(faster_eth_abi___tools____strategies___StrategyRegistryObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->__strategies);
    PyObject_VisitManagedDict((PyObject *)self, visit, arg);
    return 0;
}

static int
_strategies___StrategyRegistry_clear(faster_eth_abi___tools____strategies___StrategyRegistryObject *self)
{
    Py_CLEAR(self->__strategies);
    PyObject_ClearManagedDict((PyObject *)self);
    return 0;
}

static void
_strategies___StrategyRegistry_dealloc(faster_eth_abi___tools____strategies___StrategyRegistryObject *self)
{
    PyObject_GC_UnTrack(self);
    CPy_TRASHCAN_BEGIN(self, _strategies___StrategyRegistry_dealloc)
    _strategies___StrategyRegistry_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem _strategies___StrategyRegistry_vtable[4];
static bool
CPyDef__strategies___StrategyRegistry_trait_vtable_setup(void)
{
    CPyVTableItem _strategies___StrategyRegistry_vtable_scratch[] = {
        (CPyVTableItem)CPyDef__strategies___StrategyRegistry_____init__,
        (CPyVTableItem)CPyDef__strategies___StrategyRegistry___register_strategy,
        (CPyVTableItem)CPyDef__strategies___StrategyRegistry___unregister_strategy,
        (CPyVTableItem)CPyDef__strategies___StrategyRegistry___get_strategy,
    };
    memcpy(_strategies___StrategyRegistry_vtable, _strategies___StrategyRegistry_vtable_scratch, sizeof(_strategies___StrategyRegistry_vtable));
    return 1;
}

static PyObject *
_strategies___StrategyRegistry_get__strategies(faster_eth_abi___tools____strategies___StrategyRegistryObject *self, void *closure);
static int
_strategies___StrategyRegistry_set__strategies(faster_eth_abi___tools____strategies___StrategyRegistryObject *self, PyObject *value, void *closure);

static PyGetSetDef _strategies___StrategyRegistry_getseters[] = {
    {"_strategies",
     (getter)_strategies___StrategyRegistry_get__strategies, (setter)_strategies___StrategyRegistry_set__strategies,
     NULL, NULL},
    {"__dict__", PyObject_GenericGetDict, PyObject_GenericSetDict},
    {NULL}  /* Sentinel */
};

static PyMethodDef _strategies___StrategyRegistry_methods[] = {
    {"__init__",
     (PyCFunction)CPyPy__strategies___StrategyRegistry_____init__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__init__($self)\n--\n\n")},
    {"register_strategy",
     (PyCFunction)CPyPy__strategies___StrategyRegistry___register_strategy,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("register_strategy($self, lookup, registration, label=None)\n--\n\n")},
    {"unregister_strategy",
     (PyCFunction)CPyPy__strategies___StrategyRegistry___unregister_strategy,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("unregister_strategy($self, lookup_or_label)\n--\n\n")},
    {"get_strategy",
     (PyCFunction)CPyPy__strategies___StrategyRegistry___get_strategy,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_strategy($self, type_str)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType__strategies___StrategyRegistry_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "StrategyRegistry",
    .tp_new = _strategies___StrategyRegistry_new,
    .tp_dealloc = (destructor)_strategies___StrategyRegistry_dealloc,
    .tp_traverse = (traverseproc)_strategies___StrategyRegistry_traverse,
    .tp_clear = (inquiry)_strategies___StrategyRegistry_clear,
    .tp_getset = _strategies___StrategyRegistry_getseters,
    .tp_methods = _strategies___StrategyRegistry_methods,
    .tp_init = _strategies___StrategyRegistry_init,
    .tp_basicsize = sizeof(faster_eth_abi___tools____strategies___StrategyRegistryObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_MANAGED_DICT,
    .tp_doc = PyDoc_STR("StrategyRegistry()\n--\n\n"),
};
static PyTypeObject *CPyType__strategies___StrategyRegistry_template = &CPyType__strategies___StrategyRegistry_template_;

PyObject *CPyDef__strategies_____mypyc__StrategyRegistry_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___tools____strategies___StrategyRegistryObject *self;
    self = (faster_eth_abi___tools____strategies___StrategyRegistryObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = _strategies___StrategyRegistry_vtable;
    return (PyObject *)self;
}

PyObject *CPyDef__strategies___StrategyRegistry(void)
{
    PyObject *self = CPyDef__strategies_____mypyc__StrategyRegistry_setup((PyObject *)CPyType__strategies___StrategyRegistry);
    if (self == NULL)
        return NULL;
    char res = CPyDef__strategies___StrategyRegistry_____init__(self);
    if (res == 2) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}

static PyObject *
_strategies___StrategyRegistry_get__strategies(faster_eth_abi___tools____strategies___StrategyRegistryObject *self, void *closure)
{
    if (unlikely(self->__strategies == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute '_strategies' of 'StrategyRegistry' undefined");
        return NULL;
    }
    CPy_INCREF(self->__strategies);
    PyObject *retval = self->__strategies;
    return retval;
}

static int
_strategies___StrategyRegistry_set__strategies(faster_eth_abi___tools____strategies___StrategyRegistryObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'StrategyRegistry' object attribute '_strategies' cannot be deleted");
        return -1;
    }
    if (self->__strategies != NULL) {
        CPy_DECREF(self->__strategies);
    }
    PyObject *tmp = value;
    CPy_INCREF(tmp);
    self->__strategies = tmp;
    return 0;
}
static PyMethodDef _strategiesmodule_methods[] = {
    {"get_uint_strategy", (PyCFunction)CPyPy__strategies___get_uint_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_uint_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {"get_int_strategy", (PyCFunction)CPyPy__strategies___get_int_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_int_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {"get_ufixed_strategy", (PyCFunction)CPyPy__strategies___get_ufixed_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_ufixed_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {"get_fixed_strategy", (PyCFunction)CPyPy__strategies___get_fixed_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_fixed_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {"get_bytes_strategy", (PyCFunction)CPyPy__strategies___get_bytes_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_bytes_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {"get_array_strategy", (PyCFunction)CPyPy__strategies___get_array_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_array_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {"get_tuple_strategy", (PyCFunction)CPyPy__strategies___get_tuple_strategy, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("get_tuple_strategy(abi_type, registry)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___tools____strategies(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___tools____strategies__internal, "__name__");
    CPyStatic__strategies___globals = PyModule_GetDict(CPyModule_faster_eth_abi___tools____strategies__internal);
    if (unlikely(CPyStatic__strategies___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef__strategies_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___tools____strategies__internal);
    Py_CLEAR(modname);
    CPy_XDECREF(CPyStatic__strategies___address_strategy);
    CPyStatic__strategies___address_strategy = NULL;
    CPy_XDECREF(CPyStatic__strategies___bool_strategy);
    CPyStatic__strategies___bool_strategy = NULL;
    CPy_XDECREF(CPyStatic__strategies___bytes_strategy);
    CPyStatic__strategies___bytes_strategy = NULL;
    CPy_XDECREF(CPyStatic__strategies___string_strategy);
    CPyStatic__strategies___string_strategy = NULL;
    CPy_XDECREF_NO_IMM(CPyStatic__strategies___strategy_registry);
    CPyStatic__strategies___strategy_registry = NULL;
    CPy_XDECREF(CPyStatic__strategies___get_abi_strategy);
    CPyStatic__strategies___get_abi_strategy = NULL;
    Py_CLEAR(CPyType__strategies___StrategyRegistry);
    return -1;
}
static struct PyModuleDef _strategiesmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.tools._strategies",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    _strategiesmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___tools____strategies(void)
{
    if (CPyModule_faster_eth_abi___tools____strategies__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___tools____strategies__internal);
        return CPyModule_faster_eth_abi___tools____strategies__internal;
    }
    CPyModule_faster_eth_abi___tools____strategies__internal = PyModule_Create(&_strategiesmodule);
    if (unlikely(CPyModule_faster_eth_abi___tools____strategies__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___tools____strategies(CPyModule_faster_eth_abi___tools____strategies__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___tools____strategies__internal;
    fail:
    return NULL;
}

char CPyDef__strategies___StrategyRegistry_____init__(PyObject *cpy_r_self) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject **cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    char cpy_r_r8;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'strategy registry' */
    cpy_r_r1 = CPyStatic__strategies___globals;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'PredicateMapping' */
    cpy_r_r3 = CPyDict_GetItem(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL4;
    }
    PyObject *cpy_r_r4[1] = {cpy_r_r0};
    cpy_r_r5 = (PyObject **)&cpy_r_r4;
    cpy_r_r6 = PyObject_Vectorcall(cpy_r_r3, cpy_r_r5, 1, 0);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL4;
    }
    if (((faster_eth_abi___tools____strategies___StrategyRegistryObject *)cpy_r_self)->__strategies != NULL) {
        CPy_DECREF(((faster_eth_abi___tools____strategies___StrategyRegistryObject *)cpy_r_self)->__strategies);
    }
    ((faster_eth_abi___tools____strategies___StrategyRegistryObject *)cpy_r_self)->__strategies = cpy_r_r6;
    cpy_r_r7 = 1;
    if (unlikely(!cpy_r_r7)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL4;
    }
    return 1;
CPyL4: ;
    cpy_r_r8 = 2;
    return cpy_r_r8;
}

PyObject *CPyPy__strategies___StrategyRegistry_____init__(PyObject *self, PyObject *args, PyObject *kw) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {0};
    if (!CPyArg_ParseTupleAndKeywords(args, kw, "", "__init__", kwlist)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(Py_TYPE(obj_self) == CPyType__strategies___StrategyRegistry))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_self); 
        goto fail;
    }
    char retval = CPyDef__strategies___StrategyRegistry_____init__(arg_self);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "__init__", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

char CPyDef__strategies___StrategyRegistry___register_strategy(PyObject *cpy_r_self, PyObject *cpy_r_lookup, PyObject *cpy_r_registration, PyObject *cpy_r_label) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    char cpy_r_r7;
    if (cpy_r_label != NULL) goto CPyL6;
    cpy_r_r0 = Py_None;
    cpy_r_label = cpy_r_r0;
CPyL2: ;
    cpy_r_r1 = ((faster_eth_abi___tools____strategies___StrategyRegistryObject *)cpy_r_self)->__strategies;
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "register_strategy", "StrategyRegistry", "_strategies", 55, CPyStatic__strategies___globals);
        goto CPyL7;
    }
    CPy_INCREF(cpy_r_r1);
CPyL3: ;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_register' */
    PyObject *cpy_r_r3[5] = {
        cpy_r_self, cpy_r_r1, cpy_r_lookup, cpy_r_registration,
        cpy_r_label
    };
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('label',) */
    cpy_r_r6 = PyObject_VectorcallMethod(cpy_r_r2, cpy_r_r4, 9223372036854775812ULL, cpy_r_r5);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "register_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL8;
    } else
        goto CPyL9;
CPyL4: ;
    CPy_DECREF(cpy_r_r1);
    CPy_DECREF(cpy_r_label);
    return 1;
CPyL5: ;
    cpy_r_r7 = 2;
    return cpy_r_r7;
CPyL6: ;
    CPy_INCREF(cpy_r_label);
    goto CPyL2;
CPyL7: ;
    CPy_DecRef(cpy_r_label);
    goto CPyL5;
CPyL8: ;
    CPy_DecRef(cpy_r_label);
    CPy_DecRef(cpy_r_r1);
    goto CPyL5;
CPyL9: ;
    CPy_DECREF(cpy_r_r6);
    goto CPyL4;
}

PyObject *CPyPy__strategies___StrategyRegistry___register_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"lookup", "registration", "label", 0};
    static CPyArg_Parser parser = {"OO|O:register_strategy", kwlist, 0};
    PyObject *obj_lookup;
    PyObject *obj_registration;
    PyObject *obj_label = NULL;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_lookup, &obj_registration, &obj_label)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(Py_TYPE(obj_self) == CPyType__strategies___StrategyRegistry))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_self); 
        goto fail;
    }
    PyObject *arg_lookup;
    if (PyUnicode_Check(obj_lookup))
        arg_lookup = obj_lookup;
    else {
        arg_lookup = NULL;
    }
    if (arg_lookup != NULL) goto __LL35;
    arg_lookup = obj_lookup;
    if (arg_lookup != NULL) goto __LL35;
    CPy_TypeError("union[str, object]", obj_lookup); 
    goto fail;
__LL35: ;
    PyObject *arg_registration = obj_registration;
    PyObject *arg_label;
    if (obj_label == NULL) {
        arg_label = NULL;
        goto __LL36;
    }
    if (PyUnicode_Check(obj_label))
        arg_label = obj_label;
    else {
        arg_label = NULL;
    }
    if (arg_label != NULL) goto __LL36;
    if (obj_label == Py_None)
        arg_label = obj_label;
    else {
        arg_label = NULL;
    }
    if (arg_label != NULL) goto __LL36;
    CPy_TypeError("str or None", obj_label); 
    goto fail;
__LL36: ;
    char retval = CPyDef__strategies___StrategyRegistry___register_strategy(arg_self, arg_lookup, arg_registration, arg_label);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "register_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

char CPyDef__strategies___StrategyRegistry___unregister_strategy(PyObject *cpy_r_self, PyObject *cpy_r_lookup_or_label) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject **cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = ((faster_eth_abi___tools____strategies___StrategyRegistryObject *)cpy_r_self)->__strategies;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "unregister_strategy", "StrategyRegistry", "_strategies", 58, CPyStatic__strategies___globals);
        goto CPyL3;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_unregister' */
    PyObject *cpy_r_r2[3] = {cpy_r_self, cpy_r_r0, cpy_r_lookup_or_label};
    cpy_r_r3 = (PyObject **)&cpy_r_r2;
    cpy_r_r4 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r3, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "unregister_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL4;
    } else
        goto CPyL5;
CPyL2: ;
    CPy_DECREF(cpy_r_r0);
    return 1;
CPyL3: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
CPyL4: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL3;
CPyL5: ;
    CPy_DECREF(cpy_r_r4);
    goto CPyL2;
}

PyObject *CPyPy__strategies___StrategyRegistry___unregister_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"lookup_or_label", 0};
    static CPyArg_Parser parser = {"O:unregister_strategy", kwlist, 0};
    PyObject *obj_lookup_or_label;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_lookup_or_label)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(Py_TYPE(obj_self) == CPyType__strategies___StrategyRegistry))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_self); 
        goto fail;
    }
    PyObject *arg_lookup_or_label;
    if (PyUnicode_Check(obj_lookup_or_label))
        arg_lookup_or_label = obj_lookup_or_label;
    else {
        arg_lookup_or_label = NULL;
    }
    if (arg_lookup_or_label != NULL) goto __LL37;
    arg_lookup_or_label = obj_lookup_or_label;
    if (arg_lookup_or_label != NULL) goto __LL37;
    CPy_TypeError("union[str, object]", obj_lookup_or_label); 
    goto fail;
__LL37: ;
    char retval = CPyDef__strategies___StrategyRegistry___unregister_strategy(arg_self, arg_lookup_or_label);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "unregister_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___StrategyRegistry___get_strategy(PyObject *cpy_r_self, PyObject *cpy_r_type_str) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject **cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    int32_t cpy_r_r10;
    char cpy_r_r11;
    char cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject **cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    cpy_r_r0 = ((faster_eth_abi___tools____strategies___StrategyRegistryObject *)cpy_r_self)->__strategies;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_strategy", "StrategyRegistry", "_strategies", 70, CPyStatic__strategies___globals);
        goto CPyL12;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_get_registration' */
    PyObject *cpy_r_r2[3] = {cpy_r_self, cpy_r_r0, cpy_r_type_str};
    cpy_r_r3 = (PyObject **)&cpy_r_r2;
    cpy_r_r4 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r3, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL13;
    }
    CPy_DECREF(cpy_r_r0);
    cpy_r_r5 = CPyStatic__strategies___globals;
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r7 = CPyDict_GetItem(cpy_r_r5, cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'SearchStrategy' */
    cpy_r_r9 = CPyObject_GetAttr(cpy_r_r7, cpy_r_r8);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    cpy_r_r10 = PyObject_IsInstance(cpy_r_r4, cpy_r_r9);
    CPy_DECREF(cpy_r_r9);
    cpy_r_r11 = cpy_r_r10 >= 0;
    if (unlikely(!cpy_r_r11)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    cpy_r_r12 = cpy_r_r10;
    if (!cpy_r_r12) goto CPyL7;
    return cpy_r_r4;
CPyL7: ;
    cpy_r_r13 = CPyDef__grammar___normalize(cpy_r_type_str);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    cpy_r_r14 = CPyStatic__strategies___globals;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'parse' */
    cpy_r_r16 = CPyDict_GetItem(cpy_r_r14, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL15;
    }
    PyObject *cpy_r_r17[1] = {cpy_r_r13};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_Vectorcall(cpy_r_r16, cpy_r_r18, 1, 0);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL15;
    }
    CPy_DECREF(cpy_r_r13);
    PyObject *cpy_r_r20[2] = {cpy_r_r19, cpy_r_self};
    cpy_r_r21 = (PyObject **)&cpy_r_r20;
    cpy_r_r22 = PyObject_Vectorcall(cpy_r_r4, cpy_r_r21, 2, 0);
    CPy_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL16;
    }
    CPy_DECREF(cpy_r_r19);
    return cpy_r_r22;
CPyL12: ;
    cpy_r_r23 = NULL;
    return cpy_r_r23;
CPyL13: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL12;
CPyL14: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL12;
CPyL15: ;
    CPy_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r13);
    goto CPyL12;
CPyL16: ;
    CPy_DecRef(cpy_r_r19);
    goto CPyL12;
}

PyObject *CPyPy__strategies___StrategyRegistry___get_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj_self = self;
    static const char * const kwlist[] = {"type_str", 0};
    static CPyArg_Parser parser = {"O:get_strategy", kwlist, 0};
    PyObject *obj_type_str;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_type_str)) {
        return NULL;
    }
    PyObject *arg_self;
    if (likely(Py_TYPE(obj_self) == CPyType__strategies___StrategyRegistry))
        arg_self = obj_self;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_self); 
        goto fail;
    }
    PyObject *arg_type_str;
    if (likely(PyUnicode_Check(obj_type_str)))
        arg_type_str = obj_type_str;
    else {
        CPy_TypeError("str", obj_type_str); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___StrategyRegistry___get_strategy(arg_self, arg_type_str);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_uint_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    CPyTagged cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject **cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_abi_type)->_sub;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", "BasicType", "sub", 88, CPyStatic__strategies___globals);
        goto CPyL7;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    if (likely(PyLong_Check(cpy_r_r0)))
        cpy_r_r1 = CPyTagged_FromObject(cpy_r_r0);
    else {
        CPy_TypeError("int", cpy_r_r0); cpy_r_r1 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r1 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL7;
    }
    cpy_r_r2 = CPyStatic__strategies___globals;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r4 = CPyDict_GetItem(cpy_r_r2, cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL8;
    }
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r6 = CPyTagged_StealAsObject(cpy_r_r1);
    cpy_r_r7 = CPyNumber_Power(cpy_r_r5, cpy_r_r6);
    CPy_DECREF(cpy_r_r6);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL9;
    }
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r9 = PyNumber_Subtract(cpy_r_r7, cpy_r_r8);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL9;
    }
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'integers' */
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    PyObject *cpy_r_r12[3] = {cpy_r_r4, cpy_r_r11, cpy_r_r9};
    cpy_r_r13 = (PyObject **)&cpy_r_r12;
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_value', 'max_value') */
    cpy_r_r15 = PyObject_VectorcallMethod(cpy_r_r10, cpy_r_r13, 9223372036854775809ULL, cpy_r_r14);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL10;
    }
    CPy_DECREF(cpy_r_r4);
    CPy_DECREF(cpy_r_r9);
    return cpy_r_r15;
CPyL7: ;
    cpy_r_r16 = NULL;
    return cpy_r_r16;
CPyL8: ;
    CPyTagged_DecRef(cpy_r_r1);
    goto CPyL7;
CPyL9: ;
    CPy_DecRef(cpy_r_r4);
    goto CPyL7;
CPyL10: ;
    CPy_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r9);
    goto CPyL7;
}

PyObject *CPyPy__strategies___get_uint_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_uint_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___BasicType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_uint_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_uint_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_int_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    CPyTagged cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    CPyTagged cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    CPyTagged cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_abi_type)->_sub;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_int_strategy", "BasicType", "sub", 99, CPyStatic__strategies___globals);
        goto CPyL9;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    if (likely(PyLong_Check(cpy_r_r0)))
        cpy_r_r1 = CPyTagged_FromObject(cpy_r_r0);
    else {
        CPy_TypeError("int", cpy_r_r0); cpy_r_r1 = CPY_INT_TAG;
    }
    CPy_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r1 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL9;
    }
    cpy_r_r2 = CPyStatic__strategies___globals;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r4 = CPyDict_GetItem(cpy_r_r2, cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL10;
    }
    cpy_r_r5 = CPyTagged_Subtract(cpy_r_r1, 2);
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r7 = CPyTagged_StealAsObject(cpy_r_r5);
    cpy_r_r8 = CPyNumber_Power(cpy_r_r6, cpy_r_r7);
    CPy_DECREF(cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL11;
    }
    cpy_r_r9 = PyNumber_Negative(cpy_r_r8);
    CPy_DECREF(cpy_r_r8);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL11;
    }
    cpy_r_r10 = CPyTagged_Subtract(cpy_r_r1, 2);
    CPyTagged_DECREF(cpy_r_r1);
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r12 = CPyTagged_StealAsObject(cpy_r_r10);
    cpy_r_r13 = CPyNumber_Power(cpy_r_r11, cpy_r_r12);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL12;
    }
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r15 = PyNumber_Subtract(cpy_r_r13, cpy_r_r14);
    CPy_DECREF(cpy_r_r13);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL12;
    }
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'integers' */
    PyObject *cpy_r_r17[3] = {cpy_r_r4, cpy_r_r9, cpy_r_r15};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_value', 'max_value') */
    cpy_r_r20 = PyObject_VectorcallMethod(cpy_r_r16, cpy_r_r18, 9223372036854775809ULL, cpy_r_r19);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL13;
    }
    CPy_DECREF(cpy_r_r4);
    CPy_DECREF(cpy_r_r9);
    CPy_DECREF(cpy_r_r15);
    return cpy_r_r20;
CPyL9: ;
    cpy_r_r21 = NULL;
    return cpy_r_r21;
CPyL10: ;
    CPyTagged_DecRef(cpy_r_r1);
    goto CPyL9;
CPyL11: ;
    CPyTagged_DecRef(cpy_r_r1);
    CPy_DecRef(cpy_r_r4);
    goto CPyL9;
CPyL12: ;
    CPy_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r9);
    goto CPyL9;
CPyL13: ;
    CPy_DecRef(cpy_r_r4);
    CPy_DecRef(cpy_r_r9);
    CPy_DecRef(cpy_r_r15);
    goto CPyL9;
}

PyObject *CPyPy__strategies___get_int_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_int_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___BasicType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_int_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_int_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_ufixed_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    tuple_T2II cpy_r_r1;
    CPyTagged cpy_r_r2;
    CPyTagged cpy_r_r3;
    CPyTagged cpy_r_r4;
    CPyTagged cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject **cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_abi_type)->_sub;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", "BasicType", "sub", 114, CPyStatic__strategies___globals);
        goto CPyL9;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    PyObject *__tmp38;
    if (unlikely(!(PyTuple_Check(cpy_r_r0) && PyTuple_GET_SIZE(cpy_r_r0) == 2))) {
        __tmp38 = NULL;
        goto __LL39;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r0, 0))))
        __tmp38 = PyTuple_GET_ITEM(cpy_r_r0, 0);
    else {
        __tmp38 = NULL;
    }
    if (__tmp38 == NULL) goto __LL39;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r0, 1))))
        __tmp38 = PyTuple_GET_ITEM(cpy_r_r0, 1);
    else {
        __tmp38 = NULL;
    }
    if (__tmp38 == NULL) goto __LL39;
    __tmp38 = cpy_r_r0;
__LL39: ;
    if (unlikely(__tmp38 == NULL)) {
        CPy_TypeError("tuple[int, int]", cpy_r_r0); cpy_r_r1 = (tuple_T2II) { CPY_INT_TAG, CPY_INT_TAG };
    } else {
        PyObject *__tmp40 = PyTuple_GET_ITEM(cpy_r_r0, 0);
        CPyTagged __tmp41;
        if (likely(PyLong_Check(__tmp40)))
            __tmp41 = CPyTagged_FromObject(__tmp40);
        else {
            CPy_TypeError("int", __tmp40); __tmp41 = CPY_INT_TAG;
        }
        cpy_r_r1.f0 = __tmp41;
        PyObject *__tmp42 = PyTuple_GET_ITEM(cpy_r_r0, 1);
        CPyTagged __tmp43;
        if (likely(PyLong_Check(__tmp42)))
            __tmp43 = CPyTagged_FromObject(__tmp42);
        else {
            CPy_TypeError("int", __tmp42); __tmp43 = CPY_INT_TAG;
        }
        cpy_r_r1.f1 = __tmp43;
    }
    CPy_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r1.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL9;
    }
    cpy_r_r2 = cpy_r_r1.f0;
    cpy_r_r3 = cpy_r_r1.f1;
    cpy_r_r4 = cpy_r_r2;
    cpy_r_r5 = cpy_r_r3;
    cpy_r_r6 = CPyStatic__strategies___globals;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r8 = CPyDict_GetItem(cpy_r_r6, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL10;
    }
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r10 = CPyTagged_StealAsObject(cpy_r_r4);
    cpy_r_r11 = CPyNumber_Power(cpy_r_r9, cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL11;
    }
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r13 = PyNumber_Subtract(cpy_r_r11, cpy_r_r12);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL11;
    }
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decimals' */
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    PyObject *cpy_r_r17[4] = {cpy_r_r8, cpy_r_r15, cpy_r_r13, cpy_r_r16};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_value', 'max_value', 'places') */
    cpy_r_r20 = PyObject_VectorcallMethod(cpy_r_r14, cpy_r_r18, 9223372036854775809ULL, cpy_r_r19);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL12;
    }
    CPy_DECREF(cpy_r_r8);
    CPy_DECREF(cpy_r_r13);
    cpy_r_r21 = CPyDef_numeric___scale_places(cpy_r_r5);
    CPyTagged_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL13;
    }
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    PyObject *cpy_r_r23[2] = {cpy_r_r20, cpy_r_r21};
    cpy_r_r24 = (PyObject **)&cpy_r_r23;
    cpy_r_r25 = PyObject_VectorcallMethod(cpy_r_r22, cpy_r_r24, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    CPy_DECREF(cpy_r_r20);
    CPy_DECREF(cpy_r_r21);
    return cpy_r_r25;
CPyL9: ;
    cpy_r_r26 = NULL;
    return cpy_r_r26;
CPyL10: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r5);
    goto CPyL9;
CPyL11: ;
    CPyTagged_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r8);
    goto CPyL9;
CPyL12: ;
    CPyTagged_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_r13);
    goto CPyL9;
CPyL13: ;
    CPy_DecRef(cpy_r_r20);
    goto CPyL9;
CPyL14: ;
    CPy_DecRef(cpy_r_r20);
    CPy_DecRef(cpy_r_r21);
    goto CPyL9;
}

PyObject *CPyPy__strategies___get_ufixed_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_ufixed_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___BasicType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_ufixed_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_ufixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_fixed_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    tuple_T2II cpy_r_r1;
    CPyTagged cpy_r_r2;
    CPyTagged cpy_r_r3;
    CPyTagged cpy_r_r4;
    CPyTagged cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    CPyTagged cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    CPyTagged cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject **cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject **cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_abi_type)->_sub;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", "BasicType", "sub", 126, CPyStatic__strategies___globals);
        goto CPyL11;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    PyObject *__tmp44;
    if (unlikely(!(PyTuple_Check(cpy_r_r0) && PyTuple_GET_SIZE(cpy_r_r0) == 2))) {
        __tmp44 = NULL;
        goto __LL45;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r0, 0))))
        __tmp44 = PyTuple_GET_ITEM(cpy_r_r0, 0);
    else {
        __tmp44 = NULL;
    }
    if (__tmp44 == NULL) goto __LL45;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r0, 1))))
        __tmp44 = PyTuple_GET_ITEM(cpy_r_r0, 1);
    else {
        __tmp44 = NULL;
    }
    if (__tmp44 == NULL) goto __LL45;
    __tmp44 = cpy_r_r0;
__LL45: ;
    if (unlikely(__tmp44 == NULL)) {
        CPy_TypeError("tuple[int, int]", cpy_r_r0); cpy_r_r1 = (tuple_T2II) { CPY_INT_TAG, CPY_INT_TAG };
    } else {
        PyObject *__tmp46 = PyTuple_GET_ITEM(cpy_r_r0, 0);
        CPyTagged __tmp47;
        if (likely(PyLong_Check(__tmp46)))
            __tmp47 = CPyTagged_FromObject(__tmp46);
        else {
            CPy_TypeError("int", __tmp46); __tmp47 = CPY_INT_TAG;
        }
        cpy_r_r1.f0 = __tmp47;
        PyObject *__tmp48 = PyTuple_GET_ITEM(cpy_r_r0, 1);
        CPyTagged __tmp49;
        if (likely(PyLong_Check(__tmp48)))
            __tmp49 = CPyTagged_FromObject(__tmp48);
        else {
            CPy_TypeError("int", __tmp48); __tmp49 = CPY_INT_TAG;
        }
        cpy_r_r1.f1 = __tmp49;
    }
    CPy_DECREF(cpy_r_r0);
    if (unlikely(cpy_r_r1.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL11;
    }
    cpy_r_r2 = cpy_r_r1.f0;
    cpy_r_r3 = cpy_r_r1.f1;
    cpy_r_r4 = cpy_r_r2;
    cpy_r_r5 = cpy_r_r3;
    cpy_r_r6 = CPyStatic__strategies___globals;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r8 = CPyDict_GetItem(cpy_r_r6, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL12;
    }
    cpy_r_r9 = CPyTagged_Subtract(cpy_r_r4, 2);
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r11 = CPyTagged_StealAsObject(cpy_r_r9);
    cpy_r_r12 = CPyNumber_Power(cpy_r_r10, cpy_r_r11);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL13;
    }
    cpy_r_r13 = PyNumber_Negative(cpy_r_r12);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL13;
    }
    cpy_r_r14 = CPyTagged_Subtract(cpy_r_r4, 2);
    CPyTagged_DECREF(cpy_r_r4);
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r16 = CPyTagged_StealAsObject(cpy_r_r14);
    cpy_r_r17 = CPyNumber_Power(cpy_r_r15, cpy_r_r16);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r19 = PyNumber_Subtract(cpy_r_r17, cpy_r_r18);
    CPy_DECREF(cpy_r_r17);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decimals' */
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    PyObject *cpy_r_r22[4] = {cpy_r_r8, cpy_r_r13, cpy_r_r19, cpy_r_r21};
    cpy_r_r23 = (PyObject **)&cpy_r_r22;
    cpy_r_r24 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_value', 'max_value', 'places') */
    cpy_r_r25 = PyObject_VectorcallMethod(cpy_r_r20, cpy_r_r23, 9223372036854775809ULL, cpy_r_r24);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL15;
    }
    CPy_DECREF(cpy_r_r8);
    CPy_DECREF(cpy_r_r13);
    CPy_DECREF(cpy_r_r19);
    cpy_r_r26 = CPyDef_numeric___scale_places(cpy_r_r5);
    CPyTagged_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL16;
    }
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    PyObject *cpy_r_r28[2] = {cpy_r_r25, cpy_r_r26};
    cpy_r_r29 = (PyObject **)&cpy_r_r28;
    cpy_r_r30 = PyObject_VectorcallMethod(cpy_r_r27, cpy_r_r29, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r30 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    CPy_DECREF(cpy_r_r25);
    CPy_DECREF(cpy_r_r26);
    return cpy_r_r30;
CPyL11: ;
    cpy_r_r31 = NULL;
    return cpy_r_r31;
CPyL12: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r5);
    goto CPyL11;
CPyL13: ;
    CPyTagged_DecRef(cpy_r_r4);
    CPyTagged_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r8);
    goto CPyL11;
CPyL14: ;
    CPyTagged_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_r13);
    goto CPyL11;
CPyL15: ;
    CPyTagged_DecRef(cpy_r_r5);
    CPy_DecRef(cpy_r_r8);
    CPy_DecRef(cpy_r_r13);
    CPy_DecRef(cpy_r_r19);
    goto CPyL11;
CPyL16: ;
    CPy_DecRef(cpy_r_r25);
    goto CPyL11;
CPyL17: ;
    CPy_DecRef(cpy_r_r25);
    CPy_DecRef(cpy_r_r26);
    goto CPyL11;
}

PyObject *CPyPy__strategies___get_fixed_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_fixed_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___BasicType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_fixed_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_fixed_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_bytes_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject **cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    cpy_r_r0 = ((faster_eth_abi____grammar___BasicTypeObject *)cpy_r_abi_type)->_sub;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_bytes_strategy", "BasicType", "sub", 138, CPyStatic__strategies___globals);
        goto CPyL4;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyStatic__strategies___globals;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r3 = CPyDict_GetItem(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_bytes_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL5;
    }
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'binary' */
    PyObject *cpy_r_r5[3] = {cpy_r_r3, cpy_r_r0, cpy_r_r0};
    cpy_r_r6 = (PyObject **)&cpy_r_r5;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_size', 'max_size') */
    cpy_r_r8 = PyObject_VectorcallMethod(cpy_r_r4, cpy_r_r6, 9223372036854775809ULL, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_bytes_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL6;
    }
    CPy_DECREF(cpy_r_r3);
    CPy_DECREF(cpy_r_r0);
    return cpy_r_r8;
CPyL4: ;
    cpy_r_r9 = NULL;
    return cpy_r_r9;
CPyL5: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL4;
CPyL6: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r3);
    goto CPyL4;
}

PyObject *CPyPy__strategies___get_bytes_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_bytes_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___BasicType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.BasicType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_bytes_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_bytes_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_array_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    CPyTagged cpy_r_r8;
    char cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject **cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject **cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    cpy_r_r0 = CPY_GET_ATTR(cpy_r_abi_type, CPyType__grammar___ABIType, 4, faster_eth_abi____grammar___ABITypeObject, PyObject *); /* item_type */
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL16;
    }
CPyL1: ;
    cpy_r_r1 = CPY_GET_METHOD(cpy_r_r0, CPyType__grammar___ABIType, 3, faster_eth_abi____grammar___ABITypeObject, PyObject * (*)(PyObject *))(cpy_r_r0); /* to_type_str */
    CPy_DECREF_NO_IMM(cpy_r_r0);
    if (unlikely(cpy_r_r1 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL16;
    }
    cpy_r_r2 = CPyDef__strategies___StrategyRegistry___get_strategy(cpy_r_registry, cpy_r_r1);
    CPy_DECREF(cpy_r_r1);
    if (unlikely(cpy_r_r2 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL16;
    }
    cpy_r_r3 = ((faster_eth_abi____grammar___ABITypeObject *)cpy_r_abi_type)->_arrlist;
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_array_strategy", "ABIType", "arrlist", 157, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    CPy_INCREF(cpy_r_r3);
CPyL4: ;
    cpy_r_r4 = cpy_r_r3;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* -1 */
    cpy_r_r6 = PyObject_GetItem(cpy_r_r4, cpy_r_r5);
    CPy_DECREF(cpy_r_r4);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    cpy_r_r7 = cpy_r_r6;
    cpy_r_r8 = CPyObject_Size(cpy_r_r7);
    if (unlikely(cpy_r_r8 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL18;
    }
    cpy_r_r9 = cpy_r_r8 == 0;
    CPyTagged_DECREF(cpy_r_r8);
    if (cpy_r_r9) {
        goto CPyL19;
    } else
        goto CPyL11;
CPyL8: ;
    cpy_r_r10 = CPyStatic__strategies___globals;
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r12 = CPyDict_GetItem(cpy_r_r10, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'lists' */
    PyObject *cpy_r_r14[2] = {cpy_r_r12, cpy_r_r2};
    cpy_r_r15 = (PyObject **)&cpy_r_r14;
    cpy_r_r16 = PyObject_VectorcallMethod(cpy_r_r13, cpy_r_r15, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL20;
    }
    CPy_DECREF(cpy_r_r12);
    CPy_DECREF(cpy_r_r2);
    return cpy_r_r16;
CPyL11: ;
    cpy_r_r17 = cpy_r_r7;
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    cpy_r_r19 = PyObject_GetItem(cpy_r_r17, cpy_r_r18);
    CPy_DECREF(cpy_r_r17);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    cpy_r_r20 = cpy_r_r19;
    cpy_r_r21 = CPyStatic__strategies___globals;
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r23 = CPyDict_GetItem(cpy_r_r21, cpy_r_r22);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL21;
    }
    cpy_r_r24 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'lists' */
    PyObject *cpy_r_r25[4] = {cpy_r_r23, cpy_r_r2, cpy_r_r20, cpy_r_r20};
    cpy_r_r26 = (PyObject **)&cpy_r_r25;
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_size', 'max_size') */
    cpy_r_r28 = PyObject_VectorcallMethod(cpy_r_r24, cpy_r_r26, 9223372036854775810ULL, cpy_r_r27);
    if (unlikely(cpy_r_r28 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL22;
    }
    CPy_DECREF(cpy_r_r23);
    CPy_DECREF(cpy_r_r2);
    CPy_DECREF(cpy_r_r20);
    return cpy_r_r28;
CPyL16: ;
    cpy_r_r29 = NULL;
    return cpy_r_r29;
CPyL17: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL16;
CPyL18: ;
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r7);
    goto CPyL16;
CPyL19: ;
    CPy_DECREF(cpy_r_r7);
    goto CPyL8;
CPyL20: ;
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r12);
    goto CPyL16;
CPyL21: ;
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r20);
    goto CPyL16;
CPyL22: ;
    CPy_DecRef(cpy_r_r2);
    CPy_DecRef(cpy_r_r20);
    CPy_DecRef(cpy_r_r23);
    goto CPyL16;
}

PyObject *CPyPy__strategies___get_array_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_array_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___ABIType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.ABIType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_array_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_array_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

PyObject *CPyDef__strategies___get_tuple_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry) {
    PyObject *cpy_r_r0;
    CPyPtr cpy_r_r1;
    int64_t cpy_r_r2;
    PyObject *cpy_r_r3;
    CPyPtr cpy_r_r4;
    int64_t cpy_r_r5;
    int64_t cpy_r_r6;
    char cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    int64_t cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    cpy_r_r0 = ((faster_eth_abi____grammar___TupleTypeObject *)cpy_r_abi_type)->_components;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", "TupleType", "components", 172, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    CPy_INCREF(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = (CPyPtr)&((PyVarObject *)cpy_r_r0)->ob_size;
    cpy_r_r2 = *(int64_t *)cpy_r_r1;
    cpy_r_r3 = PyList_New(cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL15;
    }
    cpy_r_r4 = (CPyPtr)&((PyVarObject *)cpy_r_r0)->ob_size;
    cpy_r_r5 = *(int64_t *)cpy_r_r4;
    cpy_r_r6 = 0;
CPyL3: ;
    cpy_r_r7 = cpy_r_r6 < cpy_r_r5;
    if (!cpy_r_r7) goto CPyL16;
    cpy_r_r8 = CPySequenceTuple_GetItemUnsafe(cpy_r_r0, cpy_r_r6);
    if (likely(PyObject_TypeCheck(cpy_r_r8, CPyType__grammar___ABIType)))
        cpy_r_r9 = cpy_r_r8;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", 170, CPyStatic__strategies___globals, "faster_eth_abi._grammar.ABIType", cpy_r_r8);
        goto CPyL17;
    }
    cpy_r_r10 = CPY_GET_METHOD(cpy_r_r9, CPyType__grammar___ABIType, 3, faster_eth_abi____grammar___ABITypeObject, PyObject * (*)(PyObject *))(cpy_r_r9); /* to_type_str */
    CPy_DECREF_NO_IMM(cpy_r_r9);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    cpy_r_r11 = CPyDef__strategies___StrategyRegistry___get_strategy(cpy_r_registry, cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL17;
    }
    CPyList_SetItemUnsafe(cpy_r_r3, cpy_r_r6, cpy_r_r11);
    cpy_r_r12 = cpy_r_r6 + 1;
    cpy_r_r6 = cpy_r_r12;
    goto CPyL3;
CPyL9: ;
    cpy_r_r13 = CPyStatic__strategies___globals;
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r15 = CPyDict_GetItem(cpy_r_r13, cpy_r_r14);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL18;
    }
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'tuples' */
    cpy_r_r17 = CPyObject_GetAttr(cpy_r_r15, cpy_r_r16);
    CPy_DECREF(cpy_r_r15);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL18;
    }
    cpy_r_r18 = PyList_AsTuple(cpy_r_r3);
    CPy_DECREF_NO_IMM(cpy_r_r3);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL19;
    }
    cpy_r_r19 = PyObject_CallObject(cpy_r_r17, cpy_r_r18);
    CPy_DECREF(cpy_r_r17);
    CPy_DECREF(cpy_r_r18);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL14;
    }
    return cpy_r_r19;
CPyL14: ;
    cpy_r_r20 = NULL;
    return cpy_r_r20;
CPyL15: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL14;
CPyL16: ;
    CPy_DECREF(cpy_r_r0);
    goto CPyL9;
CPyL17: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r3);
    goto CPyL14;
CPyL18: ;
    CPy_DecRef(cpy_r_r3);
    goto CPyL14;
CPyL19: ;
    CPy_DecRef(cpy_r_r17);
    goto CPyL14;
}

PyObject *CPyPy__strategies___get_tuple_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"abi_type", "registry", 0};
    static CPyArg_Parser parser = {"OO:get_tuple_strategy", kwlist, 0};
    PyObject *obj_abi_type;
    PyObject *obj_registry;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_abi_type, &obj_registry)) {
        return NULL;
    }
    PyObject *arg_abi_type;
    if (likely(PyObject_TypeCheck(obj_abi_type, CPyType__grammar___TupleType)))
        arg_abi_type = obj_abi_type;
    else {
        CPy_TypeError("faster_eth_abi._grammar.TupleType", obj_abi_type); 
        goto fail;
    }
    PyObject *arg_registry;
    if (likely(Py_TYPE(obj_registry) == CPyType__strategies___StrategyRegistry))
        arg_registry = obj_registry;
    else {
        CPy_TypeError("faster_eth_abi.tools._strategies.StrategyRegistry", obj_registry); 
        goto fail;
    }
    PyObject *retval = CPyDef__strategies___get_tuple_strategy(arg_abi_type, arg_registry);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "get_tuple_strategy", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
    return NULL;
}

char CPyDef__strategies_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    PyObject *cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject *cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    CPyPtr cpy_r_r44;
    CPyPtr cpy_r_r45;
    CPyPtr cpy_r_r46;
    PyObject *cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject *cpy_r_r49;
    PyObject *cpy_r_r50;
    PyObject *cpy_r_r51;
    tuple_T2OO cpy_r_r52;
    PyObject *cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject *cpy_r_r55;
    PyObject *cpy_r_r56;
    int32_t cpy_r_r57;
    char cpy_r_r58;
    PyObject *cpy_r_r59;
    PyObject *cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    PyObject *cpy_r_r63;
    PyObject *cpy_r_r64;
    PyObject *cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject *cpy_r_r67;
    PyObject *cpy_r_r68;
    PyObject *cpy_r_r69;
    tuple_T2OO cpy_r_r70;
    PyObject *cpy_r_r71;
    PyObject *cpy_r_r72;
    PyObject *cpy_r_r73;
    PyObject *cpy_r_r74;
    int32_t cpy_r_r75;
    char cpy_r_r76;
    PyObject *cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    PyObject *cpy_r_r80;
    PyObject *cpy_r_r81;
    PyObject *cpy_r_r82;
    PyObject *cpy_r_r83;
    char cpy_r_r84;
    PyObject *cpy_r_r85;
    PyObject *cpy_r_r86;
    PyObject *cpy_r_r87;
    PyObject *cpy_r_r88;
    int32_t cpy_r_r89;
    char cpy_r_r90;
    PyObject *cpy_r_r91;
    PyObject *cpy_r_r92;
    int32_t cpy_r_r93;
    char cpy_r_r94;
    PyObject *cpy_r_r95;
    PyObject *cpy_r_r96;
    PyObject *cpy_r_r97;
    PyObject *cpy_r_r98;
    PyObject *cpy_r_r99;
    PyObject *cpy_r_r100;
    PyObject **cpy_r_r102;
    PyObject *cpy_r_r103;
    PyObject *cpy_r_r104;
    PyObject *cpy_r_r105;
    PyObject *cpy_r_r106;
    PyObject *cpy_r_r107;
    PyObject *cpy_r_r108;
    PyObject **cpy_r_r110;
    PyObject *cpy_r_r111;
    PyObject *cpy_r_r112;
    PyObject *cpy_r_r113;
    int32_t cpy_r_r114;
    char cpy_r_r115;
    PyObject *cpy_r_r116;
    PyObject *cpy_r_r117;
    PyObject *cpy_r_r118;
    PyObject *cpy_r_r119;
    PyObject **cpy_r_r121;
    PyObject *cpy_r_r122;
    PyObject *cpy_r_r123;
    PyObject *cpy_r_r124;
    int32_t cpy_r_r125;
    char cpy_r_r126;
    PyObject *cpy_r_r127;
    PyObject *cpy_r_r128;
    PyObject *cpy_r_r129;
    PyObject *cpy_r_r130;
    PyObject *cpy_r_r131;
    PyObject *cpy_r_r132;
    PyObject **cpy_r_r134;
    PyObject *cpy_r_r135;
    PyObject *cpy_r_r136;
    PyObject *cpy_r_r137;
    PyObject *cpy_r_r138;
    int32_t cpy_r_r139;
    char cpy_r_r140;
    PyObject *cpy_r_r141;
    PyObject *cpy_r_r142;
    PyObject *cpy_r_r143;
    PyObject *cpy_r_r144;
    PyObject **cpy_r_r146;
    PyObject *cpy_r_r147;
    PyObject *cpy_r_r148;
    PyObject *cpy_r_r149;
    int32_t cpy_r_r150;
    char cpy_r_r151;
    PyObject *cpy_r_r152;
    PyObject *cpy_r_r153;
    PyObject *cpy_r_r154;
    int32_t cpy_r_r155;
    char cpy_r_r156;
    PyObject *cpy_r_r157;
    char cpy_r_r158;
    PyObject *cpy_r_r159;
    PyObject *cpy_r_r160;
    PyObject *cpy_r_r161;
    PyObject *cpy_r_r162;
    PyObject **cpy_r_r164;
    PyObject *cpy_r_r165;
    PyObject *cpy_r_r166;
    PyObject *cpy_r_r167;
    PyObject *cpy_r_r168;
    PyObject *cpy_r_r169;
    char cpy_r_r170;
    PyObject *cpy_r_r171;
    char cpy_r_r172;
    PyObject *cpy_r_r173;
    PyObject *cpy_r_r174;
    PyObject *cpy_r_r175;
    PyObject *cpy_r_r176;
    PyObject **cpy_r_r178;
    PyObject *cpy_r_r179;
    PyObject *cpy_r_r180;
    PyObject *cpy_r_r181;
    PyObject *cpy_r_r182;
    PyObject *cpy_r_r183;
    char cpy_r_r184;
    PyObject *cpy_r_r185;
    char cpy_r_r186;
    PyObject *cpy_r_r187;
    PyObject *cpy_r_r188;
    PyObject *cpy_r_r189;
    PyObject *cpy_r_r190;
    PyObject *cpy_r_r191;
    PyObject **cpy_r_r193;
    PyObject *cpy_r_r194;
    PyObject *cpy_r_r195;
    PyObject *cpy_r_r196;
    char cpy_r_r197;
    PyObject *cpy_r_r198;
    char cpy_r_r199;
    PyObject *cpy_r_r200;
    char cpy_r_r201;
    PyObject *cpy_r_r202;
    PyObject *cpy_r_r203;
    PyObject *cpy_r_r204;
    PyObject *cpy_r_r205;
    PyObject *cpy_r_r206;
    PyObject **cpy_r_r208;
    PyObject *cpy_r_r209;
    PyObject *cpy_r_r210;
    PyObject *cpy_r_r211;
    char cpy_r_r212;
    PyObject *cpy_r_r213;
    char cpy_r_r214;
    PyObject *cpy_r_r215;
    char cpy_r_r216;
    PyObject *cpy_r_r217;
    PyObject *cpy_r_r218;
    PyObject *cpy_r_r219;
    PyObject *cpy_r_r220;
    PyObject **cpy_r_r222;
    PyObject *cpy_r_r223;
    PyObject *cpy_r_r224;
    PyObject *cpy_r_r225;
    PyObject *cpy_r_r226;
    PyObject *cpy_r_r227;
    char cpy_r_r228;
    PyObject *cpy_r_r229;
    char cpy_r_r230;
    PyObject *cpy_r_r231;
    PyObject *cpy_r_r232;
    PyObject *cpy_r_r233;
    PyObject *cpy_r_r234;
    PyObject **cpy_r_r236;
    PyObject *cpy_r_r237;
    PyObject *cpy_r_r238;
    PyObject *cpy_r_r239;
    PyObject *cpy_r_r240;
    PyObject *cpy_r_r241;
    char cpy_r_r242;
    PyObject *cpy_r_r243;
    char cpy_r_r244;
    PyObject *cpy_r_r245;
    PyObject *cpy_r_r246;
    PyObject *cpy_r_r247;
    PyObject *cpy_r_r248;
    PyObject *cpy_r_r249;
    PyObject **cpy_r_r251;
    PyObject *cpy_r_r252;
    PyObject *cpy_r_r253;
    PyObject *cpy_r_r254;
    PyObject *cpy_r_r255;
    PyObject *cpy_r_r256;
    PyObject *cpy_r_r257;
    char cpy_r_r258;
    PyObject *cpy_r_r259;
    char cpy_r_r260;
    PyObject *cpy_r_r261;
    PyObject *cpy_r_r262;
    PyObject *cpy_r_r263;
    PyObject *cpy_r_r264;
    PyObject *cpy_r_r265;
    PyObject **cpy_r_r267;
    PyObject *cpy_r_r268;
    PyObject *cpy_r_r269;
    PyObject *cpy_r_r270;
    char cpy_r_r271;
    PyObject *cpy_r_r272;
    char cpy_r_r273;
    PyObject *cpy_r_r274;
    char cpy_r_r275;
    PyObject *cpy_r_r276;
    PyObject *cpy_r_r277;
    PyObject *cpy_r_r278;
    PyObject *cpy_r_r279;
    PyObject *cpy_r_r280;
    PyObject **cpy_r_r282;
    PyObject *cpy_r_r283;
    PyObject *cpy_r_r284;
    PyObject *cpy_r_r285;
    PyObject *cpy_r_r286;
    PyObject *cpy_r_r287;
    PyObject *cpy_r_r288;
    char cpy_r_r289;
    PyObject *cpy_r_r290;
    char cpy_r_r291;
    PyObject *cpy_r_r292;
    PyObject *cpy_r_r293;
    PyObject *cpy_r_r294;
    PyObject *cpy_r_r295;
    PyObject *cpy_r_r296;
    PyObject **cpy_r_r298;
    PyObject *cpy_r_r299;
    PyObject *cpy_r_r300;
    PyObject *cpy_r_r301;
    char cpy_r_r302;
    PyObject *cpy_r_r303;
    char cpy_r_r304;
    PyObject *cpy_r_r305;
    char cpy_r_r306;
    PyObject *cpy_r_r307;
    PyObject *cpy_r_r308;
    PyObject *cpy_r_r309;
    PyObject *cpy_r_r310;
    PyObject *cpy_r_r311;
    PyObject *cpy_r_r312;
    PyObject *cpy_r_r313;
    char cpy_r_r314;
    PyObject *cpy_r_r315;
    char cpy_r_r316;
    PyObject *cpy_r_r317;
    PyObject *cpy_r_r318;
    PyObject *cpy_r_r319;
    PyObject *cpy_r_r320;
    PyObject *cpy_r_r321;
    PyObject *cpy_r_r322;
    PyObject *cpy_r_r323;
    char cpy_r_r324;
    PyObject *cpy_r_r325;
    char cpy_r_r326;
    PyObject *cpy_r_r327;
    PyObject *cpy_r_r328;
    PyObject *cpy_r_r329;
    PyObject *cpy_r_r330;
    int32_t cpy_r_r331;
    char cpy_r_r332;
    char cpy_r_r333;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", -1, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Callable', 'Final', 'Optional', 'Tuple', 'Union', 'cast') */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic__strategies___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('to_checksum_address',) */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'cchecksum' */
    cpy_r_r11 = CPyStatic__strategies___globals;
    cpy_r_r12 = CPyImport_ImportFromMany(cpy_r_r10, cpy_r_r9, cpy_r_r9, cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_cchecksum = cpy_r_r12;
    CPy_INCREF(CPyModule_cchecksum);
    CPy_DECREF(cpy_r_r12);
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('TypeStr',) */
    cpy_r_r14 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'eth_typing.abi' */
    cpy_r_r15 = CPyStatic__strategies___globals;
    cpy_r_r16 = CPyImport_ImportFromMany(cpy_r_r14, cpy_r_r13, cpy_r_r13, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_eth_typing___abi = cpy_r_r16;
    CPy_INCREF(CPyModule_eth_typing___abi);
    CPy_DECREF(cpy_r_r16);
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('strategies',) */
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('st',) */
    cpy_r_r19 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'hypothesis' */
    cpy_r_r20 = CPyStatic__strategies___globals;
    cpy_r_r21 = CPyImport_ImportFromMany(cpy_r_r19, cpy_r_r17, cpy_r_r18, cpy_r_r20);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_hypothesis = cpy_r_r21;
    CPy_INCREF(CPyModule_hypothesis);
    CPy_DECREF(cpy_r_r21);
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('ABIType', 'BasicType', 'TupleType', 'normalize') */
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi._grammar' */
    cpy_r_r24 = CPyStatic__strategies___globals;
    cpy_r_r25 = CPyImport_ImportFromMany(cpy_r_r23, cpy_r_r22, cpy_r_r22, cpy_r_r24);
    if (unlikely(cpy_r_r25 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_faster_eth_abi____grammar = cpy_r_r25;
    CPy_INCREF(CPyModule_faster_eth_abi____grammar);
    CPy_DECREF(cpy_r_r25);
    cpy_r_r26 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('parse',) */
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.grammar' */
    cpy_r_r28 = CPyStatic__strategies___globals;
    cpy_r_r29 = CPyImport_ImportFromMany(cpy_r_r27, cpy_r_r26, cpy_r_r26, cpy_r_r28);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_faster_eth_abi___grammar = cpy_r_r29;
    CPy_INCREF(CPyModule_faster_eth_abi___grammar);
    CPy_DECREF(cpy_r_r29);
    cpy_r_r30 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('BaseEquals', 'BaseRegistry', 'Lookup',
                                    'PredicateMapping', 'has_arrlist', 'is_base_tuple') */
    cpy_r_r31 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.registry' */
    cpy_r_r32 = CPyStatic__strategies___globals;
    cpy_r_r33 = CPyImport_ImportFromMany(cpy_r_r31, cpy_r_r30, cpy_r_r30, cpy_r_r32);
    if (unlikely(cpy_r_r33 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_faster_eth_abi___registry = cpy_r_r33;
    CPy_INCREF(CPyModule_faster_eth_abi___registry);
    CPy_DECREF(cpy_r_r33);
    cpy_r_r34 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('scale_places',) */
    cpy_r_r35 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.utils.numeric' */
    cpy_r_r36 = CPyStatic__strategies___globals;
    cpy_r_r37 = CPyImport_ImportFromMany(cpy_r_r35, cpy_r_r34, cpy_r_r34, cpy_r_r36);
    if (unlikely(cpy_r_r37 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyModule_faster_eth_abi___utils___numeric = cpy_r_r37;
    CPy_INCREF(CPyModule_faster_eth_abi___utils___numeric);
    CPy_DECREF(cpy_r_r37);
    cpy_r_r38 = CPyStatic__strategies___globals;
    cpy_r_r39 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Callable' */
    cpy_r_r40 = CPyDict_GetItem(cpy_r_r38, cpy_r_r39);
    if (unlikely(cpy_r_r40 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r41 = (PyObject *)CPyType__grammar___ABIType;
    cpy_r_r42 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'StrategyRegistry' */
    cpy_r_r43 = PyList_New(2);
    if (unlikely(cpy_r_r43 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL143;
    }
    cpy_r_r44 = (CPyPtr)&((PyListObject *)cpy_r_r43)->ob_item;
    cpy_r_r45 = *(CPyPtr *)cpy_r_r44;
    CPy_INCREF(cpy_r_r41);
    *(PyObject * *)cpy_r_r45 = cpy_r_r41;
    CPy_INCREF(cpy_r_r42);
    cpy_r_r46 = cpy_r_r45 + 8;
    *(PyObject * *)cpy_r_r46 = cpy_r_r42;
    cpy_r_r47 = CPyStatic__strategies___globals;
    cpy_r_r48 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r49 = CPyDict_GetItem(cpy_r_r47, cpy_r_r48);
    if (unlikely(cpy_r_r49 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL144;
    }
    cpy_r_r50 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'SearchStrategy' */
    cpy_r_r51 = CPyObject_GetAttr(cpy_r_r49, cpy_r_r50);
    CPy_DECREF(cpy_r_r49);
    if (unlikely(cpy_r_r51 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL144;
    }
    cpy_r_r52.f0 = cpy_r_r43;
    cpy_r_r52.f1 = cpy_r_r51;
    cpy_r_r53 = PyTuple_New(2);
    if (unlikely(cpy_r_r53 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp50 = cpy_r_r52.f0;
    PyTuple_SET_ITEM(cpy_r_r53, 0, __tmp50);
    PyObject *__tmp51 = cpy_r_r52.f1;
    PyTuple_SET_ITEM(cpy_r_r53, 1, __tmp51);
    cpy_r_r54 = PyObject_GetItem(cpy_r_r40, cpy_r_r53);
    CPy_DECREF(cpy_r_r40);
    CPy_DECREF(cpy_r_r53);
    if (unlikely(cpy_r_r54 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r55 = CPyStatic__strategies___globals;
    cpy_r_r56 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'StrategyFactory' */
    cpy_r_r57 = CPyDict_SetItem(cpy_r_r55, cpy_r_r56, cpy_r_r54);
    CPy_DECREF(cpy_r_r54);
    cpy_r_r58 = cpy_r_r57 >= 0;
    if (unlikely(!cpy_r_r58)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r59 = CPyStatic__strategies___globals;
    cpy_r_r60 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Union' */
    cpy_r_r61 = CPyDict_GetItem(cpy_r_r59, cpy_r_r60);
    if (unlikely(cpy_r_r61 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r62 = CPyStatic__strategies___globals;
    cpy_r_r63 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r64 = CPyDict_GetItem(cpy_r_r62, cpy_r_r63);
    if (unlikely(cpy_r_r64 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL145;
    }
    cpy_r_r65 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'SearchStrategy' */
    cpy_r_r66 = CPyObject_GetAttr(cpy_r_r64, cpy_r_r65);
    CPy_DECREF(cpy_r_r64);
    if (unlikely(cpy_r_r66 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL145;
    }
    cpy_r_r67 = CPyStatic__strategies___globals;
    cpy_r_r68 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'StrategyFactory' */
    cpy_r_r69 = CPyDict_GetItem(cpy_r_r67, cpy_r_r68);
    if (unlikely(cpy_r_r69 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL146;
    }
    cpy_r_r70.f0 = cpy_r_r66;
    cpy_r_r70.f1 = cpy_r_r69;
    cpy_r_r71 = PyTuple_New(2);
    if (unlikely(cpy_r_r71 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp52 = cpy_r_r70.f0;
    PyTuple_SET_ITEM(cpy_r_r71, 0, __tmp52);
    PyObject *__tmp53 = cpy_r_r70.f1;
    PyTuple_SET_ITEM(cpy_r_r71, 1, __tmp53);
    cpy_r_r72 = PyObject_GetItem(cpy_r_r61, cpy_r_r71);
    CPy_DECREF(cpy_r_r61);
    CPy_DECREF(cpy_r_r71);
    if (unlikely(cpy_r_r72 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r73 = CPyStatic__strategies___globals;
    cpy_r_r74 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'StrategyRegistration' */
    cpy_r_r75 = CPyDict_SetItem(cpy_r_r73, cpy_r_r74, cpy_r_r72);
    CPy_DECREF(cpy_r_r72);
    cpy_r_r76 = cpy_r_r75 >= 0;
    if (unlikely(!cpy_r_r76)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r77 = CPyStatic__strategies___globals;
    cpy_r_r78 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseRegistry' */
    cpy_r_r79 = CPyDict_GetItem(cpy_r_r77, cpy_r_r78);
    if (unlikely(cpy_r_r79 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r80 = PyTuple_Pack(1, cpy_r_r79);
    CPy_DECREF(cpy_r_r79);
    if (unlikely(cpy_r_r80 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r81 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi.tools._strategies' */
    cpy_r_r82 = (PyObject *)CPyType__strategies___StrategyRegistry_template;
    cpy_r_r83 = CPyType_FromTemplate(cpy_r_r82, cpy_r_r80, cpy_r_r81);
    CPy_DECREF(cpy_r_r80);
    if (unlikely(cpy_r_r83 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r84 = CPyDef__strategies___StrategyRegistry_trait_vtable_setup();
    if (unlikely(cpy_r_r84 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", -1, CPyStatic__strategies___globals);
        goto CPyL147;
    }
    cpy_r_r85 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__mypyc_attrs__' */
    cpy_r_r86 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_strategies' */
    cpy_r_r87 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__dict__' */
    cpy_r_r88 = PyTuple_Pack(2, cpy_r_r86, cpy_r_r87);
    if (unlikely(cpy_r_r88 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL147;
    }
    cpy_r_r89 = PyObject_SetAttr(cpy_r_r83, cpy_r_r85, cpy_r_r88);
    CPy_DECREF(cpy_r_r88);
    cpy_r_r90 = cpy_r_r89 >= 0;
    if (unlikely(!cpy_r_r90)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL147;
    }
    CPyType__strategies___StrategyRegistry = (PyTypeObject *)cpy_r_r83;
    CPy_INCREF(CPyType__strategies___StrategyRegistry);
    cpy_r_r91 = CPyStatic__strategies___globals;
    cpy_r_r92 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'StrategyRegistry' */
    cpy_r_r93 = PyDict_SetItem(cpy_r_r91, cpy_r_r92, cpy_r_r83);
    CPy_DECREF(cpy_r_r83);
    cpy_r_r94 = cpy_r_r93 >= 0;
    if (unlikely(!cpy_r_r94)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r95 = CPyStatic__strategies___globals;
    cpy_r_r96 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r97 = CPyDict_GetItem(cpy_r_r95, cpy_r_r96);
    if (unlikely(cpy_r_r97 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r98 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'binary' */
    cpy_r_r99 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 20 */
    cpy_r_r100 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 20 */
    PyObject *cpy_r_r101[3] = {cpy_r_r97, cpy_r_r99, cpy_r_r100};
    cpy_r_r102 = (PyObject **)&cpy_r_r101;
    cpy_r_r103 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_size', 'max_size') */
    cpy_r_r104 = PyObject_VectorcallMethod(cpy_r_r98, cpy_r_r102, 9223372036854775809ULL, cpy_r_r103);
    if (unlikely(cpy_r_r104 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL148;
    }
    CPy_DECREF(cpy_r_r97);
    cpy_r_r105 = CPyStatic__strategies___globals;
    cpy_r_r106 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'to_checksum_address' */
    cpy_r_r107 = CPyDict_GetItem(cpy_r_r105, cpy_r_r106);
    if (unlikely(cpy_r_r107 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL149;
    }
    cpy_r_r108 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'map' */
    PyObject *cpy_r_r109[2] = {cpy_r_r104, cpy_r_r107};
    cpy_r_r110 = (PyObject **)&cpy_r_r109;
    cpy_r_r111 = PyObject_VectorcallMethod(cpy_r_r108, cpy_r_r110, 9223372036854775810ULL, 0);
    if (unlikely(cpy_r_r111 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL150;
    }
    CPy_DECREF(cpy_r_r104);
    CPy_DECREF(cpy_r_r107);
    CPyStatic__strategies___address_strategy = cpy_r_r111;
    CPy_INCREF(CPyStatic__strategies___address_strategy);
    cpy_r_r112 = CPyStatic__strategies___globals;
    cpy_r_r113 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'address_strategy' */
    cpy_r_r114 = CPyDict_SetItem(cpy_r_r112, cpy_r_r113, cpy_r_r111);
    CPy_DECREF(cpy_r_r111);
    cpy_r_r115 = cpy_r_r114 >= 0;
    if (unlikely(!cpy_r_r115)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r116 = CPyStatic__strategies___globals;
    cpy_r_r117 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r118 = CPyDict_GetItem(cpy_r_r116, cpy_r_r117);
    if (unlikely(cpy_r_r118 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r119 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'booleans' */
    PyObject *cpy_r_r120[1] = {cpy_r_r118};
    cpy_r_r121 = (PyObject **)&cpy_r_r120;
    cpy_r_r122 = PyObject_VectorcallMethod(cpy_r_r119, cpy_r_r121, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r122 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL151;
    }
    CPy_DECREF(cpy_r_r118);
    CPyStatic__strategies___bool_strategy = cpy_r_r122;
    CPy_INCREF(CPyStatic__strategies___bool_strategy);
    cpy_r_r123 = CPyStatic__strategies___globals;
    cpy_r_r124 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bool_strategy' */
    cpy_r_r125 = CPyDict_SetItem(cpy_r_r123, cpy_r_r124, cpy_r_r122);
    CPy_DECREF(cpy_r_r122);
    cpy_r_r126 = cpy_r_r125 >= 0;
    if (unlikely(!cpy_r_r126)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r127 = CPyStatic__strategies___globals;
    cpy_r_r128 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r129 = CPyDict_GetItem(cpy_r_r127, cpy_r_r128);
    if (unlikely(cpy_r_r129 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r130 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'binary' */
    cpy_r_r131 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    cpy_r_r132 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 4096 */
    PyObject *cpy_r_r133[3] = {cpy_r_r129, cpy_r_r131, cpy_r_r132};
    cpy_r_r134 = (PyObject **)&cpy_r_r133;
    cpy_r_r135 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('min_size', 'max_size') */
    cpy_r_r136 = PyObject_VectorcallMethod(cpy_r_r130, cpy_r_r134, 9223372036854775809ULL, cpy_r_r135);
    if (unlikely(cpy_r_r136 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL152;
    }
    CPy_DECREF(cpy_r_r129);
    CPyStatic__strategies___bytes_strategy = cpy_r_r136;
    CPy_INCREF(CPyStatic__strategies___bytes_strategy);
    cpy_r_r137 = CPyStatic__strategies___globals;
    cpy_r_r138 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes_strategy' */
    cpy_r_r139 = CPyDict_SetItem(cpy_r_r137, cpy_r_r138, cpy_r_r136);
    CPy_DECREF(cpy_r_r136);
    cpy_r_r140 = cpy_r_r139 >= 0;
    if (unlikely(!cpy_r_r140)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r141 = CPyStatic__strategies___globals;
    cpy_r_r142 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'st' */
    cpy_r_r143 = CPyDict_GetItem(cpy_r_r141, cpy_r_r142);
    if (unlikely(cpy_r_r143 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r144 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'text' */
    PyObject *cpy_r_r145[1] = {cpy_r_r143};
    cpy_r_r146 = (PyObject **)&cpy_r_r145;
    cpy_r_r147 = PyObject_VectorcallMethod(cpy_r_r144, cpy_r_r146, 9223372036854775809ULL, 0);
    if (unlikely(cpy_r_r147 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL153;
    }
    CPy_DECREF(cpy_r_r143);
    CPyStatic__strategies___string_strategy = cpy_r_r147;
    CPy_INCREF(CPyStatic__strategies___string_strategy);
    cpy_r_r148 = CPyStatic__strategies___globals;
    cpy_r_r149 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'string_strategy' */
    cpy_r_r150 = CPyDict_SetItem(cpy_r_r148, cpy_r_r149, cpy_r_r147);
    CPy_DECREF(cpy_r_r147);
    cpy_r_r151 = cpy_r_r150 >= 0;
    if (unlikely(!cpy_r_r151)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r152 = CPyDef__strategies___StrategyRegistry();
    if (unlikely(cpy_r_r152 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyStatic__strategies___strategy_registry = cpy_r_r152;
    CPy_INCREF_NO_IMM(CPyStatic__strategies___strategy_registry);
    cpy_r_r153 = CPyStatic__strategies___globals;
    cpy_r_r154 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'strategy_registry' */
    cpy_r_r155 = CPyDict_SetItem(cpy_r_r153, cpy_r_r154, cpy_r_r152);
    CPy_DECREF_NO_IMM(cpy_r_r152);
    cpy_r_r156 = cpy_r_r155 >= 0;
    if (unlikely(!cpy_r_r156)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r157 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r157 != NULL)) goto CPyL49;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r158 = 0;
    if (unlikely(!cpy_r_r158)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL49: ;
    cpy_r_r159 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'uint' */
    cpy_r_r160 = CPyStatic__strategies___globals;
    cpy_r_r161 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r162 = CPyDict_GetItem(cpy_r_r160, cpy_r_r161);
    if (unlikely(cpy_r_r162 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    PyObject *cpy_r_r163[1] = {cpy_r_r159};
    cpy_r_r164 = (PyObject **)&cpy_r_r163;
    cpy_r_r165 = PyObject_Vectorcall(cpy_r_r162, cpy_r_r164, 1, 0);
    CPy_DECREF(cpy_r_r162);
    if (unlikely(cpy_r_r165 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r166 = CPyStatic__strategies___globals;
    cpy_r_r167 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_uint_strategy' */
    cpy_r_r168 = CPyDict_GetItem(cpy_r_r166, cpy_r_r167);
    if (unlikely(cpy_r_r168 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL154;
    }
    cpy_r_r169 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'uint' */
    cpy_r_r170 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r157, cpy_r_r165, cpy_r_r168, cpy_r_r169);
    CPy_DECREF(cpy_r_r165);
    CPy_DECREF(cpy_r_r168);
    if (unlikely(cpy_r_r170 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r171 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r171 != NULL)) goto CPyL56;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r172 = 0;
    if (unlikely(!cpy_r_r172)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL56: ;
    cpy_r_r173 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'int' */
    cpy_r_r174 = CPyStatic__strategies___globals;
    cpy_r_r175 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r176 = CPyDict_GetItem(cpy_r_r174, cpy_r_r175);
    if (unlikely(cpy_r_r176 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    PyObject *cpy_r_r177[1] = {cpy_r_r173};
    cpy_r_r178 = (PyObject **)&cpy_r_r177;
    cpy_r_r179 = PyObject_Vectorcall(cpy_r_r176, cpy_r_r178, 1, 0);
    CPy_DECREF(cpy_r_r176);
    if (unlikely(cpy_r_r179 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r180 = CPyStatic__strategies___globals;
    cpy_r_r181 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_int_strategy' */
    cpy_r_r182 = CPyDict_GetItem(cpy_r_r180, cpy_r_r181);
    if (unlikely(cpy_r_r182 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL155;
    }
    cpy_r_r183 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'int' */
    cpy_r_r184 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r171, cpy_r_r179, cpy_r_r182, cpy_r_r183);
    CPy_DECREF(cpy_r_r179);
    CPy_DECREF(cpy_r_r182);
    if (unlikely(cpy_r_r184 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r185 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r185 != NULL)) goto CPyL63;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r186 = 0;
    if (unlikely(!cpy_r_r186)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL63: ;
    cpy_r_r187 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'address' */
    cpy_r_r188 = CPyStatic__strategies___globals;
    cpy_r_r189 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r190 = CPyDict_GetItem(cpy_r_r188, cpy_r_r189);
    if (unlikely(cpy_r_r190 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r191 = 0 ? Py_True : Py_False;
    PyObject *cpy_r_r192[2] = {cpy_r_r187, cpy_r_r191};
    cpy_r_r193 = (PyObject **)&cpy_r_r192;
    cpy_r_r194 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('with_sub',) */
    cpy_r_r195 = PyObject_Vectorcall(cpy_r_r190, cpy_r_r193, 1, cpy_r_r194);
    CPy_DECREF(cpy_r_r190);
    if (unlikely(cpy_r_r195 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r196 = CPyStatic__strategies___address_strategy;
    if (unlikely(cpy_r_r196 == NULL)) {
        goto CPyL156;
    } else
        goto CPyL68;
CPyL66: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"address_strategy\" was not set");
    cpy_r_r197 = 0;
    if (unlikely(!cpy_r_r197)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL68: ;
    cpy_r_r198 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'address' */
    cpy_r_r199 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r185, cpy_r_r195, cpy_r_r196, cpy_r_r198);
    CPy_DECREF(cpy_r_r195);
    if (unlikely(cpy_r_r199 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r200 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r200 != NULL)) goto CPyL72;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r201 = 0;
    if (unlikely(!cpy_r_r201)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL72: ;
    cpy_r_r202 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bool' */
    cpy_r_r203 = CPyStatic__strategies___globals;
    cpy_r_r204 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r205 = CPyDict_GetItem(cpy_r_r203, cpy_r_r204);
    if (unlikely(cpy_r_r205 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r206 = 0 ? Py_True : Py_False;
    PyObject *cpy_r_r207[2] = {cpy_r_r202, cpy_r_r206};
    cpy_r_r208 = (PyObject **)&cpy_r_r207;
    cpy_r_r209 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('with_sub',) */
    cpy_r_r210 = PyObject_Vectorcall(cpy_r_r205, cpy_r_r208, 1, cpy_r_r209);
    CPy_DECREF(cpy_r_r205);
    if (unlikely(cpy_r_r210 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r211 = CPyStatic__strategies___bool_strategy;
    if (unlikely(cpy_r_r211 == NULL)) {
        goto CPyL157;
    } else
        goto CPyL77;
CPyL75: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"bool_strategy\" was not set");
    cpy_r_r212 = 0;
    if (unlikely(!cpy_r_r212)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL77: ;
    cpy_r_r213 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bool' */
    cpy_r_r214 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r200, cpy_r_r210, cpy_r_r211, cpy_r_r213);
    CPy_DECREF(cpy_r_r210);
    if (unlikely(cpy_r_r214 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r215 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r215 != NULL)) goto CPyL81;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r216 = 0;
    if (unlikely(!cpy_r_r216)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL81: ;
    cpy_r_r217 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ufixed' */
    cpy_r_r218 = CPyStatic__strategies___globals;
    cpy_r_r219 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r220 = CPyDict_GetItem(cpy_r_r218, cpy_r_r219);
    if (unlikely(cpy_r_r220 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    PyObject *cpy_r_r221[1] = {cpy_r_r217};
    cpy_r_r222 = (PyObject **)&cpy_r_r221;
    cpy_r_r223 = PyObject_Vectorcall(cpy_r_r220, cpy_r_r222, 1, 0);
    CPy_DECREF(cpy_r_r220);
    if (unlikely(cpy_r_r223 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r224 = CPyStatic__strategies___globals;
    cpy_r_r225 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_ufixed_strategy' */
    cpy_r_r226 = CPyDict_GetItem(cpy_r_r224, cpy_r_r225);
    if (unlikely(cpy_r_r226 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL158;
    }
    cpy_r_r227 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ufixed' */
    cpy_r_r228 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r215, cpy_r_r223, cpy_r_r226, cpy_r_r227);
    CPy_DECREF(cpy_r_r223);
    CPy_DECREF(cpy_r_r226);
    if (unlikely(cpy_r_r228 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r229 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r229 != NULL)) goto CPyL88;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r230 = 0;
    if (unlikely(!cpy_r_r230)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL88: ;
    cpy_r_r231 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed' */
    cpy_r_r232 = CPyStatic__strategies___globals;
    cpy_r_r233 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r234 = CPyDict_GetItem(cpy_r_r232, cpy_r_r233);
    if (unlikely(cpy_r_r234 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    PyObject *cpy_r_r235[1] = {cpy_r_r231};
    cpy_r_r236 = (PyObject **)&cpy_r_r235;
    cpy_r_r237 = PyObject_Vectorcall(cpy_r_r234, cpy_r_r236, 1, 0);
    CPy_DECREF(cpy_r_r234);
    if (unlikely(cpy_r_r237 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r238 = CPyStatic__strategies___globals;
    cpy_r_r239 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_fixed_strategy' */
    cpy_r_r240 = CPyDict_GetItem(cpy_r_r238, cpy_r_r239);
    if (unlikely(cpy_r_r240 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL159;
    }
    cpy_r_r241 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'fixed' */
    cpy_r_r242 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r229, cpy_r_r237, cpy_r_r240, cpy_r_r241);
    CPy_DECREF(cpy_r_r237);
    CPy_DECREF(cpy_r_r240);
    if (unlikely(cpy_r_r242 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r243 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r243 != NULL)) goto CPyL95;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r244 = 0;
    if (unlikely(!cpy_r_r244)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL95: ;
    cpy_r_r245 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes' */
    cpy_r_r246 = CPyStatic__strategies___globals;
    cpy_r_r247 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r248 = CPyDict_GetItem(cpy_r_r246, cpy_r_r247);
    if (unlikely(cpy_r_r248 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r249 = 1 ? Py_True : Py_False;
    PyObject *cpy_r_r250[2] = {cpy_r_r245, cpy_r_r249};
    cpy_r_r251 = (PyObject **)&cpy_r_r250;
    cpy_r_r252 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('with_sub',) */
    cpy_r_r253 = PyObject_Vectorcall(cpy_r_r248, cpy_r_r251, 1, cpy_r_r252);
    CPy_DECREF(cpy_r_r248);
    if (unlikely(cpy_r_r253 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r254 = CPyStatic__strategies___globals;
    cpy_r_r255 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_bytes_strategy' */
    cpy_r_r256 = CPyDict_GetItem(cpy_r_r254, cpy_r_r255);
    if (unlikely(cpy_r_r256 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL160;
    }
    cpy_r_r257 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes<M>' */
    cpy_r_r258 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r243, cpy_r_r253, cpy_r_r256, cpy_r_r257);
    CPy_DECREF(cpy_r_r253);
    CPy_DECREF(cpy_r_r256);
    if (unlikely(cpy_r_r258 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r259 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r259 != NULL)) goto CPyL102;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r260 = 0;
    if (unlikely(!cpy_r_r260)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL102: ;
    cpy_r_r261 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes' */
    cpy_r_r262 = CPyStatic__strategies___globals;
    cpy_r_r263 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r264 = CPyDict_GetItem(cpy_r_r262, cpy_r_r263);
    if (unlikely(cpy_r_r264 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r265 = 0 ? Py_True : Py_False;
    PyObject *cpy_r_r266[2] = {cpy_r_r261, cpy_r_r265};
    cpy_r_r267 = (PyObject **)&cpy_r_r266;
    cpy_r_r268 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('with_sub',) */
    cpy_r_r269 = PyObject_Vectorcall(cpy_r_r264, cpy_r_r267, 1, cpy_r_r268);
    CPy_DECREF(cpy_r_r264);
    if (unlikely(cpy_r_r269 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r270 = CPyStatic__strategies___bytes_strategy;
    if (unlikely(cpy_r_r270 == NULL)) {
        goto CPyL161;
    } else
        goto CPyL107;
CPyL105: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"bytes_strategy\" was not set");
    cpy_r_r271 = 0;
    if (unlikely(!cpy_r_r271)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL107: ;
    cpy_r_r272 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes' */
    cpy_r_r273 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r259, cpy_r_r269, cpy_r_r270, cpy_r_r272);
    CPy_DECREF(cpy_r_r269);
    if (unlikely(cpy_r_r273 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r274 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r274 != NULL)) goto CPyL111;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r275 = 0;
    if (unlikely(!cpy_r_r275)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL111: ;
    cpy_r_r276 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'function' */
    cpy_r_r277 = CPyStatic__strategies___globals;
    cpy_r_r278 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r279 = CPyDict_GetItem(cpy_r_r277, cpy_r_r278);
    if (unlikely(cpy_r_r279 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r280 = 0 ? Py_True : Py_False;
    PyObject *cpy_r_r281[2] = {cpy_r_r276, cpy_r_r280};
    cpy_r_r282 = (PyObject **)&cpy_r_r281;
    cpy_r_r283 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('with_sub',) */
    cpy_r_r284 = PyObject_Vectorcall(cpy_r_r279, cpy_r_r282, 1, cpy_r_r283);
    CPy_DECREF(cpy_r_r279);
    if (unlikely(cpy_r_r284 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r285 = CPyStatic__strategies___globals;
    cpy_r_r286 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_bytes_strategy' */
    cpy_r_r287 = CPyDict_GetItem(cpy_r_r285, cpy_r_r286);
    if (unlikely(cpy_r_r287 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL162;
    }
    cpy_r_r288 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'function' */
    cpy_r_r289 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r274, cpy_r_r284, cpy_r_r287, cpy_r_r288);
    CPy_DECREF(cpy_r_r284);
    CPy_DECREF(cpy_r_r287);
    if (unlikely(cpy_r_r289 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r290 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r290 != NULL)) goto CPyL118;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r291 = 0;
    if (unlikely(!cpy_r_r291)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL118: ;
    cpy_r_r292 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'string' */
    cpy_r_r293 = CPyStatic__strategies___globals;
    cpy_r_r294 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'BaseEquals' */
    cpy_r_r295 = CPyDict_GetItem(cpy_r_r293, cpy_r_r294);
    if (unlikely(cpy_r_r295 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r296 = 0 ? Py_True : Py_False;
    PyObject *cpy_r_r297[2] = {cpy_r_r292, cpy_r_r296};
    cpy_r_r298 = (PyObject **)&cpy_r_r297;
    cpy_r_r299 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('with_sub',) */
    cpy_r_r300 = PyObject_Vectorcall(cpy_r_r295, cpy_r_r298, 1, cpy_r_r299);
    CPy_DECREF(cpy_r_r295);
    if (unlikely(cpy_r_r300 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r301 = CPyStatic__strategies___string_strategy;
    if (unlikely(cpy_r_r301 == NULL)) {
        goto CPyL163;
    } else
        goto CPyL123;
CPyL121: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"string_strategy\" was not set");
    cpy_r_r302 = 0;
    if (unlikely(!cpy_r_r302)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL123: ;
    cpy_r_r303 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'string' */
    cpy_r_r304 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r290, cpy_r_r300, cpy_r_r301, cpy_r_r303);
    CPy_DECREF(cpy_r_r300);
    if (unlikely(cpy_r_r304 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r305 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r305 != NULL)) goto CPyL127;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r306 = 0;
    if (unlikely(!cpy_r_r306)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL127: ;
    cpy_r_r307 = CPyStatic__strategies___globals;
    cpy_r_r308 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'has_arrlist' */
    cpy_r_r309 = CPyDict_GetItem(cpy_r_r307, cpy_r_r308);
    if (unlikely(cpy_r_r309 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r310 = CPyStatic__strategies___globals;
    cpy_r_r311 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_array_strategy' */
    cpy_r_r312 = CPyDict_GetItem(cpy_r_r310, cpy_r_r311);
    if (unlikely(cpy_r_r312 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL164;
    }
    cpy_r_r313 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'has_arrlist' */
    cpy_r_r314 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r305, cpy_r_r309, cpy_r_r312, cpy_r_r313);
    CPy_DECREF(cpy_r_r309);
    CPy_DECREF(cpy_r_r312);
    if (unlikely(cpy_r_r314 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r315 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r315 != NULL)) goto CPyL133;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r316 = 0;
    if (unlikely(!cpy_r_r316)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL133: ;
    cpy_r_r317 = CPyStatic__strategies___globals;
    cpy_r_r318 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_base_tuple' */
    cpy_r_r319 = CPyDict_GetItem(cpy_r_r317, cpy_r_r318);
    if (unlikely(cpy_r_r319 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r320 = CPyStatic__strategies___globals;
    cpy_r_r321 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_tuple_strategy' */
    cpy_r_r322 = CPyDict_GetItem(cpy_r_r320, cpy_r_r321);
    if (unlikely(cpy_r_r322 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL165;
    }
    cpy_r_r323 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'is_base_tuple' */
    cpy_r_r324 = CPyDef__strategies___StrategyRegistry___register_strategy(cpy_r_r315, cpy_r_r319, cpy_r_r322, cpy_r_r323);
    CPy_DECREF(cpy_r_r319);
    CPy_DECREF(cpy_r_r322);
    if (unlikely(cpy_r_r324 == 2)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    cpy_r_r325 = CPyStatic__strategies___strategy_registry;
    if (likely(cpy_r_r325 != NULL)) goto CPyL139;
    PyErr_SetString(PyExc_NameError, "value for final name \"strategy_registry\" was not set");
    cpy_r_r326 = 0;
    if (unlikely(!cpy_r_r326)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPy_Unreachable();
CPyL139: ;
    cpy_r_r327 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_strategy' */
    cpy_r_r328 = CPyObject_GetAttr(cpy_r_r325, cpy_r_r327);
    if (unlikely(cpy_r_r328 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    CPyStatic__strategies___get_abi_strategy = cpy_r_r328;
    CPy_INCREF(CPyStatic__strategies___get_abi_strategy);
    cpy_r_r329 = CPyStatic__strategies___globals;
    cpy_r_r330 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'get_abi_strategy' */
    cpy_r_r331 = CPyDict_SetItem(cpy_r_r329, cpy_r_r330, cpy_r_r328);
    CPy_DECREF(cpy_r_r328);
    cpy_r_r332 = cpy_r_r331 >= 0;
    if (unlikely(!cpy_r_r332)) {
        CPy_AddTraceback("faster_eth_abi/tools/_strategies.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic__strategies___globals);
        goto CPyL142;
    }
    return 1;
CPyL142: ;
    cpy_r_r333 = 2;
    return cpy_r_r333;
CPyL143: ;
    CPy_DecRef(cpy_r_r40);
    goto CPyL142;
CPyL144: ;
    CPy_DecRef(cpy_r_r40);
    CPy_DecRef(cpy_r_r43);
    goto CPyL142;
CPyL145: ;
    CPy_DecRef(cpy_r_r61);
    goto CPyL142;
CPyL146: ;
    CPy_DecRef(cpy_r_r61);
    CPy_DecRef(cpy_r_r66);
    goto CPyL142;
CPyL147: ;
    CPy_DecRef(cpy_r_r83);
    goto CPyL142;
CPyL148: ;
    CPy_DecRef(cpy_r_r97);
    goto CPyL142;
CPyL149: ;
    CPy_DecRef(cpy_r_r104);
    goto CPyL142;
CPyL150: ;
    CPy_DecRef(cpy_r_r104);
    CPy_DecRef(cpy_r_r107);
    goto CPyL142;
CPyL151: ;
    CPy_DecRef(cpy_r_r118);
    goto CPyL142;
CPyL152: ;
    CPy_DecRef(cpy_r_r129);
    goto CPyL142;
CPyL153: ;
    CPy_DecRef(cpy_r_r143);
    goto CPyL142;
CPyL154: ;
    CPy_DecRef(cpy_r_r165);
    goto CPyL142;
CPyL155: ;
    CPy_DecRef(cpy_r_r179);
    goto CPyL142;
CPyL156: ;
    CPy_DecRef(cpy_r_r195);
    goto CPyL66;
CPyL157: ;
    CPy_DecRef(cpy_r_r210);
    goto CPyL75;
CPyL158: ;
    CPy_DecRef(cpy_r_r223);
    goto CPyL142;
CPyL159: ;
    CPy_DecRef(cpy_r_r237);
    goto CPyL142;
CPyL160: ;
    CPy_DecRef(cpy_r_r253);
    goto CPyL142;
CPyL161: ;
    CPy_DecRef(cpy_r_r269);
    goto CPyL105;
CPyL162: ;
    CPy_DecRef(cpy_r_r284);
    goto CPyL142;
CPyL163: ;
    CPy_DecRef(cpy_r_r300);
    goto CPyL121;
CPyL164: ;
    CPy_DecRef(cpy_r_r309);
    goto CPyL142;
CPyL165: ;
    CPy_DecRef(cpy_r_r319);
    goto CPyL142;
}
static PyMethodDef utilsmodule_methods[] = {
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___utils(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___utils__internal, "__name__");
    CPyStatic_utils___globals = PyModule_GetDict(CPyModule_faster_eth_abi___utils__internal);
    if (unlikely(CPyStatic_utils___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_utils_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___utils__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef utilsmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.utils",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    utilsmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___utils(void)
{
    if (CPyModule_faster_eth_abi___utils__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___utils__internal);
        return CPyModule_faster_eth_abi___utils__internal;
    }
    CPyModule_faster_eth_abi___utils__internal = PyModule_Create(&utilsmodule);
    if (unlikely(CPyModule_faster_eth_abi___utils__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___utils(CPyModule_faster_eth_abi___utils__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___utils__internal;
    fail:
    return NULL;
}

char CPyDef_utils_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/__init__.py", "<module>", -1, CPyStatic_utils___globals);
        goto CPyL4;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    return 1;
CPyL4: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
}

PyObject *CPyDef_numeric_____mypyc__scale_places_env_setup(PyObject *cpy_r_type);
PyObject *CPyDef_numeric___scale_places_env(void);

static PyObject *
numeric___scale_places_env_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_numeric___scale_places_env) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_numeric_____mypyc__scale_places_env_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
numeric___scale_places_env_traverse(faster_eth_abi___utils___numeric___scale_places_envObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_self__);
    Py_VISIT(self->_scaling_factor);
    Py_VISIT(self->_f);
    if (CPyTagged_CheckLong(self->_places)) {
        Py_VISIT(CPyTagged_LongAsObject(self->_places));
    }
    return 0;
}

static int
numeric___scale_places_env_clear(faster_eth_abi___utils___numeric___scale_places_envObject *self)
{
    Py_CLEAR(self->___mypyc_self__);
    Py_CLEAR(self->_scaling_factor);
    Py_CLEAR(self->_f);
    if (CPyTagged_CheckLong(self->_places)) {
        CPyTagged __tmp = self->_places;
        self->_places = CPY_INT_TAG;
        Py_XDECREF(CPyTagged_LongAsObject(__tmp));
    }
    return 0;
}

static void
numeric___scale_places_env_dealloc(faster_eth_abi___utils___numeric___scale_places_envObject *self)
{
    PyObject_GC_UnTrack(self);
    if (numeric___scale_places_env_free_instance == NULL) {
        numeric___scale_places_env_free_instance = self;
        Py_CLEAR(self->___mypyc_self__);
        Py_CLEAR(self->_scaling_factor);
        Py_CLEAR(self->_f);
        if (CPyTagged_CheckLong(self->_places)) {
            CPyTagged __tmp = self->_places;
            self->_places = CPY_INT_TAG;
            Py_XDECREF(CPyTagged_LongAsObject(__tmp));
        } else {
            self->_places = CPY_INT_TAG;
        }
        return;
    }
    CPy_TRASHCAN_BEGIN(self, numeric___scale_places_env_dealloc)
    numeric___scale_places_env_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem numeric___scale_places_env_vtable[1];
static bool
CPyDef_numeric___scale_places_env_trait_vtable_setup(void)
{
    CPyVTableItem numeric___scale_places_env_vtable_scratch[] = {
        NULL
    };
    memcpy(numeric___scale_places_env_vtable, numeric___scale_places_env_vtable_scratch, sizeof(numeric___scale_places_env_vtable));
    return 1;
}

static PyMethodDef numeric___scale_places_env_methods[] = {
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_numeric___scale_places_env_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "scale_places_env",
    .tp_new = numeric___scale_places_env_new,
    .tp_dealloc = (destructor)numeric___scale_places_env_dealloc,
    .tp_traverse = (traverseproc)numeric___scale_places_env_traverse,
    .tp_clear = (inquiry)numeric___scale_places_env_clear,
    .tp_methods = numeric___scale_places_env_methods,
    .tp_basicsize = sizeof(faster_eth_abi___utils___numeric___scale_places_envObject),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc = PyDoc_STR("scale_places_env()\n--\n\n"),
};
static PyTypeObject *CPyType_numeric___scale_places_env_template = &CPyType_numeric___scale_places_env_template_;

PyObject *CPyDef_numeric_____mypyc__scale_places_env_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___utils___numeric___scale_places_envObject *self;
    if (numeric___scale_places_env_free_instance != NULL) {
        self = numeric___scale_places_env_free_instance;
        numeric___scale_places_env_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___utils___numeric___scale_places_envObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = numeric___scale_places_env_vtable;
    self->_places = CPY_INT_TAG;
    return (PyObject *)self;
}

PyObject *CPyDef_numeric___scale_places_env(void)
{
    PyObject *self = CPyDef_numeric_____mypyc__scale_places_env_setup((PyObject *)CPyType_numeric___scale_places_env);
    if (self == NULL)
        return NULL;
    return self;
}


static PyObject *CPyDunder___get__numeric___f_scale_places_obj(PyObject *self, PyObject *instance, PyObject *owner) {
    instance = instance ? instance : Py_None;
    return CPyDef_numeric___f_scale_places_obj_____get__(self, instance, owner);
}
PyObject *CPyDef_numeric_____mypyc__f_scale_places_obj_setup(PyObject *cpy_r_type);
PyObject *CPyDef_numeric___f_scale_places_obj(void);

static PyObject *
numeric___f_scale_places_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    if (type != CPyType_numeric___f_scale_places_obj) {
        PyErr_SetString(PyExc_TypeError, "interpreted classes cannot inherit from compiled");
        return NULL;
    }
    PyObject *self = CPyDef_numeric_____mypyc__f_scale_places_obj_setup((PyObject*)type);
    if (self == NULL)
        return NULL;
    return self;
}

static int
numeric___f_scale_places_obj_traverse(faster_eth_abi___utils___numeric___f_scale_places_objObject *self, visitproc visit, void *arg)
{
    Py_VISIT(self->___mypyc_env__);
    PyObject_VisitManagedDict((PyObject *)self, visit, arg);
    return 0;
}

static int
numeric___f_scale_places_obj_clear(faster_eth_abi___utils___numeric___f_scale_places_objObject *self)
{
    Py_CLEAR(self->___mypyc_env__);
    PyObject_ClearManagedDict((PyObject *)self);
    return 0;
}

static void
numeric___f_scale_places_obj_dealloc(faster_eth_abi___utils___numeric___f_scale_places_objObject *self)
{
    PyObject_GC_UnTrack(self);
    if (numeric___f_scale_places_obj_free_instance == NULL) {
        numeric___f_scale_places_obj_free_instance = self;
        Py_CLEAR(self->___mypyc_env__);
        return;
    }
    CPy_TRASHCAN_BEGIN(self, numeric___f_scale_places_obj_dealloc)
    numeric___f_scale_places_obj_clear(self);
    Py_TYPE(self)->tp_free((PyObject *)self);
    CPy_TRASHCAN_END(self)
}

static CPyVTableItem numeric___f_scale_places_obj_vtable[2];
static bool
CPyDef_numeric___f_scale_places_obj_trait_vtable_setup(void)
{
    CPyVTableItem numeric___f_scale_places_obj_vtable_scratch[] = {
        (CPyVTableItem)CPyDef_numeric___f_scale_places_obj_____call__,
        (CPyVTableItem)CPyDef_numeric___f_scale_places_obj_____get__,
    };
    memcpy(numeric___f_scale_places_obj_vtable, numeric___f_scale_places_obj_vtable_scratch, sizeof(numeric___f_scale_places_obj_vtable));
    return 1;
}

static PyObject *
numeric___f_scale_places_obj_get___3_mypyc_env__(faster_eth_abi___utils___numeric___f_scale_places_objObject *self, void *closure);
static int
numeric___f_scale_places_obj_set___3_mypyc_env__(faster_eth_abi___utils___numeric___f_scale_places_objObject *self, PyObject *value, void *closure);

static PyGetSetDef numeric___f_scale_places_obj_getseters[] = {
    {"__mypyc_env__",
     (getter)numeric___f_scale_places_obj_get___3_mypyc_env__, (setter)numeric___f_scale_places_obj_set___3_mypyc_env__,
     NULL, NULL},
    {"__dict__", PyObject_GenericGetDict, PyObject_GenericSetDict},
    {NULL}  /* Sentinel */
};

static PyMethodDef numeric___f_scale_places_obj_methods[] = {
    {"__call__",
     (PyCFunction)CPyPy_numeric___f_scale_places_obj_____call__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__call__($x)\n--\n\n")},
    {"__get__",
     (PyCFunction)CPyPy_numeric___f_scale_places_obj_____get__,
     METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("__get__($instance, owner)\n--\n\n")},
    {"__setstate__", (PyCFunction)CPyPickle_SetState, METH_O, NULL},
    {"__getstate__", (PyCFunction)CPyPickle_GetState, METH_NOARGS, NULL},
    {NULL}  /* Sentinel */
};

static PyTypeObject CPyType_numeric___f_scale_places_obj_template_ = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "f_scale_places_obj",
    .tp_new = numeric___f_scale_places_obj_new,
    .tp_dealloc = (destructor)numeric___f_scale_places_obj_dealloc,
    .tp_traverse = (traverseproc)numeric___f_scale_places_obj_traverse,
    .tp_clear = (inquiry)numeric___f_scale_places_obj_clear,
    .tp_getset = numeric___f_scale_places_obj_getseters,
    .tp_methods = numeric___f_scale_places_obj_methods,
    .tp_call = PyVectorcall_Call,
    .tp_descr_get = CPyDunder___get__numeric___f_scale_places_obj,
    .tp_basicsize = sizeof(faster_eth_abi___utils___numeric___f_scale_places_objObject),
    .tp_vectorcall_offset = offsetof(faster_eth_abi___utils___numeric___f_scale_places_objObject, vectorcall),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HEAPTYPE | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | _Py_TPFLAGS_HAVE_VECTORCALL | Py_TPFLAGS_MANAGED_DICT,
    .tp_doc = PyDoc_STR("f_scale_places_obj()\n--\n\n"),
};
static PyTypeObject *CPyType_numeric___f_scale_places_obj_template = &CPyType_numeric___f_scale_places_obj_template_;

PyObject *CPyDef_numeric_____mypyc__f_scale_places_obj_setup(PyObject *cpy_r_type)
{
    PyTypeObject *type = (PyTypeObject*)cpy_r_type;
    faster_eth_abi___utils___numeric___f_scale_places_objObject *self;
    if (numeric___f_scale_places_obj_free_instance != NULL) {
        self = numeric___f_scale_places_obj_free_instance;
        numeric___f_scale_places_obj_free_instance = NULL;
        Py_SET_REFCNT(self, 1);
        PyObject_GC_Track(self);
        return (PyObject *)self;
    }
    self = (faster_eth_abi___utils___numeric___f_scale_places_objObject *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->vtable = numeric___f_scale_places_obj_vtable;
    self->vectorcall = CPyPy_numeric___f_scale_places_obj_____call__;
    return (PyObject *)self;
}

PyObject *CPyDef_numeric___f_scale_places_obj(void)
{
    PyObject *self = CPyDef_numeric_____mypyc__f_scale_places_obj_setup((PyObject *)CPyType_numeric___f_scale_places_obj);
    if (self == NULL)
        return NULL;
    return self;
}

static PyObject *
numeric___f_scale_places_obj_get___3_mypyc_env__(faster_eth_abi___utils___numeric___f_scale_places_objObject *self, void *closure)
{
    if (unlikely(self->___mypyc_env__ == NULL)) {
        PyErr_SetString(PyExc_AttributeError,
            "attribute '__mypyc_env__' of 'f_scale_places_obj' undefined");
        return NULL;
    }
    CPy_INCREF_NO_IMM(self->___mypyc_env__);
    PyObject *retval = self->___mypyc_env__;
    return retval;
}

static int
numeric___f_scale_places_obj_set___3_mypyc_env__(faster_eth_abi___utils___numeric___f_scale_places_objObject *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_AttributeError,
            "'f_scale_places_obj' object attribute '__mypyc_env__' cannot be deleted");
        return -1;
    }
    if (self->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(self->___mypyc_env__);
    }
    PyObject *tmp;
    if (likely(Py_TYPE(value) == CPyType_numeric___scale_places_env))
        tmp = value;
    else {
        CPy_TypeError("faster_eth_abi.utils.numeric.scale_places_env", value); 
        tmp = NULL;
    }
    if (!tmp)
        return -1;
    CPy_INCREF_NO_IMM(tmp);
    self->___mypyc_env__ = tmp;
    return 0;
}
static PyMethodDef numericmodule_methods[] = {
    {"ceil32", (PyCFunction)CPyPy_numeric___ceil32, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("ceil32(x)\n--\n\n") /* docstring */},
    {"compute_unsigned_integer_bounds", (PyCFunction)CPyPy_numeric___compute_unsigned_integer_bounds, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("compute_unsigned_integer_bounds(num_bits)\n--\n\n") /* docstring */},
    {"compute_signed_integer_bounds", (PyCFunction)CPyPy_numeric___compute_signed_integer_bounds, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("compute_signed_integer_bounds(num_bits)\n--\n\n") /* docstring */},
    {"compute_unsigned_fixed_bounds", (PyCFunction)CPyPy_numeric___compute_unsigned_fixed_bounds, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("compute_unsigned_fixed_bounds(num_bits, frac_places)\n--\n\n") /* docstring */},
    {"compute_signed_fixed_bounds", (PyCFunction)CPyPy_numeric___compute_signed_fixed_bounds, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("compute_signed_fixed_bounds(num_bits, frac_places)\n--\n\n") /* docstring */},
    {"scale_places", (PyCFunction)CPyPy_numeric___scale_places, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("scale_places(places)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___utils___numeric(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___utils___numeric__internal, "__name__");
    CPyStatic_numeric___globals = PyModule_GetDict(CPyModule_faster_eth_abi___utils___numeric__internal);
    if (unlikely(CPyStatic_numeric___globals == NULL))
        goto fail;
    CPyType_numeric___scale_places_env = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_numeric___scale_places_env_template, NULL, modname);
    if (unlikely(!CPyType_numeric___scale_places_env))
        goto fail;
    CPyType_numeric___f_scale_places_obj = (PyTypeObject *)CPyType_FromTemplate((PyObject *)CPyType_numeric___f_scale_places_obj_template, NULL, modname);
    if (unlikely(!CPyType_numeric___f_scale_places_obj))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_numeric_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___utils___numeric__internal);
    Py_CLEAR(modname);
    CPy_XDECREF(CPyStatic_numeric___abi_decimal_context);
    CPyStatic_numeric___abi_decimal_context = NULL;
    CPy_XDECREF(CPyStatic_numeric___decimal_localcontext);
    CPyStatic_numeric___decimal_localcontext = NULL;
    CPy_XDECREF(CPyStatic_numeric___ZERO);
    CPyStatic_numeric___ZERO = NULL;
    CPy_XDECREF(CPyStatic_numeric___TEN);
    CPyStatic_numeric___TEN = NULL;
    CPy_XDECREF(CPyStatic_numeric___Decimal);
    CPyStatic_numeric___Decimal = NULL;
    CPy_XDECREF(CPyStatic_numeric____unsigned_integer_bounds_cache);
    CPyStatic_numeric____unsigned_integer_bounds_cache = NULL;
    CPy_XDECREF(CPyStatic_numeric____signed_integer_bounds_cache);
    CPyStatic_numeric____signed_integer_bounds_cache = NULL;
    CPy_XDECREF(CPyStatic_numeric____unsigned_fixed_bounds_cache);
    CPyStatic_numeric____unsigned_fixed_bounds_cache = NULL;
    CPy_XDECREF(CPyStatic_numeric____signed_fixed_bounds_cache);
    CPyStatic_numeric____signed_fixed_bounds_cache = NULL;
    Py_CLEAR(CPyType_numeric___scale_places_env);
    Py_CLEAR(CPyType_numeric___f_scale_places_obj);
    return -1;
}
static struct PyModuleDef numericmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.utils.numeric",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    numericmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___utils___numeric(void)
{
    if (CPyModule_faster_eth_abi___utils___numeric__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___utils___numeric__internal);
        return CPyModule_faster_eth_abi___utils___numeric__internal;
    }
    CPyModule_faster_eth_abi___utils___numeric__internal = PyModule_Create(&numericmodule);
    if (unlikely(CPyModule_faster_eth_abi___utils___numeric__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___utils___numeric(CPyModule_faster_eth_abi___utils___numeric__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___utils___numeric__internal;
    fail:
    return NULL;
}

CPyTagged CPyDef_numeric___ceil32(CPyTagged cpy_r_x) {
    CPyTagged cpy_r_r0;
    char cpy_r_r1;
    CPyTagged cpy_r_r2;
    CPyTagged cpy_r_r3;
    CPyTagged cpy_r_r4;
    CPyTagged cpy_r_r5;
    cpy_r_r0 = CPyTagged_Remainder(cpy_r_x, 64);
    if (unlikely(cpy_r_r0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "ceil32", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL5;
    }
    cpy_r_r1 = cpy_r_r0 == 0;
    if (cpy_r_r1) {
        goto CPyL6;
    } else
        goto CPyL3;
CPyL2: ;
    CPyTagged_INCREF(cpy_r_x);
    cpy_r_r2 = cpy_r_x;
    goto CPyL4;
CPyL3: ;
    cpy_r_r3 = CPyTagged_Add(cpy_r_x, 64);
    cpy_r_r4 = CPyTagged_Subtract(cpy_r_r3, cpy_r_r0);
    CPyTagged_DECREF(cpy_r_r3);
    CPyTagged_DECREF(cpy_r_r0);
    cpy_r_r2 = cpy_r_r4;
CPyL4: ;
    return cpy_r_r2;
CPyL5: ;
    cpy_r_r5 = CPY_INT_TAG;
    return cpy_r_r5;
CPyL6: ;
    CPyTagged_DECREF(cpy_r_r0);
    goto CPyL2;
}

PyObject *CPyPy_numeric___ceil32(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"x", 0};
    static CPyArg_Parser parser = {"O:ceil32", kwlist, 0};
    PyObject *obj_x;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_x)) {
        return NULL;
    }
    CPyTagged arg_x;
    if (likely(PyLong_Check(obj_x)))
        arg_x = CPyTagged_BorrowFromObject(obj_x);
    else {
        CPy_TypeError("int", obj_x); goto fail;
    }
    CPyTagged retval = CPyDef_numeric___ceil32(arg_x);
    if (retval == CPY_INT_TAG) {
        return NULL;
    }
    PyObject *retbox = CPyTagged_StealAsObject(retval);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "ceil32", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

tuple_T2II CPyDef_numeric___compute_unsigned_integer_bounds(CPyTagged cpy_r_num_bits) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_bounds;
    PyObject *cpy_r_r5;
    char cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    tuple_T2IO cpy_r_r12;
    PyObject *cpy_r_r13;
    tuple_T2II cpy_r_r14;
    PyObject *cpy_r_r15;
    char cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    int32_t cpy_r_r19;
    char cpy_r_r20;
    tuple_T2II cpy_r_r21;
    tuple_T2II cpy_r_r22;
    cpy_r_r0 = CPyStatic_numeric____unsigned_integer_bounds_cache;
    if (likely(cpy_r_r0 != NULL)) goto CPyL3;
    PyErr_SetString(PyExc_NameError, "value for final name \"_unsigned_integer_bounds_cache\" was not set");
    cpy_r_r1 = 0;
    if (unlikely(!cpy_r_r1)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    CPy_Unreachable();
CPyL3: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    cpy_r_r2 = CPyTagged_StealAsObject(cpy_r_num_bits);
    cpy_r_r3 = CPyDict_GetWithNone(cpy_r_r0, cpy_r_r2);
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    if (unlikely(!(PyTuple_Check(cpy_r_r3) && PyTuple_GET_SIZE(cpy_r_r3) == 2))) {
        cpy_r_r4 = NULL;
        goto __LL55;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r3, 0))))
        cpy_r_r4 = PyTuple_GET_ITEM(cpy_r_r3, 0);
    else {
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto __LL55;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r3, 1))))
        cpy_r_r4 = PyTuple_GET_ITEM(cpy_r_r3, 1);
    else {
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto __LL55;
    cpy_r_r4 = cpy_r_r3;
__LL55: ;
    if (cpy_r_r4 != NULL) goto __LL54;
    if (cpy_r_r3 == Py_None)
        cpy_r_r4 = cpy_r_r3;
    else {
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 != NULL) goto __LL54;
    CPy_TypeErrorTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", 29, CPyStatic_numeric___globals, "tuple[int, int] or None", cpy_r_r3);
    goto CPyL15;
__LL54: ;
    cpy_r_bounds = cpy_r_r4;
    cpy_r_r5 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r6 = cpy_r_bounds == cpy_r_r5;
    if (cpy_r_r6) {
        goto CPyL16;
    } else
        goto CPyL13;
CPyL6: ;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    CPyTagged_INCREF(cpy_r_num_bits);
    cpy_r_r8 = CPyTagged_StealAsObject(cpy_r_num_bits);
    cpy_r_r9 = CPyNumber_Power(cpy_r_r7, cpy_r_r8);
    CPy_DECREF(cpy_r_r8);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r11 = PyNumber_Subtract(cpy_r_r9, cpy_r_r10);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    cpy_r_r12.f0 = 0;
    cpy_r_r12.f1 = cpy_r_r11;
    cpy_r_r13 = PyTuple_New(2);
    if (unlikely(cpy_r_r13 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp56 = CPyTagged_StealAsObject(cpy_r_r12.f0);
    PyTuple_SET_ITEM(cpy_r_r13, 0, __tmp56);
    PyObject *__tmp57 = cpy_r_r12.f1;
    PyTuple_SET_ITEM(cpy_r_r13, 1, __tmp57);
    cpy_r_bounds = cpy_r_r13;
    PyObject *__tmp58;
    if (unlikely(!(PyTuple_Check(cpy_r_bounds) && PyTuple_GET_SIZE(cpy_r_bounds) == 2))) {
        __tmp58 = NULL;
        goto __LL59;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 0))))
        __tmp58 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
    else {
        __tmp58 = NULL;
    }
    if (__tmp58 == NULL) goto __LL59;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 1))))
        __tmp58 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
    else {
        __tmp58 = NULL;
    }
    if (__tmp58 == NULL) goto __LL59;
    __tmp58 = cpy_r_bounds;
__LL59: ;
    if (unlikely(__tmp58 == NULL)) {
        CPy_TypeError("tuple[int, int]", cpy_r_bounds); cpy_r_r14 = (tuple_T2II) { CPY_INT_TAG, CPY_INT_TAG };
    } else {
        PyObject *__tmp60 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
        CPyTagged __tmp61;
        if (likely(PyLong_Check(__tmp60)))
            __tmp61 = CPyTagged_FromObject(__tmp60);
        else {
            CPy_TypeError("int", __tmp60); __tmp61 = CPY_INT_TAG;
        }
        cpy_r_r14.f0 = __tmp61;
        PyObject *__tmp62 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
        CPyTagged __tmp63;
        if (likely(PyLong_Check(__tmp62)))
            __tmp63 = CPyTagged_FromObject(__tmp62);
        else {
            CPy_TypeError("int", __tmp62); __tmp63 = CPY_INT_TAG;
        }
        cpy_r_r14.f1 = __tmp63;
    }
    if (unlikely(cpy_r_r14.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL17;
    }
    cpy_r_r15 = CPyStatic_numeric____unsigned_integer_bounds_cache;
    if (unlikely(cpy_r_r15 == NULL)) {
        goto CPyL18;
    } else
        goto CPyL12;
CPyL10: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"_unsigned_integer_bounds_cache\" was not set");
    cpy_r_r16 = 0;
    if (unlikely(!cpy_r_r16)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    CPy_Unreachable();
CPyL12: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    cpy_r_r17 = CPyTagged_StealAsObject(cpy_r_num_bits);
    cpy_r_r18 = PyTuple_New(2);
    if (unlikely(cpy_r_r18 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp64 = CPyTagged_StealAsObject(cpy_r_r14.f0);
    PyTuple_SET_ITEM(cpy_r_r18, 0, __tmp64);
    PyObject *__tmp65 = CPyTagged_StealAsObject(cpy_r_r14.f1);
    PyTuple_SET_ITEM(cpy_r_r18, 1, __tmp65);
    cpy_r_r19 = CPyDict_SetItem(cpy_r_r15, cpy_r_r17, cpy_r_r18);
    CPy_DECREF(cpy_r_r17);
    CPy_DECREF(cpy_r_r18);
    cpy_r_r20 = cpy_r_r19 >= 0;
    if (unlikely(!cpy_r_r20)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL17;
    }
CPyL13: ;
    PyObject *__tmp66;
    if (unlikely(!(PyTuple_Check(cpy_r_bounds) && PyTuple_GET_SIZE(cpy_r_bounds) == 2))) {
        __tmp66 = NULL;
        goto __LL67;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 0))))
        __tmp66 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
    else {
        __tmp66 = NULL;
    }
    if (__tmp66 == NULL) goto __LL67;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 1))))
        __tmp66 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
    else {
        __tmp66 = NULL;
    }
    if (__tmp66 == NULL) goto __LL67;
    __tmp66 = cpy_r_bounds;
__LL67: ;
    if (unlikely(__tmp66 == NULL)) {
        CPy_TypeError("tuple[int, int]", cpy_r_bounds); cpy_r_r21 = (tuple_T2II) { CPY_INT_TAG, CPY_INT_TAG };
    } else {
        PyObject *__tmp68 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
        CPyTagged __tmp69;
        if (likely(PyLong_Check(__tmp68)))
            __tmp69 = CPyTagged_FromObject(__tmp68);
        else {
            CPy_TypeError("int", __tmp68); __tmp69 = CPY_INT_TAG;
        }
        cpy_r_r21.f0 = __tmp69;
        PyObject *__tmp70 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
        CPyTagged __tmp71;
        if (likely(PyLong_Check(__tmp70)))
            __tmp71 = CPyTagged_FromObject(__tmp70);
        else {
            CPy_TypeError("int", __tmp70); __tmp71 = CPY_INT_TAG;
        }
        cpy_r_r21.f1 = __tmp71;
    }
    CPy_DECREF(cpy_r_bounds);
    if (unlikely(cpy_r_r21.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    return cpy_r_r21;
CPyL15: ;
    tuple_T2II __tmp72 = { CPY_INT_TAG, CPY_INT_TAG };
    cpy_r_r22 = __tmp72;
    return cpy_r_r22;
CPyL16: ;
    CPy_DECREF(cpy_r_bounds);
    goto CPyL6;
CPyL17: ;
    CPy_DecRef(cpy_r_bounds);
    goto CPyL15;
CPyL18: ;
    CPy_DecRef(cpy_r_bounds);
    CPyTagged_DecRef(cpy_r_r14.f0);
    CPyTagged_DecRef(cpy_r_r14.f1);
    goto CPyL10;
}

PyObject *CPyPy_numeric___compute_unsigned_integer_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"num_bits", 0};
    static CPyArg_Parser parser = {"O:compute_unsigned_integer_bounds", kwlist, 0};
    PyObject *obj_num_bits;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_num_bits)) {
        return NULL;
    }
    CPyTagged arg_num_bits;
    if (likely(PyLong_Check(obj_num_bits)))
        arg_num_bits = CPyTagged_BorrowFromObject(obj_num_bits);
    else {
        CPy_TypeError("int", obj_num_bits); goto fail;
    }
    tuple_T2II retval = CPyDef_numeric___compute_unsigned_integer_bounds(arg_num_bits);
    if (retval.f0 == CPY_INT_TAG) {
        return NULL;
    }
    PyObject *retbox = PyTuple_New(2);
    if (unlikely(retbox == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp73 = CPyTagged_StealAsObject(retval.f0);
    PyTuple_SET_ITEM(retbox, 0, __tmp73);
    PyObject *__tmp74 = CPyTagged_StealAsObject(retval.f1);
    PyTuple_SET_ITEM(retbox, 1, __tmp74);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

tuple_T2II CPyDef_numeric___compute_signed_integer_bounds(CPyTagged cpy_r_num_bits) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_bounds;
    PyObject *cpy_r_r5;
    char cpy_r_r6;
    CPyTagged cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    tuple_T2OO cpy_r_r14;
    PyObject *cpy_r_r15;
    tuple_T2II cpy_r_r16;
    PyObject *cpy_r_r17;
    char cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    int32_t cpy_r_r21;
    char cpy_r_r22;
    tuple_T2II cpy_r_r23;
    tuple_T2II cpy_r_r24;
    cpy_r_r0 = CPyStatic_numeric____signed_integer_bounds_cache;
    if (likely(cpy_r_r0 != NULL)) goto CPyL3;
    PyErr_SetString(PyExc_NameError, "value for final name \"_signed_integer_bounds_cache\" was not set");
    cpy_r_r1 = 0;
    if (unlikely(!cpy_r_r1)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL16;
    }
    CPy_Unreachable();
CPyL3: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    cpy_r_r2 = CPyTagged_StealAsObject(cpy_r_num_bits);
    cpy_r_r3 = CPyDict_GetWithNone(cpy_r_r0, cpy_r_r2);
    CPy_DECREF(cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL16;
    }
    if (unlikely(!(PyTuple_Check(cpy_r_r3) && PyTuple_GET_SIZE(cpy_r_r3) == 2))) {
        cpy_r_r4 = NULL;
        goto __LL76;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r3, 0))))
        cpy_r_r4 = PyTuple_GET_ITEM(cpy_r_r3, 0);
    else {
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto __LL76;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_r3, 1))))
        cpy_r_r4 = PyTuple_GET_ITEM(cpy_r_r3, 1);
    else {
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 == NULL) goto __LL76;
    cpy_r_r4 = cpy_r_r3;
__LL76: ;
    if (cpy_r_r4 != NULL) goto __LL75;
    if (cpy_r_r3 == Py_None)
        cpy_r_r4 = cpy_r_r3;
    else {
        cpy_r_r4 = NULL;
    }
    if (cpy_r_r4 != NULL) goto __LL75;
    CPy_TypeErrorTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", 40, CPyStatic_numeric___globals, "tuple[int, int] or None", cpy_r_r3);
    goto CPyL16;
__LL75: ;
    cpy_r_bounds = cpy_r_r4;
    cpy_r_r5 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r6 = cpy_r_bounds == cpy_r_r5;
    if (cpy_r_r6) {
        goto CPyL17;
    } else
        goto CPyL14;
CPyL6: ;
    cpy_r_r7 = CPyTagged_Subtract(cpy_r_num_bits, 2);
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    cpy_r_r9 = CPyTagged_StealAsObject(cpy_r_r7);
    cpy_r_r10 = CPyNumber_Power(cpy_r_r8, cpy_r_r9);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL16;
    }
    cpy_r_r11 = PyNumber_Negative(cpy_r_r10);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL18;
    }
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r13 = PyNumber_Subtract(cpy_r_r10, cpy_r_r12);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL19;
    }
    cpy_r_r14.f0 = cpy_r_r11;
    cpy_r_r14.f1 = cpy_r_r13;
    cpy_r_r15 = PyTuple_New(2);
    if (unlikely(cpy_r_r15 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp77 = cpy_r_r14.f0;
    PyTuple_SET_ITEM(cpy_r_r15, 0, __tmp77);
    PyObject *__tmp78 = cpy_r_r14.f1;
    PyTuple_SET_ITEM(cpy_r_r15, 1, __tmp78);
    cpy_r_bounds = cpy_r_r15;
    PyObject *__tmp79;
    if (unlikely(!(PyTuple_Check(cpy_r_bounds) && PyTuple_GET_SIZE(cpy_r_bounds) == 2))) {
        __tmp79 = NULL;
        goto __LL80;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 0))))
        __tmp79 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
    else {
        __tmp79 = NULL;
    }
    if (__tmp79 == NULL) goto __LL80;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 1))))
        __tmp79 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
    else {
        __tmp79 = NULL;
    }
    if (__tmp79 == NULL) goto __LL80;
    __tmp79 = cpy_r_bounds;
__LL80: ;
    if (unlikely(__tmp79 == NULL)) {
        CPy_TypeError("tuple[int, int]", cpy_r_bounds); cpy_r_r16 = (tuple_T2II) { CPY_INT_TAG, CPY_INT_TAG };
    } else {
        PyObject *__tmp81 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
        CPyTagged __tmp82;
        if (likely(PyLong_Check(__tmp81)))
            __tmp82 = CPyTagged_FromObject(__tmp81);
        else {
            CPy_TypeError("int", __tmp81); __tmp82 = CPY_INT_TAG;
        }
        cpy_r_r16.f0 = __tmp82;
        PyObject *__tmp83 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
        CPyTagged __tmp84;
        if (likely(PyLong_Check(__tmp83)))
            __tmp84 = CPyTagged_FromObject(__tmp83);
        else {
            CPy_TypeError("int", __tmp83); __tmp84 = CPY_INT_TAG;
        }
        cpy_r_r16.f1 = __tmp84;
    }
    if (unlikely(cpy_r_r16.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL20;
    }
    cpy_r_r17 = CPyStatic_numeric____signed_integer_bounds_cache;
    if (unlikely(cpy_r_r17 == NULL)) {
        goto CPyL21;
    } else
        goto CPyL13;
CPyL11: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"_signed_integer_bounds_cache\" was not set");
    cpy_r_r18 = 0;
    if (unlikely(!cpy_r_r18)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL16;
    }
    CPy_Unreachable();
CPyL13: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    cpy_r_r19 = CPyTagged_StealAsObject(cpy_r_num_bits);
    cpy_r_r20 = PyTuple_New(2);
    if (unlikely(cpy_r_r20 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp85 = CPyTagged_StealAsObject(cpy_r_r16.f0);
    PyTuple_SET_ITEM(cpy_r_r20, 0, __tmp85);
    PyObject *__tmp86 = CPyTagged_StealAsObject(cpy_r_r16.f1);
    PyTuple_SET_ITEM(cpy_r_r20, 1, __tmp86);
    cpy_r_r21 = CPyDict_SetItem(cpy_r_r17, cpy_r_r19, cpy_r_r20);
    CPy_DECREF(cpy_r_r19);
    CPy_DECREF(cpy_r_r20);
    cpy_r_r22 = cpy_r_r21 >= 0;
    if (unlikely(!cpy_r_r22)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL20;
    }
CPyL14: ;
    PyObject *__tmp87;
    if (unlikely(!(PyTuple_Check(cpy_r_bounds) && PyTuple_GET_SIZE(cpy_r_bounds) == 2))) {
        __tmp87 = NULL;
        goto __LL88;
    }
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 0))))
        __tmp87 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
    else {
        __tmp87 = NULL;
    }
    if (__tmp87 == NULL) goto __LL88;
    if (likely(PyLong_Check(PyTuple_GET_ITEM(cpy_r_bounds, 1))))
        __tmp87 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
    else {
        __tmp87 = NULL;
    }
    if (__tmp87 == NULL) goto __LL88;
    __tmp87 = cpy_r_bounds;
__LL88: ;
    if (unlikely(__tmp87 == NULL)) {
        CPy_TypeError("tuple[int, int]", cpy_r_bounds); cpy_r_r23 = (tuple_T2II) { CPY_INT_TAG, CPY_INT_TAG };
    } else {
        PyObject *__tmp89 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
        CPyTagged __tmp90;
        if (likely(PyLong_Check(__tmp89)))
            __tmp90 = CPyTagged_FromObject(__tmp89);
        else {
            CPy_TypeError("int", __tmp89); __tmp90 = CPY_INT_TAG;
        }
        cpy_r_r23.f0 = __tmp90;
        PyObject *__tmp91 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
        CPyTagged __tmp92;
        if (likely(PyLong_Check(__tmp91)))
            __tmp92 = CPyTagged_FromObject(__tmp91);
        else {
            CPy_TypeError("int", __tmp91); __tmp92 = CPY_INT_TAG;
        }
        cpy_r_r23.f1 = __tmp92;
    }
    CPy_DECREF(cpy_r_bounds);
    if (unlikely(cpy_r_r23.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL16;
    }
    return cpy_r_r23;
CPyL16: ;
    tuple_T2II __tmp93 = { CPY_INT_TAG, CPY_INT_TAG };
    cpy_r_r24 = __tmp93;
    return cpy_r_r24;
CPyL17: ;
    CPy_DECREF(cpy_r_bounds);
    goto CPyL6;
CPyL18: ;
    CPy_DecRef(cpy_r_r10);
    goto CPyL16;
CPyL19: ;
    CPy_DecRef(cpy_r_r11);
    goto CPyL16;
CPyL20: ;
    CPy_DecRef(cpy_r_bounds);
    goto CPyL16;
CPyL21: ;
    CPy_DecRef(cpy_r_bounds);
    CPyTagged_DecRef(cpy_r_r16.f0);
    CPyTagged_DecRef(cpy_r_r16.f1);
    goto CPyL11;
}

PyObject *CPyPy_numeric___compute_signed_integer_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"num_bits", 0};
    static CPyArg_Parser parser = {"O:compute_signed_integer_bounds", kwlist, 0};
    PyObject *obj_num_bits;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_num_bits)) {
        return NULL;
    }
    CPyTagged arg_num_bits;
    if (likely(PyLong_Check(obj_num_bits)))
        arg_num_bits = CPyTagged_BorrowFromObject(obj_num_bits);
    else {
        CPy_TypeError("int", obj_num_bits); goto fail;
    }
    tuple_T2II retval = CPyDef_numeric___compute_signed_integer_bounds(arg_num_bits);
    if (retval.f0 == CPY_INT_TAG) {
        return NULL;
    }
    PyObject *retbox = PyTuple_New(2);
    if (unlikely(retbox == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp94 = CPyTagged_StealAsObject(retval.f0);
    PyTuple_SET_ITEM(retbox, 0, __tmp94);
    PyObject *__tmp95 = CPyTagged_StealAsObject(retval.f1);
    PyTuple_SET_ITEM(retbox, 1, __tmp95);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_integer_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

tuple_T2OO CPyDef_numeric___compute_unsigned_fixed_bounds(CPyTagged cpy_r_num_bits, CPyTagged cpy_r_frac_places) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    tuple_T2II cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_upper;
    PyObject *cpy_r_r5;
    char cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    char cpy_r_r13;
    PyObject *cpy_r_r14;
    char cpy_r_r15;
    PyObject **cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject **cpy_r_r25;
    PyObject *cpy_r_r26;
    char cpy_r_r27;
    PyObject *cpy_r_r28;
    char cpy_r_r29;
    PyObject **cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    char cpy_r_r34;
    CPyTagged cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    tuple_T3OOO cpy_r_r39;
    tuple_T3OOO cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject **cpy_r_r45;
    PyObject *cpy_r_r46;
    int32_t cpy_r_r47;
    char cpy_r_r48;
    char cpy_r_r49;
    char cpy_r_r50;
    tuple_T3OOO cpy_r_r51;
    tuple_T3OOO cpy_r_r52;
    tuple_T3OOO cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject **cpy_r_r56;
    PyObject *cpy_r_r57;
    char cpy_r_r58;
    PyObject *cpy_r_r59;
    char cpy_r_r60;
    tuple_T2II cpy_r_r61;
    PyObject *cpy_r_r62;
    int32_t cpy_r_r63;
    char cpy_r_r64;
    PyObject *cpy_r_r65;
    char cpy_r_r66;
    tuple_T2OO cpy_r_r67;
    tuple_T2OO cpy_r_r68;
    cpy_r_r0 = CPyStatic_numeric____unsigned_fixed_bounds_cache;
    if (likely(cpy_r_r0 != NULL)) goto CPyL3;
    PyErr_SetString(PyExc_NameError, "value for final name \"_unsigned_fixed_bounds_cache\" was not set");
    cpy_r_r1 = 0;
    if (unlikely(!cpy_r_r1)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL56;
    }
    CPy_Unreachable();
CPyL3: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    CPyTagged_INCREF(cpy_r_frac_places);
    cpy_r_r2.f0 = cpy_r_num_bits;
    cpy_r_r2.f1 = cpy_r_frac_places;
    cpy_r_r3 = PyTuple_New(2);
    if (unlikely(cpy_r_r3 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp96 = CPyTagged_StealAsObject(cpy_r_r2.f0);
    PyTuple_SET_ITEM(cpy_r_r3, 0, __tmp96);
    PyObject *__tmp97 = CPyTagged_StealAsObject(cpy_r_r2.f1);
    PyTuple_SET_ITEM(cpy_r_r3, 1, __tmp97);
    cpy_r_r4 = CPyDict_GetWithNone(cpy_r_r0, cpy_r_r3);
    CPy_DECREF(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL56;
    }
    cpy_r_upper = cpy_r_r4;
    cpy_r_r5 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r6 = cpy_r_upper == cpy_r_r5;
    if (!cpy_r_r6) goto CPyL52;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 2 */
    CPyTagged_INCREF(cpy_r_num_bits);
    cpy_r_r8 = CPyTagged_StealAsObject(cpy_r_num_bits);
    cpy_r_r9 = CPyNumber_Power(cpy_r_r7, cpy_r_r8);
    CPy_DECREF(cpy_r_r8);
    if (unlikely(cpy_r_r9 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL57;
    }
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 1 */
    cpy_r_r11 = PyNumber_Subtract(cpy_r_r9, cpy_r_r10);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL57;
    }
    cpy_r_r12 = CPyStatic_numeric___abi_decimal_context;
    if (unlikely(cpy_r_r12 == NULL)) {
        goto CPyL58;
    } else
        goto CPyL10;
CPyL8: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"abi_decimal_context\" was not set");
    cpy_r_r13 = 0;
    if (unlikely(!cpy_r_r13)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL56;
    }
    CPy_Unreachable();
CPyL10: ;
    cpy_r_r14 = CPyStatic_numeric___decimal_localcontext;
    if (unlikely(cpy_r_r14 == NULL)) {
        goto CPyL59;
    } else
        goto CPyL13;
CPyL11: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"decimal_localcontext\" was not set");
    cpy_r_r15 = 0;
    if (unlikely(!cpy_r_r15)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL56;
    }
    CPy_Unreachable();
CPyL13: ;
    PyObject *cpy_r_r16[1] = {cpy_r_r12};
    cpy_r_r17 = (PyObject **)&cpy_r_r16;
    cpy_r_r18 = PyObject_Vectorcall(cpy_r_r14, cpy_r_r17, 1, 0);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL60;
    }
    cpy_r_r19 = CPy_TYPE(cpy_r_r18);
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__exit__' */
    cpy_r_r21 = CPyObject_GetAttr(cpy_r_r19, cpy_r_r20);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL61;
    }
    cpy_r_r22 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__enter__' */
    cpy_r_r23 = CPyObject_GetAttr(cpy_r_r19, cpy_r_r22);
    CPy_DECREF(cpy_r_r19);
    if (unlikely(cpy_r_r23 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    }
    PyObject *cpy_r_r24[1] = {cpy_r_r18};
    cpy_r_r25 = (PyObject **)&cpy_r_r24;
    cpy_r_r26 = PyObject_Vectorcall(cpy_r_r23, cpy_r_r25, 1, 0);
    CPy_DECREF(cpy_r_r23);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    } else
        goto CPyL63;
CPyL17: ;
    cpy_r_r27 = 1;
    cpy_r_r28 = CPyStatic_numeric___Decimal;
    if (unlikely(cpy_r_r28 == NULL)) {
        goto CPyL64;
    } else
        goto CPyL21;
CPyL19: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"Decimal\" was not set");
    cpy_r_r29 = 0;
    if (unlikely(!cpy_r_r29)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    } else
        goto CPyL65;
CPyL20: ;
    CPy_Unreachable();
CPyL21: ;
    PyObject *cpy_r_r30[1] = {cpy_r_r11};
    cpy_r_r31 = (PyObject **)&cpy_r_r30;
    cpy_r_r32 = PyObject_Vectorcall(cpy_r_r28, cpy_r_r31, 1, 0);
    if (unlikely(cpy_r_r32 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_DECREF(cpy_r_r11);
    cpy_r_r33 = CPyStatic_numeric___TEN;
    if (unlikely(cpy_r_r33 == NULL)) {
        goto CPyL67;
    } else
        goto CPyL25;
CPyL23: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"TEN\" was not set");
    cpy_r_r34 = 0;
    if (unlikely(!cpy_r_r34)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    } else
        goto CPyL68;
CPyL24: ;
    CPy_Unreachable();
CPyL25: ;
    cpy_r_r35 = CPyTagged_Negate(cpy_r_frac_places);
    cpy_r_r36 = CPyTagged_StealAsObject(cpy_r_r35);
    cpy_r_r37 = CPyNumber_Power(cpy_r_r33, cpy_r_r36);
    CPy_DECREF(cpy_r_r36);
    if (unlikely(cpy_r_r37 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL69;
    }
    cpy_r_r38 = PyNumber_Multiply(cpy_r_r32, cpy_r_r37);
    CPy_DECREF(cpy_r_r32);
    CPy_DECREF(cpy_r_r37);
    if (unlikely(cpy_r_r38 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    } else
        goto CPyL70;
CPyL27: ;
    cpy_r_upper = cpy_r_r38;
    goto CPyL36;
CPyL28: ;
    cpy_r_r39 = CPy_CatchError();
    cpy_r_r27 = 0;
    cpy_r_r40 = CPy_GetExcInfo();
    cpy_r_r41 = cpy_r_r40.f0;
    CPy_INCREF(cpy_r_r41);
    cpy_r_r42 = cpy_r_r40.f1;
    CPy_INCREF(cpy_r_r42);
    cpy_r_r43 = cpy_r_r40.f2;
    CPy_INCREF(cpy_r_r43);
    CPy_DecRef(cpy_r_r40.f0);
    CPy_DecRef(cpy_r_r40.f1);
    CPy_DecRef(cpy_r_r40.f2);
    PyObject *cpy_r_r44[4] = {cpy_r_r18, cpy_r_r41, cpy_r_r42, cpy_r_r43};
    cpy_r_r45 = (PyObject **)&cpy_r_r44;
    cpy_r_r46 = PyObject_Vectorcall(cpy_r_r21, cpy_r_r45, 4, 0);
    if (unlikely(cpy_r_r46 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL71;
    }
    CPy_DecRef(cpy_r_r41);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r43);
    cpy_r_r47 = PyObject_IsTrue(cpy_r_r46);
    CPy_DecRef(cpy_r_r46);
    cpy_r_r48 = cpy_r_r47 >= 0;
    if (unlikely(!cpy_r_r48)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL34;
    }
    cpy_r_r49 = cpy_r_r47;
    if (cpy_r_r49) goto CPyL33;
    CPy_Reraise();
    if (!0) {
        goto CPyL34;
    } else
        goto CPyL72;
CPyL32: ;
    CPy_Unreachable();
CPyL33: ;
    CPy_RestoreExcInfo(cpy_r_r39);
    CPy_DecRef(cpy_r_r39.f0);
    CPy_DecRef(cpy_r_r39.f1);
    CPy_DecRef(cpy_r_r39.f2);
    goto CPyL36;
CPyL34: ;
    CPy_RestoreExcInfo(cpy_r_r39);
    CPy_DecRef(cpy_r_r39.f0);
    CPy_DecRef(cpy_r_r39.f1);
    CPy_DecRef(cpy_r_r39.f2);
    cpy_r_r50 = CPy_KeepPropagating();
    if (!cpy_r_r50) {
        goto CPyL37;
    } else
        goto CPyL73;
CPyL35: ;
    CPy_Unreachable();
CPyL36: ;
    tuple_T3OOO __tmp98 = { NULL, NULL, NULL };
    cpy_r_r51 = __tmp98;
    cpy_r_r52 = cpy_r_r51;
    goto CPyL38;
CPyL37: ;
    cpy_r_r53 = CPy_CatchError();
    cpy_r_r52 = cpy_r_r53;
CPyL38: ;
    if (!cpy_r_r27) goto CPyL74;
    cpy_r_r54 = (PyObject *)&_Py_NoneStruct;
    PyObject *cpy_r_r55[4] = {cpy_r_r18, cpy_r_r54, cpy_r_r54, cpy_r_r54};
    cpy_r_r56 = (PyObject **)&cpy_r_r55;
    cpy_r_r57 = PyObject_Vectorcall(cpy_r_r21, cpy_r_r56, 4, 0);
    CPy_DECREF(cpy_r_r21);
    if (unlikely(cpy_r_r57 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL75;
    } else
        goto CPyL76;
CPyL40: ;
    CPy_DECREF(cpy_r_r18);
CPyL41: ;
    if (cpy_r_r52.f0 == NULL) {
        goto CPyL48;
    } else
        goto CPyL77;
CPyL42: ;
    CPy_Reraise();
    if (!0) {
        goto CPyL44;
    } else
        goto CPyL78;
CPyL43: ;
    CPy_Unreachable();
CPyL44: ;
    if (cpy_r_r52.f0 == NULL) goto CPyL46;
    CPy_RestoreExcInfo(cpy_r_r52);
    CPy_XDECREF(cpy_r_r52.f0);
    CPy_XDECREF(cpy_r_r52.f1);
    CPy_XDECREF(cpy_r_r52.f2);
CPyL46: ;
    cpy_r_r58 = CPy_KeepPropagating();
    if (!cpy_r_r58) goto CPyL56;
    CPy_Unreachable();
CPyL48: ;
    cpy_r_r59 = CPyStatic_numeric____unsigned_fixed_bounds_cache;
    if (unlikely(cpy_r_r59 == NULL)) {
        goto CPyL79;
    } else
        goto CPyL51;
CPyL49: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"_unsigned_fixed_bounds_cache\" was not set");
    cpy_r_r60 = 0;
    if (unlikely(!cpy_r_r60)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL56;
    }
    CPy_Unreachable();
CPyL51: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    CPyTagged_INCREF(cpy_r_frac_places);
    cpy_r_r61.f0 = cpy_r_num_bits;
    cpy_r_r61.f1 = cpy_r_frac_places;
    cpy_r_r62 = PyTuple_New(2);
    if (unlikely(cpy_r_r62 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp99 = CPyTagged_StealAsObject(cpy_r_r61.f0);
    PyTuple_SET_ITEM(cpy_r_r62, 0, __tmp99);
    PyObject *__tmp100 = CPyTagged_StealAsObject(cpy_r_r61.f1);
    PyTuple_SET_ITEM(cpy_r_r62, 1, __tmp100);
    cpy_r_r63 = CPyDict_SetItem(cpy_r_r59, cpy_r_r62, cpy_r_upper);
    CPy_DECREF(cpy_r_r62);
    cpy_r_r64 = cpy_r_r63 >= 0;
    if (unlikely(!cpy_r_r64)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL57;
    }
CPyL52: ;
    cpy_r_r65 = CPyStatic_numeric___ZERO;
    if (unlikely(cpy_r_r65 == NULL)) {
        goto CPyL80;
    } else
        goto CPyL55;
CPyL53: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"ZERO\" was not set");
    cpy_r_r66 = 0;
    if (unlikely(!cpy_r_r66)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL56;
    }
    CPy_Unreachable();
CPyL55: ;
    CPy_INCREF(cpy_r_r65);
    cpy_r_r67.f0 = cpy_r_r65;
    cpy_r_r67.f1 = cpy_r_upper;
    return cpy_r_r67;
CPyL56: ;
    tuple_T2OO __tmp101 = { NULL, NULL };
    cpy_r_r68 = __tmp101;
    return cpy_r_r68;
CPyL57: ;
    CPy_DecRef(cpy_r_upper);
    goto CPyL56;
CPyL58: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r11);
    goto CPyL8;
CPyL59: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r11);
    goto CPyL11;
CPyL60: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r11);
    goto CPyL56;
CPyL61: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_r18);
    CPy_DecRef(cpy_r_r19);
    goto CPyL56;
CPyL62: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_r18);
    CPy_DecRef(cpy_r_r21);
    goto CPyL56;
CPyL63: ;
    CPy_DECREF(cpy_r_r26);
    goto CPyL17;
CPyL64: ;
    CPy_DecRef(cpy_r_r11);
    goto CPyL19;
CPyL65: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r18);
    CPy_DecRef(cpy_r_r21);
    goto CPyL20;
CPyL66: ;
    CPy_DecRef(cpy_r_r11);
    goto CPyL28;
CPyL67: ;
    CPy_DecRef(cpy_r_r32);
    goto CPyL23;
CPyL68: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r18);
    CPy_DecRef(cpy_r_r21);
    goto CPyL24;
CPyL69: ;
    CPy_DecRef(cpy_r_r32);
    goto CPyL28;
CPyL70: ;
    CPy_DECREF(cpy_r_upper);
    goto CPyL27;
CPyL71: ;
    CPy_DecRef(cpy_r_r41);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r43);
    goto CPyL34;
CPyL72: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r18);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r39.f0);
    CPy_DecRef(cpy_r_r39.f1);
    CPy_DecRef(cpy_r_r39.f2);
    goto CPyL32;
CPyL73: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r18);
    CPy_DecRef(cpy_r_r21);
    goto CPyL35;
CPyL74: ;
    CPy_DECREF(cpy_r_r18);
    CPy_DECREF(cpy_r_r21);
    goto CPyL41;
CPyL75: ;
    CPy_DecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r18);
    goto CPyL44;
CPyL76: ;
    CPy_DECREF(cpy_r_r57);
    goto CPyL40;
CPyL77: ;
    CPy_DECREF(cpy_r_upper);
    goto CPyL42;
CPyL78: ;
    CPy_XDECREF(cpy_r_r52.f0);
    CPy_XDECREF(cpy_r_r52.f1);
    CPy_XDECREF(cpy_r_r52.f2);
    goto CPyL43;
CPyL79: ;
    CPy_DecRef(cpy_r_upper);
    goto CPyL49;
CPyL80: ;
    CPy_DecRef(cpy_r_upper);
    goto CPyL53;
}

PyObject *CPyPy_numeric___compute_unsigned_fixed_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"num_bits", "frac_places", 0};
    static CPyArg_Parser parser = {"OO:compute_unsigned_fixed_bounds", kwlist, 0};
    PyObject *obj_num_bits;
    PyObject *obj_frac_places;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_num_bits, &obj_frac_places)) {
        return NULL;
    }
    CPyTagged arg_num_bits;
    if (likely(PyLong_Check(obj_num_bits)))
        arg_num_bits = CPyTagged_BorrowFromObject(obj_num_bits);
    else {
        CPy_TypeError("int", obj_num_bits); goto fail;
    }
    CPyTagged arg_frac_places;
    if (likely(PyLong_Check(obj_frac_places)))
        arg_frac_places = CPyTagged_BorrowFromObject(obj_frac_places);
    else {
        CPy_TypeError("int", obj_frac_places); goto fail;
    }
    tuple_T2OO retval = CPyDef_numeric___compute_unsigned_fixed_bounds(arg_num_bits, arg_frac_places);
    if (retval.f0 == NULL) {
        return NULL;
    }
    PyObject *retbox = PyTuple_New(2);
    if (unlikely(retbox == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp102 = retval.f0;
    PyTuple_SET_ITEM(retbox, 0, __tmp102);
    PyObject *__tmp103 = retval.f1;
    PyTuple_SET_ITEM(retbox, 1, __tmp103);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_unsigned_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

tuple_T2OO CPyDef_numeric___compute_signed_fixed_bounds(CPyTagged cpy_r_num_bits, CPyTagged cpy_r_frac_places) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_lower;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_upper;
    PyObject *cpy_r_r2;
    char cpy_r_r3;
    tuple_T2II cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_bounds;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    tuple_T2II cpy_r_r10;
    CPyTagged cpy_r_r11;
    CPyTagged cpy_r_r12;
    CPyTagged cpy_r_r13;
    CPyTagged cpy_r_r14;
    PyObject *cpy_r_r15;
    char cpy_r_r16;
    PyObject *cpy_r_r17;
    char cpy_r_r18;
    PyObject **cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject **cpy_r_r28;
    PyObject *cpy_r_r29;
    char cpy_r_r30;
    PyObject *cpy_r_r31;
    char cpy_r_r32;
    CPyTagged cpy_r_r33;
    PyObject *cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    char cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject **cpy_r_r40;
    PyObject *cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    char cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject **cpy_r_r47;
    PyObject *cpy_r_r48;
    PyObject *cpy_r_r49;
    tuple_T3OOO cpy_r_r50;
    tuple_T3OOO cpy_r_r51;
    PyObject *cpy_r_r52;
    PyObject *cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject **cpy_r_r56;
    PyObject *cpy_r_r57;
    int32_t cpy_r_r58;
    char cpy_r_r59;
    char cpy_r_r60;
    char cpy_r_r61;
    tuple_T3OOO cpy_r_r62;
    tuple_T3OOO cpy_r_r63;
    tuple_T3OOO cpy_r_r64;
    PyObject *cpy_r_r65;
    PyObject **cpy_r_r67;
    PyObject *cpy_r_r68;
    char cpy_r_r69;
    char cpy_r_r70;
    char cpy_r_r71;
    tuple_T2OO cpy_r_r72;
    PyObject *cpy_r_r73;
    tuple_T2OO cpy_r_r74;
    PyObject *cpy_r_r75;
    char cpy_r_r76;
    tuple_T2II cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    int32_t cpy_r_r80;
    char cpy_r_r81;
    tuple_T2OO cpy_r_r82;
    tuple_T2OO cpy_r_r83;
    cpy_r_r0 = NULL;
    cpy_r_lower = cpy_r_r0;
    cpy_r_r1 = NULL;
    cpy_r_upper = cpy_r_r1;
    cpy_r_r2 = CPyStatic_numeric____signed_fixed_bounds_cache;
    if (unlikely(cpy_r_r2 == NULL)) {
        goto CPyL67;
    } else
        goto CPyL3;
CPyL1: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"_signed_fixed_bounds_cache\" was not set");
    cpy_r_r3 = 0;
    if (unlikely(!cpy_r_r3)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_Unreachable();
CPyL3: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    CPyTagged_INCREF(cpy_r_frac_places);
    cpy_r_r4.f0 = cpy_r_num_bits;
    cpy_r_r4.f1 = cpy_r_frac_places;
    cpy_r_r5 = PyTuple_New(2);
    if (unlikely(cpy_r_r5 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp104 = CPyTagged_StealAsObject(cpy_r_r4.f0);
    PyTuple_SET_ITEM(cpy_r_r5, 0, __tmp104);
    PyObject *__tmp105 = CPyTagged_StealAsObject(cpy_r_r4.f1);
    PyTuple_SET_ITEM(cpy_r_r5, 1, __tmp105);
    cpy_r_r6 = CPyDict_GetWithNone(cpy_r_r2, cpy_r_r5);
    CPy_DECREF(cpy_r_r5);
    if (unlikely(cpy_r_r6 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL68;
    }
    if (unlikely(!(PyTuple_Check(cpy_r_r6) && PyTuple_GET_SIZE(cpy_r_r6) == 2))) {
        cpy_r_r7 = NULL;
        goto __LL107;
    }
    cpy_r_r7 = PyTuple_GET_ITEM(cpy_r_r6, 0);
    if (cpy_r_r7 == NULL) goto __LL107;
    cpy_r_r7 = PyTuple_GET_ITEM(cpy_r_r6, 1);
    if (cpy_r_r7 == NULL) goto __LL107;
    cpy_r_r7 = cpy_r_r6;
__LL107: ;
    if (cpy_r_r7 != NULL) goto __LL106;
    if (cpy_r_r6 == Py_None)
        cpy_r_r7 = cpy_r_r6;
    else {
        cpy_r_r7 = NULL;
    }
    if (cpy_r_r7 != NULL) goto __LL106;
    CPy_TypeErrorTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", 78, CPyStatic_numeric___globals, "tuple[object, object] or None", cpy_r_r6);
    goto CPyL68;
__LL106: ;
    cpy_r_bounds = cpy_r_r7;
    cpy_r_r8 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r9 = cpy_r_bounds == cpy_r_r8;
    if (cpy_r_r9) {
        goto CPyL69;
    } else
        goto CPyL70;
CPyL6: ;
    cpy_r_r10 = CPyDef_numeric___compute_signed_integer_bounds(cpy_r_num_bits);
    if (unlikely(cpy_r_r10.f0 == CPY_INT_TAG)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL68;
    }
    cpy_r_r11 = cpy_r_r10.f0;
    cpy_r_r12 = cpy_r_r10.f1;
    cpy_r_r13 = cpy_r_r11;
    cpy_r_r14 = cpy_r_r12;
    cpy_r_r15 = CPyStatic_numeric___abi_decimal_context;
    if (unlikely(cpy_r_r15 == NULL)) {
        goto CPyL71;
    } else
        goto CPyL10;
CPyL8: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"abi_decimal_context\" was not set");
    cpy_r_r16 = 0;
    if (unlikely(!cpy_r_r16)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_Unreachable();
CPyL10: ;
    cpy_r_r17 = CPyStatic_numeric___decimal_localcontext;
    if (unlikely(cpy_r_r17 == NULL)) {
        goto CPyL72;
    } else
        goto CPyL13;
CPyL11: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"decimal_localcontext\" was not set");
    cpy_r_r18 = 0;
    if (unlikely(!cpy_r_r18)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_Unreachable();
CPyL13: ;
    PyObject *cpy_r_r19[1] = {cpy_r_r15};
    cpy_r_r20 = (PyObject **)&cpy_r_r19;
    cpy_r_r21 = PyObject_Vectorcall(cpy_r_r17, cpy_r_r20, 1, 0);
    if (unlikely(cpy_r_r21 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL73;
    }
    cpy_r_r22 = CPy_TYPE(cpy_r_r21);
    cpy_r_r23 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__exit__' */
    cpy_r_r24 = CPyObject_GetAttr(cpy_r_r22, cpy_r_r23);
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL74;
    }
    cpy_r_r25 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__enter__' */
    cpy_r_r26 = CPyObject_GetAttr(cpy_r_r22, cpy_r_r25);
    CPy_DECREF(cpy_r_r22);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL75;
    }
    PyObject *cpy_r_r27[1] = {cpy_r_r21};
    cpy_r_r28 = (PyObject **)&cpy_r_r27;
    cpy_r_r29 = PyObject_Vectorcall(cpy_r_r26, cpy_r_r28, 1, 0);
    CPy_DECREF(cpy_r_r26);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL75;
    } else
        goto CPyL76;
CPyL17: ;
    cpy_r_r30 = 1;
    cpy_r_r31 = CPyStatic_numeric___TEN;
    if (unlikely(cpy_r_r31 == NULL)) {
        goto CPyL77;
    } else
        goto CPyL21;
CPyL19: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"TEN\" was not set");
    cpy_r_r32 = 0;
    if (unlikely(!cpy_r_r32)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL33;
    } else
        goto CPyL78;
CPyL20: ;
    CPy_Unreachable();
CPyL21: ;
    cpy_r_r33 = CPyTagged_Negate(cpy_r_frac_places);
    cpy_r_r34 = CPyTagged_StealAsObject(cpy_r_r33);
    cpy_r_r35 = CPyNumber_Power(cpy_r_r31, cpy_r_r34);
    CPy_DECREF(cpy_r_r34);
    if (unlikely(cpy_r_r35 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL79;
    }
    cpy_r_r36 = CPyStatic_numeric___Decimal;
    if (unlikely(cpy_r_r36 == NULL)) {
        goto CPyL80;
    } else
        goto CPyL25;
CPyL23: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"Decimal\" was not set");
    cpy_r_r37 = 0;
    if (unlikely(!cpy_r_r37)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL33;
    } else
        goto CPyL81;
CPyL24: ;
    CPy_Unreachable();
CPyL25: ;
    cpy_r_r38 = CPyTagged_StealAsObject(cpy_r_r13);
    PyObject *cpy_r_r39[1] = {cpy_r_r38};
    cpy_r_r40 = (PyObject **)&cpy_r_r39;
    cpy_r_r41 = PyObject_Vectorcall(cpy_r_r36, cpy_r_r40, 1, 0);
    if (unlikely(cpy_r_r41 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL82;
    }
    CPy_DECREF(cpy_r_r38);
    cpy_r_r42 = PyNumber_Multiply(cpy_r_r41, cpy_r_r35);
    CPy_DECREF(cpy_r_r41);
    if (unlikely(cpy_r_r42 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL83;
    } else
        goto CPyL84;
CPyL27: ;
    cpy_r_lower = cpy_r_r42;
    cpy_r_r43 = CPyStatic_numeric___Decimal;
    if (unlikely(cpy_r_r43 == NULL)) {
        goto CPyL85;
    } else
        goto CPyL30;
CPyL28: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"Decimal\" was not set");
    cpy_r_r44 = 0;
    if (unlikely(!cpy_r_r44)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL33;
    } else
        goto CPyL86;
CPyL29: ;
    CPy_Unreachable();
CPyL30: ;
    cpy_r_r45 = CPyTagged_StealAsObject(cpy_r_r14);
    PyObject *cpy_r_r46[1] = {cpy_r_r45};
    cpy_r_r47 = (PyObject **)&cpy_r_r46;
    cpy_r_r48 = PyObject_Vectorcall(cpy_r_r43, cpy_r_r47, 1, 0);
    if (unlikely(cpy_r_r48 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL87;
    }
    CPy_DECREF(cpy_r_r45);
    cpy_r_r49 = PyNumber_Multiply(cpy_r_r48, cpy_r_r35);
    CPy_DECREF(cpy_r_r48);
    CPy_DECREF(cpy_r_r35);
    if (unlikely(cpy_r_r49 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL33;
    } else
        goto CPyL88;
CPyL32: ;
    cpy_r_upper = cpy_r_r49;
    goto CPyL41;
CPyL33: ;
    cpy_r_r50 = CPy_CatchError();
    cpy_r_r30 = 0;
    cpy_r_r51 = CPy_GetExcInfo();
    cpy_r_r52 = cpy_r_r51.f0;
    CPy_INCREF(cpy_r_r52);
    cpy_r_r53 = cpy_r_r51.f1;
    CPy_INCREF(cpy_r_r53);
    cpy_r_r54 = cpy_r_r51.f2;
    CPy_INCREF(cpy_r_r54);
    CPy_DecRef(cpy_r_r51.f0);
    CPy_DecRef(cpy_r_r51.f1);
    CPy_DecRef(cpy_r_r51.f2);
    PyObject *cpy_r_r55[4] = {cpy_r_r21, cpy_r_r52, cpy_r_r53, cpy_r_r54};
    cpy_r_r56 = (PyObject **)&cpy_r_r55;
    cpy_r_r57 = PyObject_Vectorcall(cpy_r_r24, cpy_r_r56, 4, 0);
    if (unlikely(cpy_r_r57 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL89;
    }
    CPy_DecRef(cpy_r_r52);
    CPy_DecRef(cpy_r_r53);
    CPy_DecRef(cpy_r_r54);
    cpy_r_r58 = PyObject_IsTrue(cpy_r_r57);
    CPy_DecRef(cpy_r_r57);
    cpy_r_r59 = cpy_r_r58 >= 0;
    if (unlikely(!cpy_r_r59)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL39;
    }
    cpy_r_r60 = cpy_r_r58;
    if (cpy_r_r60) goto CPyL38;
    CPy_Reraise();
    if (!0) {
        goto CPyL39;
    } else
        goto CPyL90;
CPyL37: ;
    CPy_Unreachable();
CPyL38: ;
    CPy_RestoreExcInfo(cpy_r_r50);
    CPy_DecRef(cpy_r_r50.f0);
    CPy_DecRef(cpy_r_r50.f1);
    CPy_DecRef(cpy_r_r50.f2);
    goto CPyL41;
CPyL39: ;
    CPy_RestoreExcInfo(cpy_r_r50);
    CPy_DecRef(cpy_r_r50.f0);
    CPy_DecRef(cpy_r_r50.f1);
    CPy_DecRef(cpy_r_r50.f2);
    cpy_r_r61 = CPy_KeepPropagating();
    if (!cpy_r_r61) {
        goto CPyL42;
    } else
        goto CPyL91;
CPyL40: ;
    CPy_Unreachable();
CPyL41: ;
    tuple_T3OOO __tmp108 = { NULL, NULL, NULL };
    cpy_r_r62 = __tmp108;
    cpy_r_r63 = cpy_r_r62;
    goto CPyL43;
CPyL42: ;
    cpy_r_r64 = CPy_CatchError();
    cpy_r_r63 = cpy_r_r64;
CPyL43: ;
    if (!cpy_r_r30) goto CPyL92;
    cpy_r_r65 = (PyObject *)&_Py_NoneStruct;
    PyObject *cpy_r_r66[4] = {cpy_r_r21, cpy_r_r65, cpy_r_r65, cpy_r_r65};
    cpy_r_r67 = (PyObject **)&cpy_r_r66;
    cpy_r_r68 = PyObject_Vectorcall(cpy_r_r24, cpy_r_r67, 4, 0);
    CPy_DECREF(cpy_r_r24);
    if (unlikely(cpy_r_r68 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL93;
    } else
        goto CPyL94;
CPyL45: ;
    CPy_DECREF(cpy_r_r21);
CPyL46: ;
    if (cpy_r_r63.f0 == NULL) {
        goto CPyL53;
    } else
        goto CPyL95;
CPyL47: ;
    CPy_Reraise();
    if (!0) {
        goto CPyL49;
    } else
        goto CPyL96;
CPyL48: ;
    CPy_Unreachable();
CPyL49: ;
    if (cpy_r_r63.f0 == NULL) goto CPyL51;
    CPy_RestoreExcInfo(cpy_r_r63);
    CPy_XDECREF(cpy_r_r63.f0);
    CPy_XDECREF(cpy_r_r63.f1);
    CPy_XDECREF(cpy_r_r63.f2);
CPyL51: ;
    cpy_r_r69 = CPy_KeepPropagating();
    if (!cpy_r_r69) goto CPyL66;
    CPy_Unreachable();
CPyL53: ;
    if (cpy_r_lower == NULL) {
        goto CPyL97;
    } else
        goto CPyL56;
CPyL54: ;
    PyErr_SetString(PyExc_UnboundLocalError, "local variable \"lower\" referenced before assignment");
    cpy_r_r70 = 0;
    if (unlikely(!cpy_r_r70)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_Unreachable();
CPyL56: ;
    if (cpy_r_upper == NULL) {
        goto CPyL98;
    } else
        goto CPyL59;
CPyL57: ;
    PyErr_SetString(PyExc_UnboundLocalError, "local variable \"upper\" referenced before assignment");
    cpy_r_r71 = 0;
    if (unlikely(!cpy_r_r71)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_Unreachable();
CPyL59: ;
    cpy_r_r72.f0 = cpy_r_lower;
    cpy_r_r72.f1 = cpy_r_upper;
    cpy_r_r73 = PyTuple_New(2);
    if (unlikely(cpy_r_r73 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp109 = cpy_r_r72.f0;
    PyTuple_SET_ITEM(cpy_r_r73, 0, __tmp109);
    PyObject *__tmp110 = cpy_r_r72.f1;
    PyTuple_SET_ITEM(cpy_r_r73, 1, __tmp110);
    cpy_r_bounds = cpy_r_r73;
    PyObject *__tmp111;
    if (unlikely(!(PyTuple_Check(cpy_r_bounds) && PyTuple_GET_SIZE(cpy_r_bounds) == 2))) {
        __tmp111 = NULL;
        goto __LL112;
    }
    __tmp111 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
    if (__tmp111 == NULL) goto __LL112;
    __tmp111 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
    if (__tmp111 == NULL) goto __LL112;
    __tmp111 = cpy_r_bounds;
__LL112: ;
    if (unlikely(__tmp111 == NULL)) {
        CPy_TypeError("tuple[object, object]", cpy_r_bounds); cpy_r_r74 = (tuple_T2OO) { NULL, NULL };
    } else {
        PyObject *__tmp113 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
        CPy_INCREF(__tmp113);
        PyObject *__tmp114;
        __tmp114 = __tmp113;
        cpy_r_r74.f0 = __tmp114;
        PyObject *__tmp115 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
        CPy_INCREF(__tmp115);
        PyObject *__tmp116;
        __tmp116 = __tmp115;
        cpy_r_r74.f1 = __tmp116;
    }
    if (unlikely(cpy_r_r74.f0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL99;
    }
    cpy_r_r75 = CPyStatic_numeric____signed_fixed_bounds_cache;
    if (unlikely(cpy_r_r75 == NULL)) {
        goto CPyL100;
    } else
        goto CPyL63;
CPyL61: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"_signed_fixed_bounds_cache\" was not set");
    cpy_r_r76 = 0;
    if (unlikely(!cpy_r_r76)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    CPy_Unreachable();
CPyL63: ;
    CPyTagged_INCREF(cpy_r_num_bits);
    CPyTagged_INCREF(cpy_r_frac_places);
    cpy_r_r77.f0 = cpy_r_num_bits;
    cpy_r_r77.f1 = cpy_r_frac_places;
    cpy_r_r78 = PyTuple_New(2);
    if (unlikely(cpy_r_r78 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp117 = CPyTagged_StealAsObject(cpy_r_r77.f0);
    PyTuple_SET_ITEM(cpy_r_r78, 0, __tmp117);
    PyObject *__tmp118 = CPyTagged_StealAsObject(cpy_r_r77.f1);
    PyTuple_SET_ITEM(cpy_r_r78, 1, __tmp118);
    cpy_r_r79 = PyTuple_New(2);
    if (unlikely(cpy_r_r79 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp119 = cpy_r_r74.f0;
    PyTuple_SET_ITEM(cpy_r_r79, 0, __tmp119);
    PyObject *__tmp120 = cpy_r_r74.f1;
    PyTuple_SET_ITEM(cpy_r_r79, 1, __tmp120);
    cpy_r_r80 = CPyDict_SetItem(cpy_r_r75, cpy_r_r78, cpy_r_r79);
    CPy_DECREF(cpy_r_r78);
    CPy_DECREF(cpy_r_r79);
    cpy_r_r81 = cpy_r_r80 >= 0;
    if (unlikely(!cpy_r_r81)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL99;
    }
CPyL64: ;
    PyObject *__tmp121;
    if (unlikely(!(PyTuple_Check(cpy_r_bounds) && PyTuple_GET_SIZE(cpy_r_bounds) == 2))) {
        __tmp121 = NULL;
        goto __LL122;
    }
    __tmp121 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
    if (__tmp121 == NULL) goto __LL122;
    __tmp121 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
    if (__tmp121 == NULL) goto __LL122;
    __tmp121 = cpy_r_bounds;
__LL122: ;
    if (unlikely(__tmp121 == NULL)) {
        CPy_TypeError("tuple[object, object]", cpy_r_bounds); cpy_r_r82 = (tuple_T2OO) { NULL, NULL };
    } else {
        PyObject *__tmp123 = PyTuple_GET_ITEM(cpy_r_bounds, 0);
        CPy_INCREF(__tmp123);
        PyObject *__tmp124;
        __tmp124 = __tmp123;
        cpy_r_r82.f0 = __tmp124;
        PyObject *__tmp125 = PyTuple_GET_ITEM(cpy_r_bounds, 1);
        CPy_INCREF(__tmp125);
        PyObject *__tmp126;
        __tmp126 = __tmp125;
        cpy_r_r82.f1 = __tmp126;
    }
    CPy_DECREF(cpy_r_bounds);
    if (unlikely(cpy_r_r82.f0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    return cpy_r_r82;
CPyL66: ;
    tuple_T2OO __tmp127 = { NULL, NULL };
    cpy_r_r83 = __tmp127;
    return cpy_r_r83;
CPyL67: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    goto CPyL1;
CPyL68: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    goto CPyL66;
CPyL69: ;
    CPy_DECREF(cpy_r_bounds);
    goto CPyL6;
CPyL70: ;
    CPy_XDECREF(cpy_r_lower);
    CPy_XDECREF(cpy_r_upper);
    goto CPyL64;
CPyL71: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    goto CPyL8;
CPyL72: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    goto CPyL11;
CPyL73: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    goto CPyL66;
CPyL74: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r22);
    goto CPyL66;
CPyL75: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r24);
    goto CPyL66;
CPyL76: ;
    CPy_DECREF(cpy_r_r29);
    goto CPyL17;
CPyL77: ;
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    goto CPyL19;
CPyL78: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r24);
    goto CPyL20;
CPyL79: ;
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    goto CPyL33;
CPyL80: ;
    CPyTagged_DecRef(cpy_r_r13);
    CPyTagged_DecRef(cpy_r_r14);
    CPy_DecRef(cpy_r_r35);
    goto CPyL23;
CPyL81: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r24);
    goto CPyL24;
CPyL82: ;
    CPyTagged_DecRef(cpy_r_r14);
    CPy_DecRef(cpy_r_r35);
    CPy_DecRef(cpy_r_r38);
    goto CPyL33;
CPyL83: ;
    CPyTagged_DecRef(cpy_r_r14);
    CPy_DecRef(cpy_r_r35);
    goto CPyL33;
CPyL84: ;
    CPy_XDECREF(cpy_r_lower);
    goto CPyL27;
CPyL85: ;
    CPyTagged_DecRef(cpy_r_r14);
    CPy_DecRef(cpy_r_r35);
    goto CPyL28;
CPyL86: ;
    CPy_DecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r24);
    goto CPyL29;
CPyL87: ;
    CPy_DecRef(cpy_r_r35);
    CPy_DecRef(cpy_r_r45);
    goto CPyL33;
CPyL88: ;
    CPy_XDECREF(cpy_r_upper);
    goto CPyL32;
CPyL89: ;
    CPy_DecRef(cpy_r_r52);
    CPy_DecRef(cpy_r_r53);
    CPy_DecRef(cpy_r_r54);
    goto CPyL39;
CPyL90: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r24);
    CPy_DecRef(cpy_r_r50.f0);
    CPy_DecRef(cpy_r_r50.f1);
    CPy_DecRef(cpy_r_r50.f2);
    goto CPyL37;
CPyL91: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r21);
    CPy_DecRef(cpy_r_r24);
    goto CPyL40;
CPyL92: ;
    CPy_DECREF(cpy_r_r21);
    CPy_DECREF(cpy_r_r24);
    goto CPyL46;
CPyL93: ;
    CPy_XDecRef(cpy_r_lower);
    CPy_XDecRef(cpy_r_upper);
    CPy_DecRef(cpy_r_r21);
    goto CPyL49;
CPyL94: ;
    CPy_DECREF(cpy_r_r68);
    goto CPyL45;
CPyL95: ;
    CPy_XDECREF(cpy_r_lower);
    CPy_XDECREF(cpy_r_upper);
    goto CPyL47;
CPyL96: ;
    CPy_XDECREF(cpy_r_r63.f0);
    CPy_XDECREF(cpy_r_r63.f1);
    CPy_XDECREF(cpy_r_r63.f2);
    goto CPyL48;
CPyL97: ;
    CPy_XDECREF(cpy_r_upper);
    goto CPyL54;
CPyL98: ;
    CPy_XDECREF(cpy_r_lower);
    goto CPyL57;
CPyL99: ;
    CPy_DecRef(cpy_r_bounds);
    goto CPyL66;
CPyL100: ;
    CPy_DecRef(cpy_r_bounds);
    CPy_DecRef(cpy_r_r74.f0);
    CPy_DecRef(cpy_r_r74.f1);
    goto CPyL61;
}

PyObject *CPyPy_numeric___compute_signed_fixed_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"num_bits", "frac_places", 0};
    static CPyArg_Parser parser = {"OO:compute_signed_fixed_bounds", kwlist, 0};
    PyObject *obj_num_bits;
    PyObject *obj_frac_places;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_num_bits, &obj_frac_places)) {
        return NULL;
    }
    CPyTagged arg_num_bits;
    if (likely(PyLong_Check(obj_num_bits)))
        arg_num_bits = CPyTagged_BorrowFromObject(obj_num_bits);
    else {
        CPy_TypeError("int", obj_num_bits); goto fail;
    }
    CPyTagged arg_frac_places;
    if (likely(PyLong_Check(obj_frac_places)))
        arg_frac_places = CPyTagged_BorrowFromObject(obj_frac_places);
    else {
        CPy_TypeError("int", obj_frac_places); goto fail;
    }
    tuple_T2OO retval = CPyDef_numeric___compute_signed_fixed_bounds(arg_num_bits, arg_frac_places);
    if (retval.f0 == NULL) {
        return NULL;
    }
    PyObject *retbox = PyTuple_New(2);
    if (unlikely(retbox == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp128 = retval.f0;
    PyTuple_SET_ITEM(retbox, 0, __tmp128);
    PyObject *__tmp129 = retval.f1;
    PyTuple_SET_ITEM(retbox, 1, __tmp129);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "compute_signed_fixed_bounds", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

PyObject *CPyDef_numeric___f_scale_places_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner) {
    PyObject *cpy_r_r0;
    char cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    cpy_r_r0 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r1 = cpy_r_instance == cpy_r_r0;
    if (!cpy_r_r1) goto CPyL2;
    CPy_INCREF(cpy_r___mypyc_self__);
    return cpy_r___mypyc_self__;
CPyL2: ;
    cpy_r_r2 = PyMethod_New(cpy_r___mypyc_self__, cpy_r_instance);
    if (cpy_r_r2 == NULL) goto CPyL4;
    return cpy_r_r2;
CPyL4: ;
    cpy_r_r3 = NULL;
    return cpy_r_r3;
}

PyObject *CPyPy_numeric___f_scale_places_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"instance", "owner", 0};
    static CPyArg_Parser parser = {"OO:__get__", kwlist, 0};
    PyObject *obj_instance;
    PyObject *obj_owner;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_instance, &obj_owner)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_instance = obj_instance;
    PyObject *arg_owner = obj_owner;
    PyObject *retval = CPyDef_numeric___f_scale_places_obj_____get__(arg___mypyc_self__, arg_instance, arg_owner);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "__get__", -1, CPyStatic_numeric___globals);
    return NULL;
}

PyObject *CPyDef_numeric___f_scale_places_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_x) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    char cpy_r_r4;
    PyObject **cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject **cpy_r_r14;
    PyObject *cpy_r_r15;
    char cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    tuple_T3OOO cpy_r_r20;
    tuple_T3OOO cpy_r_r21;
    PyObject *cpy_r_r22;
    PyObject *cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject **cpy_r_r26;
    PyObject *cpy_r_r27;
    int32_t cpy_r_r28;
    char cpy_r_r29;
    char cpy_r_r30;
    char cpy_r_r31;
    PyObject *cpy_r_r32;
    tuple_T3OOO cpy_r_r33;
    tuple_T3OOO cpy_r_r34;
    PyObject *cpy_r_r35;
    tuple_T3OOO cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject **cpy_r_r39;
    PyObject *cpy_r_r40;
    char cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    cpy_r_r0 = ((faster_eth_abi___utils___numeric___f_scale_places_objObject *)cpy_r___mypyc_self__)->___mypyc_env__;
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AttributeError("faster_eth_abi/utils/numeric.py", "f", "f_scale_places_obj", "__mypyc_env__", 107, CPyStatic_numeric___globals);
        goto CPyL39;
    }
    CPy_INCREF_NO_IMM(cpy_r_r0);
CPyL1: ;
    cpy_r_r1 = CPyStatic_numeric___abi_decimal_context;
    if (unlikely(cpy_r_r1 == NULL)) {
        goto CPyL40;
    } else
        goto CPyL4;
CPyL2: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"abi_decimal_context\" was not set");
    cpy_r_r2 = 0;
    if (unlikely(!cpy_r_r2)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL39;
    }
    CPy_Unreachable();
CPyL4: ;
    cpy_r_r3 = CPyStatic_numeric___decimal_localcontext;
    if (unlikely(cpy_r_r3 == NULL)) {
        goto CPyL41;
    } else
        goto CPyL7;
CPyL5: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"decimal_localcontext\" was not set");
    cpy_r_r4 = 0;
    if (unlikely(!cpy_r_r4)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL39;
    }
    CPy_Unreachable();
CPyL7: ;
    PyObject *cpy_r_r5[1] = {cpy_r_r1};
    cpy_r_r6 = (PyObject **)&cpy_r_r5;
    cpy_r_r7 = PyObject_Vectorcall(cpy_r_r3, cpy_r_r6, 1, 0);
    if (unlikely(cpy_r_r7 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL42;
    }
    cpy_r_r8 = CPy_TYPE(cpy_r_r7);
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__exit__' */
    cpy_r_r10 = CPyObject_GetAttr(cpy_r_r8, cpy_r_r9);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL43;
    }
    cpy_r_r11 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__enter__' */
    cpy_r_r12 = CPyObject_GetAttr(cpy_r_r8, cpy_r_r11);
    CPy_DECREF(cpy_r_r8);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL44;
    }
    PyObject *cpy_r_r13[1] = {cpy_r_r7};
    cpy_r_r14 = (PyObject **)&cpy_r_r13;
    cpy_r_r15 = PyObject_Vectorcall(cpy_r_r12, cpy_r_r14, 1, 0);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r15 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL44;
    } else
        goto CPyL45;
CPyL11: ;
    cpy_r_r16 = 1;
    cpy_r_r17 = ((faster_eth_abi___utils___numeric___scale_places_envObject *)cpy_r_r0)->_scaling_factor;
    if (unlikely(cpy_r_r17 == NULL)) {
        PyErr_SetString(PyExc_AttributeError, "attribute 'scaling_factor' of 'scale_places_env' undefined");
    } else {
        CPy_INCREF(cpy_r_r17);
    }
    CPy_DECREF_NO_IMM(cpy_r_r0);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
CPyL13: ;
    cpy_r_r18 = PyNumber_Multiply(cpy_r_x, cpy_r_r17);
    CPy_DECREF(cpy_r_r17);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL15;
    }
    cpy_r_r19 = cpy_r_r18;
    goto CPyL24;
CPyL15: ;
    cpy_r_r20 = CPy_CatchError();
    cpy_r_r16 = 0;
    cpy_r_r21 = CPy_GetExcInfo();
    cpy_r_r22 = cpy_r_r21.f0;
    CPy_INCREF(cpy_r_r22);
    cpy_r_r23 = cpy_r_r21.f1;
    CPy_INCREF(cpy_r_r23);
    cpy_r_r24 = cpy_r_r21.f2;
    CPy_INCREF(cpy_r_r24);
    CPy_DecRef(cpy_r_r21.f0);
    CPy_DecRef(cpy_r_r21.f1);
    CPy_DecRef(cpy_r_r21.f2);
    PyObject *cpy_r_r25[4] = {cpy_r_r7, cpy_r_r22, cpy_r_r23, cpy_r_r24};
    cpy_r_r26 = (PyObject **)&cpy_r_r25;
    cpy_r_r27 = PyObject_Vectorcall(cpy_r_r10, cpy_r_r26, 4, 0);
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL46;
    }
    CPy_DecRef(cpy_r_r22);
    CPy_DecRef(cpy_r_r23);
    CPy_DecRef(cpy_r_r24);
    cpy_r_r28 = PyObject_IsTrue(cpy_r_r27);
    CPy_DecRef(cpy_r_r27);
    cpy_r_r29 = cpy_r_r28 >= 0;
    if (unlikely(!cpy_r_r29)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL21;
    }
    cpy_r_r30 = cpy_r_r28;
    if (cpy_r_r30) goto CPyL20;
    CPy_Reraise();
    if (!0) {
        goto CPyL21;
    } else
        goto CPyL47;
CPyL19: ;
    CPy_Unreachable();
CPyL20: ;
    CPy_RestoreExcInfo(cpy_r_r20);
    CPy_DecRef(cpy_r_r20.f0);
    CPy_DecRef(cpy_r_r20.f1);
    CPy_DecRef(cpy_r_r20.f2);
    goto CPyL23;
CPyL21: ;
    CPy_RestoreExcInfo(cpy_r_r20);
    CPy_DecRef(cpy_r_r20.f0);
    CPy_DecRef(cpy_r_r20.f1);
    CPy_DecRef(cpy_r_r20.f2);
    cpy_r_r31 = CPy_KeepPropagating();
    if (!cpy_r_r31) {
        goto CPyL25;
    } else
        goto CPyL48;
CPyL22: ;
    CPy_Unreachable();
CPyL23: ;
    cpy_r_r32 = NULL;
    cpy_r_r19 = cpy_r_r32;
CPyL24: ;
    tuple_T3OOO __tmp130 = { NULL, NULL, NULL };
    cpy_r_r33 = __tmp130;
    cpy_r_r34 = cpy_r_r33;
    goto CPyL26;
CPyL25: ;
    cpy_r_r35 = NULL;
    cpy_r_r19 = cpy_r_r35;
    cpy_r_r36 = CPy_CatchError();
    cpy_r_r34 = cpy_r_r36;
CPyL26: ;
    if (!cpy_r_r16) goto CPyL49;
    cpy_r_r37 = (PyObject *)&_Py_NoneStruct;
    PyObject *cpy_r_r38[4] = {cpy_r_r7, cpy_r_r37, cpy_r_r37, cpy_r_r37};
    cpy_r_r39 = (PyObject **)&cpy_r_r38;
    cpy_r_r40 = PyObject_Vectorcall(cpy_r_r10, cpy_r_r39, 4, 0);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r40 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL50;
    } else
        goto CPyL51;
CPyL28: ;
    CPy_DECREF(cpy_r_r7);
CPyL29: ;
    if (cpy_r_r34.f0 == NULL) {
        goto CPyL32;
    } else
        goto CPyL52;
CPyL30: ;
    CPy_Reraise();
    if (!0) {
        goto CPyL34;
    } else
        goto CPyL53;
CPyL31: ;
    CPy_Unreachable();
CPyL32: ;
    if (cpy_r_r19 == NULL) goto CPyL38;
    return cpy_r_r19;
CPyL34: ;
    if (cpy_r_r34.f0 == NULL) goto CPyL36;
    CPy_RestoreExcInfo(cpy_r_r34);
    CPy_XDECREF(cpy_r_r34.f0);
    CPy_XDECREF(cpy_r_r34.f1);
    CPy_XDECREF(cpy_r_r34.f2);
CPyL36: ;
    cpy_r_r41 = CPy_KeepPropagating();
    if (!cpy_r_r41) goto CPyL39;
    CPy_Unreachable();
CPyL38: ;
    cpy_r_r42 = Py_None;
    return cpy_r_r42;
CPyL39: ;
    cpy_r_r43 = NULL;
    return cpy_r_r43;
CPyL40: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL2;
CPyL41: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL5;
CPyL42: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL39;
CPyL43: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r7);
    CPy_DecRef(cpy_r_r8);
    goto CPyL39;
CPyL44: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r7);
    CPy_DecRef(cpy_r_r10);
    goto CPyL39;
CPyL45: ;
    CPy_DECREF(cpy_r_r15);
    goto CPyL11;
CPyL46: ;
    CPy_DecRef(cpy_r_r22);
    CPy_DecRef(cpy_r_r23);
    CPy_DecRef(cpy_r_r24);
    goto CPyL21;
CPyL47: ;
    CPy_DecRef(cpy_r_r7);
    CPy_DecRef(cpy_r_r10);
    CPy_DecRef(cpy_r_r20.f0);
    CPy_DecRef(cpy_r_r20.f1);
    CPy_DecRef(cpy_r_r20.f2);
    goto CPyL19;
CPyL48: ;
    CPy_DecRef(cpy_r_r7);
    CPy_DecRef(cpy_r_r10);
    goto CPyL22;
CPyL49: ;
    CPy_DECREF(cpy_r_r7);
    CPy_DECREF(cpy_r_r10);
    goto CPyL29;
CPyL50: ;
    CPy_DecRef(cpy_r_r7);
    CPy_XDecRef(cpy_r_r19);
    goto CPyL34;
CPyL51: ;
    CPy_DECREF(cpy_r_r40);
    goto CPyL28;
CPyL52: ;
    CPy_XDECREF(cpy_r_r19);
    goto CPyL30;
CPyL53: ;
    CPy_XDECREF(cpy_r_r34.f0);
    CPy_XDECREF(cpy_r_r34.f1);
    CPy_XDECREF(cpy_r_r34.f2);
    goto CPyL31;
}

PyObject *CPyPy_numeric___f_scale_places_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    PyObject *obj___mypyc_self__ = self;
    static const char * const kwlist[] = {"x", 0};
    static CPyArg_Parser parser = {"O:__call__", kwlist, 0};
    PyObject *obj_x;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, PyVectorcall_NARGS(nargs), kwnames, &parser, &obj_x)) {
        return NULL;
    }
    PyObject *arg___mypyc_self__ = obj___mypyc_self__;
    PyObject *arg_x = obj_x;
    PyObject *retval = CPyDef_numeric___f_scale_places_obj_____call__(arg___mypyc_self__, arg_x);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "f", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

PyObject *CPyDef_numeric___scale_places(CPyTagged cpy_r_places) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject **cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject **cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    PyObject *cpy_r_r22;
    CPyPtr cpy_r_r23;
    CPyPtr cpy_r_r24;
    CPyPtr cpy_r_r25;
    CPyPtr cpy_r_r26;
    CPyPtr cpy_r_r27;
    CPyPtr cpy_r_r28;
    PyObject *cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject **cpy_r_r34;
    PyObject *cpy_r_r35;
    PyObject *cpy_r_r36;
    char cpy_r_r37;
    PyObject *cpy_r_r38;
    char cpy_r_r39;
    PyObject **cpy_r_r41;
    PyObject *cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject *cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject *cpy_r_r46;
    PyObject *cpy_r_r47;
    PyObject **cpy_r_r49;
    PyObject *cpy_r_r50;
    char cpy_r_r51;
    PyObject *cpy_r_r52;
    char cpy_r_r53;
    CPyTagged cpy_r_r54;
    PyObject *cpy_r_r55;
    PyObject *cpy_r_r56;
    char cpy_r_r57;
    tuple_T3OOO cpy_r_r58;
    tuple_T3OOO cpy_r_r59;
    PyObject *cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    PyObject **cpy_r_r64;
    PyObject *cpy_r_r65;
    int32_t cpy_r_r66;
    char cpy_r_r67;
    char cpy_r_r68;
    char cpy_r_r69;
    tuple_T3OOO cpy_r_r70;
    tuple_T3OOO cpy_r_r71;
    tuple_T3OOO cpy_r_r72;
    PyObject *cpy_r_r73;
    PyObject **cpy_r_r75;
    PyObject *cpy_r_r76;
    char cpy_r_r77;
    PyObject *cpy_r_r78;
    char cpy_r_r79;
    PyObject *cpy_r_f;
    int64_t cpy_r_r80;
    char cpy_r_r81;
    int64_t cpy_r_r82;
    char cpy_r_r83;
    char cpy_r_r84;
    char cpy_r_r85;
    PyObject *cpy_r_r86;
    PyObject *cpy_r_r87;
    PyObject *cpy_r_r88;
    PyObject *cpy_r_r89;
    PyObject *cpy_r_r90;
    CPyTagged cpy_r_r91;
    PyObject *cpy_r_r92;
    PyObject *cpy_r_r93;
    PyObject *cpy_r_places_repr;
    PyObject *cpy_r_r94;
    PyObject *cpy_r_r95;
    PyObject *cpy_r_r96;
    int32_t cpy_r_r97;
    char cpy_r_r98;
    PyObject *cpy_r_r99;
    int32_t cpy_r_r100;
    char cpy_r_r101;
    PyObject *cpy_r_r102;
    cpy_r_r0 = CPyDef_numeric___scale_places_env();
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    }
    CPyTagged_INCREF(cpy_r_places);
    cpy_r_r1 = CPyTagged_StealAsObject(cpy_r_places);
    cpy_r_r2 = PyLong_Check(cpy_r_r1);
    CPy_DECREF(cpy_r_r1);
    if (cpy_r_r2) {
        goto CPyL10;
    } else
        goto CPyL63;
CPyL2: ;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r4 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Argument `places` must be int.  Got value ' */
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{:{}}' */
    CPyTagged_INCREF(cpy_r_places);
    cpy_r_r6 = CPyTagged_StealAsObject(cpy_r_places);
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r9[3] = {cpy_r_r5, cpy_r_r6, cpy_r_r7};
    cpy_r_r10 = (PyObject **)&cpy_r_r9;
    cpy_r_r11 = PyObject_VectorcallMethod(cpy_r_r8, cpy_r_r10, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL64;
    }
    CPy_DECREF(cpy_r_r6);
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ' of type ' */
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '{:{}}' */
    CPyTagged_INCREF(cpy_r_places);
    cpy_r_r14 = CPyTagged_StealAsObject(cpy_r_places);
    cpy_r_r15 = CPy_TYPE(cpy_r_r14);
    CPy_DECREF(cpy_r_r14);
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '' */
    cpy_r_r17 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'format' */
    PyObject *cpy_r_r18[3] = {cpy_r_r13, cpy_r_r15, cpy_r_r16};
    cpy_r_r19 = (PyObject **)&cpy_r_r18;
    cpy_r_r20 = PyObject_VectorcallMethod(cpy_r_r17, cpy_r_r19, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r20 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL65;
    }
    CPy_DECREF(cpy_r_r15);
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '.' */
    cpy_r_r22 = PyList_New(5);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL66;
    }
    cpy_r_r23 = (CPyPtr)&((PyListObject *)cpy_r_r22)->ob_item;
    cpy_r_r24 = *(CPyPtr *)cpy_r_r23;
    CPy_INCREF(cpy_r_r4);
    *(PyObject * *)cpy_r_r24 = cpy_r_r4;
    cpy_r_r25 = cpy_r_r24 + 8;
    *(PyObject * *)cpy_r_r25 = cpy_r_r11;
    CPy_INCREF(cpy_r_r12);
    cpy_r_r26 = cpy_r_r24 + 16;
    *(PyObject * *)cpy_r_r26 = cpy_r_r12;
    cpy_r_r27 = cpy_r_r24 + 24;
    *(PyObject * *)cpy_r_r27 = cpy_r_r20;
    CPy_INCREF(cpy_r_r21);
    cpy_r_r28 = cpy_r_r24 + 32;
    *(PyObject * *)cpy_r_r28 = cpy_r_r21;
    cpy_r_r29 = PyUnicode_Join(cpy_r_r3, cpy_r_r22);
    CPy_DECREF_NO_IMM(cpy_r_r22);
    if (unlikely(cpy_r_r29 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    }
    cpy_r_r30 = CPyModule_builtins;
    cpy_r_r31 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r32 = CPyObject_GetAttr(cpy_r_r30, cpy_r_r31);
    if (unlikely(cpy_r_r32 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL67;
    }
    PyObject *cpy_r_r33[1] = {cpy_r_r29};
    cpy_r_r34 = (PyObject **)&cpy_r_r33;
    cpy_r_r35 = PyObject_Vectorcall(cpy_r_r32, cpy_r_r34, 1, 0);
    CPy_DECREF(cpy_r_r32);
    if (unlikely(cpy_r_r35 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL67;
    }
    CPy_DECREF(cpy_r_r29);
    CPy_Raise(cpy_r_r35);
    CPy_DECREF(cpy_r_r35);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    }
    CPy_Unreachable();
CPyL10: ;
    cpy_r_r36 = CPyStatic_numeric___abi_decimal_context;
    if (unlikely(cpy_r_r36 == NULL)) {
        goto CPyL68;
    } else
        goto CPyL13;
CPyL11: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"abi_decimal_context\" was not set");
    cpy_r_r37 = 0;
    if (unlikely(!cpy_r_r37)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    }
    CPy_Unreachable();
CPyL13: ;
    cpy_r_r38 = CPyStatic_numeric___decimal_localcontext;
    if (unlikely(cpy_r_r38 == NULL)) {
        goto CPyL69;
    } else
        goto CPyL16;
CPyL14: ;
    PyErr_SetString(PyExc_NameError, "value for final name \"decimal_localcontext\" was not set");
    cpy_r_r39 = 0;
    if (unlikely(!cpy_r_r39)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL62;
    }
    CPy_Unreachable();
CPyL16: ;
    PyObject *cpy_r_r40[1] = {cpy_r_r36};
    cpy_r_r41 = (PyObject **)&cpy_r_r40;
    cpy_r_r42 = PyObject_Vectorcall(cpy_r_r38, cpy_r_r41, 1, 0);
    if (unlikely(cpy_r_r42 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL70;
    }
    cpy_r_r43 = CPy_TYPE(cpy_r_r42);
    cpy_r_r44 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__exit__' */
    cpy_r_r45 = CPyObject_GetAttr(cpy_r_r43, cpy_r_r44);
    if (unlikely(cpy_r_r45 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL71;
    }
    cpy_r_r46 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__enter__' */
    cpy_r_r47 = CPyObject_GetAttr(cpy_r_r43, cpy_r_r46);
    CPy_DECREF(cpy_r_r43);
    if (unlikely(cpy_r_r47 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL72;
    }
    PyObject *cpy_r_r48[1] = {cpy_r_r42};
    cpy_r_r49 = (PyObject **)&cpy_r_r48;
    cpy_r_r50 = PyObject_Vectorcall(cpy_r_r47, cpy_r_r49, 1, 0);
    CPy_DECREF(cpy_r_r47);
    if (unlikely(cpy_r_r50 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL72;
    } else
        goto CPyL73;
CPyL20: ;
    cpy_r_r51 = 1;
    cpy_r_r52 = CPyStatic_numeric___TEN;
    if (likely(cpy_r_r52 != NULL)) goto CPyL24;
    PyErr_SetString(PyExc_NameError, "value for final name \"TEN\" was not set");
    cpy_r_r53 = 0;
    if (unlikely(!cpy_r_r53)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL26;
    } else
        goto CPyL74;
CPyL23: ;
    CPy_Unreachable();
CPyL24: ;
    cpy_r_r54 = CPyTagged_Negate(cpy_r_places);
    cpy_r_r55 = CPyTagged_StealAsObject(cpy_r_r54);
    cpy_r_r56 = CPyNumber_Power(cpy_r_r52, cpy_r_r55);
    CPy_DECREF(cpy_r_r55);
    if (unlikely(cpy_r_r56 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL26;
    }
    if (((faster_eth_abi___utils___numeric___scale_places_envObject *)cpy_r_r0)->_scaling_factor != NULL) {
        CPy_DECREF(((faster_eth_abi___utils___numeric___scale_places_envObject *)cpy_r_r0)->_scaling_factor);
    }
    ((faster_eth_abi___utils___numeric___scale_places_envObject *)cpy_r_r0)->_scaling_factor = cpy_r_r56;
    cpy_r_r57 = 1;
    if (unlikely(!cpy_r_r57)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    } else
        goto CPyL34;
CPyL26: ;
    cpy_r_r58 = CPy_CatchError();
    cpy_r_r51 = 0;
    cpy_r_r59 = CPy_GetExcInfo();
    cpy_r_r60 = cpy_r_r59.f0;
    CPy_INCREF(cpy_r_r60);
    cpy_r_r61 = cpy_r_r59.f1;
    CPy_INCREF(cpy_r_r61);
    cpy_r_r62 = cpy_r_r59.f2;
    CPy_INCREF(cpy_r_r62);
    CPy_DecRef(cpy_r_r59.f0);
    CPy_DecRef(cpy_r_r59.f1);
    CPy_DecRef(cpy_r_r59.f2);
    PyObject *cpy_r_r63[4] = {cpy_r_r42, cpy_r_r60, cpy_r_r61, cpy_r_r62};
    cpy_r_r64 = (PyObject **)&cpy_r_r63;
    cpy_r_r65 = PyObject_Vectorcall(cpy_r_r45, cpy_r_r64, 4, 0);
    if (unlikely(cpy_r_r65 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL75;
    }
    CPy_DecRef(cpy_r_r60);
    CPy_DecRef(cpy_r_r61);
    CPy_DecRef(cpy_r_r62);
    cpy_r_r66 = PyObject_IsTrue(cpy_r_r65);
    CPy_DecRef(cpy_r_r65);
    cpy_r_r67 = cpy_r_r66 >= 0;
    if (unlikely(!cpy_r_r67)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL32;
    }
    cpy_r_r68 = cpy_r_r66;
    if (cpy_r_r68) goto CPyL31;
    CPy_Reraise();
    if (!0) {
        goto CPyL32;
    } else
        goto CPyL76;
CPyL30: ;
    CPy_Unreachable();
CPyL31: ;
    CPy_RestoreExcInfo(cpy_r_r58);
    CPy_DecRef(cpy_r_r58.f0);
    CPy_DecRef(cpy_r_r58.f1);
    CPy_DecRef(cpy_r_r58.f2);
    goto CPyL34;
CPyL32: ;
    CPy_RestoreExcInfo(cpy_r_r58);
    CPy_DecRef(cpy_r_r58.f0);
    CPy_DecRef(cpy_r_r58.f1);
    CPy_DecRef(cpy_r_r58.f2);
    cpy_r_r69 = CPy_KeepPropagating();
    if (!cpy_r_r69) {
        goto CPyL35;
    } else
        goto CPyL77;
CPyL33: ;
    CPy_Unreachable();
CPyL34: ;
    tuple_T3OOO __tmp131 = { NULL, NULL, NULL };
    cpy_r_r70 = __tmp131;
    cpy_r_r71 = cpy_r_r70;
    goto CPyL36;
CPyL35: ;
    cpy_r_r72 = CPy_CatchError();
    cpy_r_r71 = cpy_r_r72;
CPyL36: ;
    if (!cpy_r_r51) goto CPyL78;
    cpy_r_r73 = (PyObject *)&_Py_NoneStruct;
    PyObject *cpy_r_r74[4] = {cpy_r_r42, cpy_r_r73, cpy_r_r73, cpy_r_r73};
    cpy_r_r75 = (PyObject **)&cpy_r_r74;
    cpy_r_r76 = PyObject_Vectorcall(cpy_r_r45, cpy_r_r75, 4, 0);
    CPy_DECREF(cpy_r_r45);
    if (unlikely(cpy_r_r76 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL79;
    } else
        goto CPyL80;
CPyL38: ;
    CPy_DECREF(cpy_r_r42);
CPyL39: ;
    if (cpy_r_r71.f0 == NULL) {
        goto CPyL46;
    } else
        goto CPyL81;
CPyL40: ;
    CPy_Reraise();
    if (!0) {
        goto CPyL42;
    } else
        goto CPyL82;
CPyL41: ;
    CPy_Unreachable();
CPyL42: ;
    if (cpy_r_r71.f0 == NULL) goto CPyL44;
    CPy_RestoreExcInfo(cpy_r_r71);
    CPy_XDECREF(cpy_r_r71.f0);
    CPy_XDECREF(cpy_r_r71.f1);
    CPy_XDECREF(cpy_r_r71.f2);
CPyL44: ;
    cpy_r_r77 = CPy_KeepPropagating();
    if (!cpy_r_r77) goto CPyL62;
    CPy_Unreachable();
CPyL46: ;
    cpy_r_r78 = CPyDef_numeric___f_scale_places_obj();
    if (unlikely(cpy_r_r78 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL70;
    }
    if (((faster_eth_abi___utils___numeric___f_scale_places_objObject *)cpy_r_r78)->___mypyc_env__ != NULL) {
        CPy_DECREF_NO_IMM(((faster_eth_abi___utils___numeric___f_scale_places_objObject *)cpy_r_r78)->___mypyc_env__);
    }
    ((faster_eth_abi___utils___numeric___f_scale_places_objObject *)cpy_r_r78)->___mypyc_env__ = cpy_r_r0;
    cpy_r_r79 = 1;
    if (unlikely(!cpy_r_r79)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL83;
    }
    cpy_r_f = cpy_r_r78;
    cpy_r_r80 = cpy_r_places & 1;
    cpy_r_r81 = cpy_r_r80 != 0;
    if (cpy_r_r81) goto CPyL50;
    cpy_r_r82 = 0 & 1;
    cpy_r_r83 = cpy_r_r82 != 0;
    if (!cpy_r_r83) goto CPyL51;
CPyL50: ;
    cpy_r_r84 = CPyTagged_IsLt_(0, cpy_r_places);
    if (cpy_r_r84) {
        goto CPyL52;
    } else
        goto CPyL55;
CPyL51: ;
    cpy_r_r85 = (Py_ssize_t)cpy_r_places > (Py_ssize_t)0;
    if (!cpy_r_r85) goto CPyL55;
CPyL52: ;
    cpy_r_r86 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Eneg' */
    cpy_r_r87 = CPyTagged_Str(cpy_r_places);
    if (unlikely(cpy_r_r87 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL84;
    }
    cpy_r_r88 = CPyStr_Build(2, cpy_r_r86, cpy_r_r87);
    CPy_DECREF(cpy_r_r87);
    if (unlikely(cpy_r_r88 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL84;
    }
    cpy_r_r89 = cpy_r_r88;
    goto CPyL58;
CPyL55: ;
    cpy_r_r90 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Epos' */
    cpy_r_r91 = CPyTagged_Negate(cpy_r_places);
    cpy_r_r92 = CPyTagged_Str(cpy_r_r91);
    CPyTagged_DECREF(cpy_r_r91);
    if (unlikely(cpy_r_r92 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL84;
    }
    cpy_r_r93 = CPyStr_Build(2, cpy_r_r90, cpy_r_r92);
    CPy_DECREF(cpy_r_r92);
    if (unlikely(cpy_r_r93 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL84;
    }
    cpy_r_r89 = cpy_r_r93;
CPyL58: ;
    cpy_r_places_repr = cpy_r_r89;
    cpy_r_r94 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'scale_by_' */
    cpy_r_r95 = CPyStr_Build(2, cpy_r_r94, cpy_r_places_repr);
    CPy_DECREF(cpy_r_places_repr);
    if (unlikely(cpy_r_r95 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL84;
    }
    cpy_r_r96 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__name__' */
    cpy_r_r97 = PyObject_SetAttr(cpy_r_f, cpy_r_r96, cpy_r_r95);
    cpy_r_r98 = cpy_r_r97 >= 0;
    if (unlikely(!cpy_r_r98)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL85;
    }
    cpy_r_r99 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '__qualname__' */
    cpy_r_r100 = PyObject_SetAttr(cpy_r_f, cpy_r_r99, cpy_r_r95);
    CPy_DECREF(cpy_r_r95);
    cpy_r_r101 = cpy_r_r100 >= 0;
    if (unlikely(!cpy_r_r101)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL84;
    }
    return cpy_r_f;
CPyL62: ;
    cpy_r_r102 = NULL;
    return cpy_r_r102;
CPyL63: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    goto CPyL2;
CPyL64: ;
    CPy_DecRef(cpy_r_r6);
    goto CPyL62;
CPyL65: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_r15);
    goto CPyL62;
CPyL66: ;
    CPy_DecRef(cpy_r_r11);
    CPy_DecRef(cpy_r_r20);
    goto CPyL62;
CPyL67: ;
    CPy_DecRef(cpy_r_r29);
    goto CPyL62;
CPyL68: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL11;
CPyL69: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL14;
CPyL70: ;
    CPy_DecRef(cpy_r_r0);
    goto CPyL62;
CPyL71: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r43);
    goto CPyL62;
CPyL72: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r45);
    goto CPyL62;
CPyL73: ;
    CPy_DECREF(cpy_r_r50);
    goto CPyL20;
CPyL74: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r45);
    goto CPyL23;
CPyL75: ;
    CPy_DecRef(cpy_r_r60);
    CPy_DecRef(cpy_r_r61);
    CPy_DecRef(cpy_r_r62);
    goto CPyL32;
CPyL76: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r45);
    CPy_DecRef(cpy_r_r58.f0);
    CPy_DecRef(cpy_r_r58.f1);
    CPy_DecRef(cpy_r_r58.f2);
    goto CPyL30;
CPyL77: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r42);
    CPy_DecRef(cpy_r_r45);
    goto CPyL33;
CPyL78: ;
    CPy_DECREF(cpy_r_r42);
    CPy_DECREF(cpy_r_r45);
    goto CPyL39;
CPyL79: ;
    CPy_DecRef(cpy_r_r0);
    CPy_DecRef(cpy_r_r42);
    goto CPyL42;
CPyL80: ;
    CPy_DECREF(cpy_r_r76);
    goto CPyL38;
CPyL81: ;
    CPy_DECREF_NO_IMM(cpy_r_r0);
    goto CPyL40;
CPyL82: ;
    CPy_XDECREF(cpy_r_r71.f0);
    CPy_XDECREF(cpy_r_r71.f1);
    CPy_XDECREF(cpy_r_r71.f2);
    goto CPyL41;
CPyL83: ;
    CPy_DecRef(cpy_r_r78);
    goto CPyL62;
CPyL84: ;
    CPy_DecRef(cpy_r_f);
    goto CPyL62;
CPyL85: ;
    CPy_DecRef(cpy_r_f);
    CPy_DecRef(cpy_r_r95);
    goto CPyL62;
}

PyObject *CPyPy_numeric___scale_places(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"places", 0};
    static CPyArg_Parser parser = {"O:scale_places", kwlist, 0};
    PyObject *obj_places;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_places)) {
        return NULL;
    }
    CPyTagged arg_places;
    if (likely(PyLong_Check(obj_places)))
        arg_places = CPyTagged_BorrowFromObject(obj_places);
    else {
        CPy_TypeError("int", obj_places); goto fail;
    }
    PyObject *retval = CPyDef_numeric___scale_places(arg_places);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "scale_places", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
    return NULL;
}

char CPyDef_numeric_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject **cpy_r_r5;
    void *cpy_r_r7;
    void *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    char cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject *cpy_r_r20;
    PyObject *cpy_r_r21;
    int32_t cpy_r_r22;
    char cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject **cpy_r_r29;
    PyObject *cpy_r_r30;
    PyObject *cpy_r_r31;
    PyObject *cpy_r_r32;
    PyObject *cpy_r_r33;
    int32_t cpy_r_r34;
    char cpy_r_r35;
    PyObject *cpy_r_r36;
    PyObject *cpy_r_r37;
    PyObject *cpy_r_r38;
    PyObject *cpy_r_r39;
    PyObject *cpy_r_r40;
    int32_t cpy_r_r41;
    char cpy_r_r42;
    PyObject *cpy_r_r43;
    PyObject *cpy_r_r44;
    PyObject *cpy_r_r45;
    PyObject *cpy_r_r46;
    PyObject **cpy_r_r48;
    PyObject *cpy_r_r49;
    PyObject *cpy_r_r50;
    PyObject *cpy_r_r51;
    int32_t cpy_r_r52;
    char cpy_r_r53;
    PyObject *cpy_r_r54;
    PyObject *cpy_r_r55;
    PyObject *cpy_r_r56;
    PyObject *cpy_r_r57;
    PyObject **cpy_r_r59;
    PyObject *cpy_r_r60;
    PyObject *cpy_r_r61;
    PyObject *cpy_r_r62;
    int32_t cpy_r_r63;
    char cpy_r_r64;
    PyObject *cpy_r_r65;
    PyObject *cpy_r_r66;
    PyObject *cpy_r_r67;
    PyObject *cpy_r_r68;
    PyObject *cpy_r_r69;
    int32_t cpy_r_r70;
    char cpy_r_r71;
    PyObject *cpy_r_r72;
    PyObject *cpy_r_r73;
    PyObject *cpy_r_r74;
    int32_t cpy_r_r75;
    char cpy_r_r76;
    PyObject *cpy_r_r77;
    PyObject *cpy_r_r78;
    PyObject *cpy_r_r79;
    int32_t cpy_r_r80;
    char cpy_r_r81;
    PyObject *cpy_r_r82;
    PyObject *cpy_r_r83;
    PyObject *cpy_r_r84;
    int32_t cpy_r_r85;
    char cpy_r_r86;
    PyObject *cpy_r_r87;
    PyObject *cpy_r_r88;
    PyObject *cpy_r_r89;
    int32_t cpy_r_r90;
    char cpy_r_r91;
    char cpy_r_r92;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", -1, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = (PyObject **)&CPyModule_decimal;
    PyObject **cpy_r_r6[1] = {cpy_r_r5};
    cpy_r_r7 = (void *)&cpy_r_r6;
    int64_t cpy_r_r8[1] = {1};
    cpy_r_r9 = (void *)&cpy_r_r8;
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* (('decimal', 'decimal', 'decimal'),) */
    cpy_r_r11 = CPyStatic_numeric___globals;
    cpy_r_r12 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'faster_eth_abi/utils/numeric.py' */
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '<module>' */
    cpy_r_r14 = CPyImport_ImportMany(cpy_r_r10, cpy_r_r7, cpy_r_r11, cpy_r_r12, cpy_r_r13, cpy_r_r9);
    if (!cpy_r_r14) goto CPyL28;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Callable', 'Dict', 'Final', 'Tuple') */
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r17 = CPyStatic_numeric___globals;
    cpy_r_r18 = CPyImport_ImportFromMany(cpy_r_r16, cpy_r_r15, cpy_r_r15, cpy_r_r17);
    if (unlikely(cpy_r_r18 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyModule_typing = cpy_r_r18;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r18);
    cpy_r_r19 = CPyStatic_numeric___globals;
    cpy_r_r20 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ABI_DECIMAL_PREC' */
    cpy_r_r21 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 999 */
    cpy_r_r22 = CPyDict_SetItem(cpy_r_r19, cpy_r_r20, cpy_r_r21);
    cpy_r_r23 = cpy_r_r22 >= 0;
    if (unlikely(!cpy_r_r23)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r24 = CPyModule_decimal;
    cpy_r_r25 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Context' */
    cpy_r_r26 = CPyObject_GetAttr(cpy_r_r24, cpy_r_r25);
    if (unlikely(cpy_r_r26 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r27 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 999 */
    PyObject *cpy_r_r28[1] = {cpy_r_r27};
    cpy_r_r29 = (PyObject **)&cpy_r_r28;
    cpy_r_r30 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('prec',) */
    cpy_r_r31 = PyObject_Vectorcall(cpy_r_r26, cpy_r_r29, 0, cpy_r_r30);
    CPy_DECREF(cpy_r_r26);
    if (unlikely(cpy_r_r31 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric___abi_decimal_context = cpy_r_r31;
    CPy_INCREF(CPyStatic_numeric___abi_decimal_context);
    cpy_r_r32 = CPyStatic_numeric___globals;
    cpy_r_r33 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'abi_decimal_context' */
    cpy_r_r34 = CPyDict_SetItem(cpy_r_r32, cpy_r_r33, cpy_r_r31);
    CPy_DECREF(cpy_r_r31);
    cpy_r_r35 = cpy_r_r34 >= 0;
    if (unlikely(!cpy_r_r35)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r36 = CPyModule_decimal;
    cpy_r_r37 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'localcontext' */
    cpy_r_r38 = CPyObject_GetAttr(cpy_r_r36, cpy_r_r37);
    if (unlikely(cpy_r_r38 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric___decimal_localcontext = cpy_r_r38;
    CPy_INCREF(CPyStatic_numeric___decimal_localcontext);
    cpy_r_r39 = CPyStatic_numeric___globals;
    cpy_r_r40 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decimal_localcontext' */
    cpy_r_r41 = CPyDict_SetItem(cpy_r_r39, cpy_r_r40, cpy_r_r38);
    CPy_DECREF(cpy_r_r38);
    cpy_r_r42 = cpy_r_r41 >= 0;
    if (unlikely(!cpy_r_r42)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r43 = CPyModule_decimal;
    cpy_r_r44 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Decimal' */
    cpy_r_r45 = CPyObject_GetAttr(cpy_r_r43, cpy_r_r44);
    if (unlikely(cpy_r_r45 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r46 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 0 */
    PyObject *cpy_r_r47[1] = {cpy_r_r46};
    cpy_r_r48 = (PyObject **)&cpy_r_r47;
    cpy_r_r49 = PyObject_Vectorcall(cpy_r_r45, cpy_r_r48, 1, 0);
    CPy_DECREF(cpy_r_r45);
    if (unlikely(cpy_r_r49 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric___ZERO = cpy_r_r49;
    CPy_INCREF(CPyStatic_numeric___ZERO);
    cpy_r_r50 = CPyStatic_numeric___globals;
    cpy_r_r51 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ZERO' */
    cpy_r_r52 = CPyDict_SetItem(cpy_r_r50, cpy_r_r51, cpy_r_r49);
    CPy_DECREF(cpy_r_r49);
    cpy_r_r53 = cpy_r_r52 >= 0;
    if (unlikely(!cpy_r_r53)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r54 = CPyModule_decimal;
    cpy_r_r55 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Decimal' */
    cpy_r_r56 = CPyObject_GetAttr(cpy_r_r54, cpy_r_r55);
    if (unlikely(cpy_r_r56 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r57 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 10 */
    PyObject *cpy_r_r58[1] = {cpy_r_r57};
    cpy_r_r59 = (PyObject **)&cpy_r_r58;
    cpy_r_r60 = PyObject_Vectorcall(cpy_r_r56, cpy_r_r59, 1, 0);
    CPy_DECREF(cpy_r_r56);
    if (unlikely(cpy_r_r60 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric___TEN = cpy_r_r60;
    CPy_INCREF(CPyStatic_numeric___TEN);
    cpy_r_r61 = CPyStatic_numeric___globals;
    cpy_r_r62 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TEN' */
    cpy_r_r63 = CPyDict_SetItem(cpy_r_r61, cpy_r_r62, cpy_r_r60);
    CPy_DECREF(cpy_r_r60);
    cpy_r_r64 = cpy_r_r63 >= 0;
    if (unlikely(!cpy_r_r64)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r65 = CPyModule_decimal;
    cpy_r_r66 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Decimal' */
    cpy_r_r67 = CPyObject_GetAttr(cpy_r_r65, cpy_r_r66);
    if (unlikely(cpy_r_r67 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric___Decimal = cpy_r_r67;
    CPy_INCREF(CPyStatic_numeric___Decimal);
    cpy_r_r68 = CPyStatic_numeric___globals;
    cpy_r_r69 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Decimal' */
    cpy_r_r70 = CPyDict_SetItem(cpy_r_r68, cpy_r_r69, cpy_r_r67);
    CPy_DECREF(cpy_r_r67);
    cpy_r_r71 = cpy_r_r70 >= 0;
    if (unlikely(!cpy_r_r71)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r72 = PyDict_New();
    if (unlikely(cpy_r_r72 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric____unsigned_integer_bounds_cache = cpy_r_r72;
    CPy_INCREF(CPyStatic_numeric____unsigned_integer_bounds_cache);
    cpy_r_r73 = CPyStatic_numeric___globals;
    cpy_r_r74 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_unsigned_integer_bounds_cache' */
    cpy_r_r75 = CPyDict_SetItem(cpy_r_r73, cpy_r_r74, cpy_r_r72);
    CPy_DECREF(cpy_r_r72);
    cpy_r_r76 = cpy_r_r75 >= 0;
    if (unlikely(!cpy_r_r76)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r77 = PyDict_New();
    if (unlikely(cpy_r_r77 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric____signed_integer_bounds_cache = cpy_r_r77;
    CPy_INCREF(CPyStatic_numeric____signed_integer_bounds_cache);
    cpy_r_r78 = CPyStatic_numeric___globals;
    cpy_r_r79 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_signed_integer_bounds_cache' */
    cpy_r_r80 = CPyDict_SetItem(cpy_r_r78, cpy_r_r79, cpy_r_r77);
    CPy_DECREF(cpy_r_r77);
    cpy_r_r81 = cpy_r_r80 >= 0;
    if (unlikely(!cpy_r_r81)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r82 = PyDict_New();
    if (unlikely(cpy_r_r82 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric____unsigned_fixed_bounds_cache = cpy_r_r82;
    CPy_INCREF(CPyStatic_numeric____unsigned_fixed_bounds_cache);
    cpy_r_r83 = CPyStatic_numeric___globals;
    cpy_r_r84 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_unsigned_fixed_bounds_cache' */
    cpy_r_r85 = CPyDict_SetItem(cpy_r_r83, cpy_r_r84, cpy_r_r82);
    CPy_DECREF(cpy_r_r82);
    cpy_r_r86 = cpy_r_r85 >= 0;
    if (unlikely(!cpy_r_r86)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    cpy_r_r87 = PyDict_New();
    if (unlikely(cpy_r_r87 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    CPyStatic_numeric____signed_fixed_bounds_cache = cpy_r_r87;
    CPy_INCREF(CPyStatic_numeric____signed_fixed_bounds_cache);
    cpy_r_r88 = CPyStatic_numeric___globals;
    cpy_r_r89 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '_signed_fixed_bounds_cache' */
    cpy_r_r90 = CPyDict_SetItem(cpy_r_r88, cpy_r_r89, cpy_r_r87);
    CPy_DECREF(cpy_r_r87);
    cpy_r_r91 = cpy_r_r90 >= 0;
    if (unlikely(!cpy_r_r91)) {
        CPy_AddTraceback("faster_eth_abi/utils/numeric.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_numeric___globals);
        goto CPyL28;
    }
    return 1;
CPyL28: ;
    cpy_r_r92 = 2;
    return cpy_r_r92;
}
static PyMethodDef paddingmodule_methods[] = {
    {"zpad", (PyCFunction)CPyPy_padding___zpad, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("zpad(value, length)\n--\n\n") /* docstring */},
    {"zpad32", (PyCFunction)CPyPy_padding___zpad32, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("zpad32(value)\n--\n\n") /* docstring */},
    {"zpad_right", (PyCFunction)CPyPy_padding___zpad_right, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("zpad_right(value, length)\n--\n\n") /* docstring */},
    {"zpad32_right", (PyCFunction)CPyPy_padding___zpad32_right, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("zpad32_right(value)\n--\n\n") /* docstring */},
    {"fpad", (PyCFunction)CPyPy_padding___fpad, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("fpad(value, length)\n--\n\n") /* docstring */},
    {"fpad32", (PyCFunction)CPyPy_padding___fpad32, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("fpad32(value)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___utils___padding(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___utils___padding__internal, "__name__");
    CPyStatic_padding___globals = PyModule_GetDict(CPyModule_faster_eth_abi___utils___padding__internal);
    if (unlikely(CPyStatic_padding___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_padding_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___utils___padding__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef paddingmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.utils.padding",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    paddingmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___utils___padding(void)
{
    if (CPyModule_faster_eth_abi___utils___padding__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___utils___padding__internal);
        return CPyModule_faster_eth_abi___utils___padding__internal;
    }
    CPyModule_faster_eth_abi___utils___padding__internal = PyModule_Create(&paddingmodule);
    if (unlikely(CPyModule_faster_eth_abi___utils___padding__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___utils___padding(CPyModule_faster_eth_abi___utils___padding__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___utils___padding__internal;
    fail:
    return NULL;
}

PyObject *CPyDef_padding___zpad(PyObject *cpy_r_value, CPyTagged cpy_r_length) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'rjust' */
    CPyTagged_INCREF(cpy_r_length);
    cpy_r_r2 = CPyTagged_StealAsObject(cpy_r_length);
    PyObject *cpy_r_r3[3] = {cpy_r_value, cpy_r_r2, cpy_r_r0};
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r4, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
        goto CPyL4;
    }
    CPy_DECREF(cpy_r_r2);
    if (likely(PyBytes_Check(cpy_r_r5) || PyByteArray_Check(cpy_r_r5)))
        cpy_r_r6 = cpy_r_r5;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/utils/padding.py", "zpad", 2, CPyStatic_padding___globals, "bytes", cpy_r_r5);
        goto CPyL3;
    }
    return cpy_r_r6;
CPyL3: ;
    cpy_r_r7 = NULL;
    return cpy_r_r7;
CPyL4: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL3;
}

PyObject *CPyPy_padding___zpad(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", "length", 0};
    static CPyArg_Parser parser = {"OO:zpad", kwlist, 0};
    PyObject *obj_value;
    PyObject *obj_length;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_value, &obj_length)) {
        return NULL;
    }
    PyObject *arg_value;
    if (likely(PyBytes_Check(obj_value) || PyByteArray_Check(obj_value)))
        arg_value = obj_value;
    else {
        CPy_TypeError("bytes", obj_value); 
        goto fail;
    }
    CPyTagged arg_length;
    if (likely(PyLong_Check(obj_length)))
        arg_length = CPyTagged_BorrowFromObject(obj_length);
    else {
        CPy_TypeError("int", obj_length); goto fail;
    }
    PyObject *retval = CPyDef_padding___zpad(arg_value, arg_length);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
    return NULL;
}

PyObject *CPyDef_padding___zpad32(PyObject *cpy_r_value) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    cpy_r_r0 = CPyDef_padding___zpad(cpy_r_value, 64);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad32", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
        goto CPyL2;
    }
    return cpy_r_r0;
CPyL2: ;
    cpy_r_r1 = NULL;
    return cpy_r_r1;
}

PyObject *CPyPy_padding___zpad32(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", 0};
    static CPyArg_Parser parser = {"O:zpad32", kwlist, 0};
    PyObject *obj_value;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_value)) {
        return NULL;
    }
    PyObject *arg_value;
    if (likely(PyBytes_Check(obj_value) || PyByteArray_Check(obj_value)))
        arg_value = obj_value;
    else {
        CPy_TypeError("bytes", obj_value); 
        goto fail;
    }
    PyObject *retval = CPyDef_padding___zpad32(arg_value);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad32", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
    return NULL;
}

PyObject *CPyDef_padding___zpad_right(PyObject *cpy_r_value, CPyTagged cpy_r_length) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\x00' */
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ljust' */
    CPyTagged_INCREF(cpy_r_length);
    cpy_r_r2 = CPyTagged_StealAsObject(cpy_r_length);
    PyObject *cpy_r_r3[3] = {cpy_r_value, cpy_r_r2, cpy_r_r0};
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r4, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad_right", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
        goto CPyL4;
    }
    CPy_DECREF(cpy_r_r2);
    if (likely(PyBytes_Check(cpy_r_r5) || PyByteArray_Check(cpy_r_r5)))
        cpy_r_r6 = cpy_r_r5;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/utils/padding.py", "zpad_right", 10, CPyStatic_padding___globals, "bytes", cpy_r_r5);
        goto CPyL3;
    }
    return cpy_r_r6;
CPyL3: ;
    cpy_r_r7 = NULL;
    return cpy_r_r7;
CPyL4: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL3;
}

PyObject *CPyPy_padding___zpad_right(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", "length", 0};
    static CPyArg_Parser parser = {"OO:zpad_right", kwlist, 0};
    PyObject *obj_value;
    PyObject *obj_length;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_value, &obj_length)) {
        return NULL;
    }
    PyObject *arg_value;
    if (likely(PyBytes_Check(obj_value) || PyByteArray_Check(obj_value)))
        arg_value = obj_value;
    else {
        CPy_TypeError("bytes", obj_value); 
        goto fail;
    }
    CPyTagged arg_length;
    if (likely(PyLong_Check(obj_length)))
        arg_length = CPyTagged_BorrowFromObject(obj_length);
    else {
        CPy_TypeError("int", obj_length); goto fail;
    }
    PyObject *retval = CPyDef_padding___zpad_right(arg_value, arg_length);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad_right", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
    return NULL;
}

PyObject *CPyDef_padding___zpad32_right(PyObject *cpy_r_value) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    cpy_r_r0 = CPyDef_padding___zpad_right(cpy_r_value, 64);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad32_right", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
        goto CPyL2;
    }
    return cpy_r_r0;
CPyL2: ;
    cpy_r_r1 = NULL;
    return cpy_r_r1;
}

PyObject *CPyPy_padding___zpad32_right(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", 0};
    static CPyArg_Parser parser = {"O:zpad32_right", kwlist, 0};
    PyObject *obj_value;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_value)) {
        return NULL;
    }
    PyObject *arg_value;
    if (likely(PyBytes_Check(obj_value) || PyByteArray_Check(obj_value)))
        arg_value = obj_value;
    else {
        CPy_TypeError("bytes", obj_value); 
        goto fail;
    }
    PyObject *retval = CPyDef_padding___zpad32_right(arg_value);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/padding.py", "zpad32_right", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
    return NULL;
}

PyObject *CPyDef_padding___fpad(PyObject *cpy_r_value, CPyTagged cpy_r_length) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject **cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    cpy_r_r0 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* b'\xff' */
    cpy_r_r1 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'rjust' */
    CPyTagged_INCREF(cpy_r_length);
    cpy_r_r2 = CPyTagged_StealAsObject(cpy_r_length);
    PyObject *cpy_r_r3[3] = {cpy_r_value, cpy_r_r2, cpy_r_r0};
    cpy_r_r4 = (PyObject **)&cpy_r_r3;
    cpy_r_r5 = PyObject_VectorcallMethod(cpy_r_r1, cpy_r_r4, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r5 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "fpad", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
        goto CPyL4;
    }
    CPy_DECREF(cpy_r_r2);
    if (likely(PyBytes_Check(cpy_r_r5) || PyByteArray_Check(cpy_r_r5)))
        cpy_r_r6 = cpy_r_r5;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/utils/padding.py", "fpad", 18, CPyStatic_padding___globals, "bytes", cpy_r_r5);
        goto CPyL3;
    }
    return cpy_r_r6;
CPyL3: ;
    cpy_r_r7 = NULL;
    return cpy_r_r7;
CPyL4: ;
    CPy_DecRef(cpy_r_r2);
    goto CPyL3;
}

PyObject *CPyPy_padding___fpad(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", "length", 0};
    static CPyArg_Parser parser = {"OO:fpad", kwlist, 0};
    PyObject *obj_value;
    PyObject *obj_length;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_value, &obj_length)) {
        return NULL;
    }
    PyObject *arg_value;
    if (likely(PyBytes_Check(obj_value) || PyByteArray_Check(obj_value)))
        arg_value = obj_value;
    else {
        CPy_TypeError("bytes", obj_value); 
        goto fail;
    }
    CPyTagged arg_length;
    if (likely(PyLong_Check(obj_length)))
        arg_length = CPyTagged_BorrowFromObject(obj_length);
    else {
        CPy_TypeError("int", obj_length); goto fail;
    }
    PyObject *retval = CPyDef_padding___fpad(arg_value, arg_length);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/padding.py", "fpad", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
    return NULL;
}

PyObject *CPyDef_padding___fpad32(PyObject *cpy_r_value) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    cpy_r_r0 = CPyDef_padding___fpad(cpy_r_value, 64);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "fpad32", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
        goto CPyL2;
    }
    return cpy_r_r0;
CPyL2: ;
    cpy_r_r1 = NULL;
    return cpy_r_r1;
}

PyObject *CPyPy_padding___fpad32(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", 0};
    static CPyArg_Parser parser = {"O:fpad32", kwlist, 0};
    PyObject *obj_value;
    if (!CPyArg_ParseStackAndKeywordsOneArg(args, nargs, kwnames, &parser, &obj_value)) {
        return NULL;
    }
    PyObject *arg_value;
    if (likely(PyBytes_Check(obj_value) || PyByteArray_Check(obj_value)))
        arg_value = obj_value;
    else {
        CPy_TypeError("bytes", obj_value); 
        goto fail;
    }
    PyObject *retval = CPyDef_padding___fpad32(arg_value);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/padding.py", "fpad32", DIFFCHECK_PLACEHOLDER, CPyStatic_padding___globals);
    return NULL;
}

char CPyDef_padding_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    char cpy_r_r5;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/padding.py", "<module>", -1, CPyStatic_padding___globals);
        goto CPyL4;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    return 1;
CPyL4: ;
    cpy_r_r5 = 2;
    return cpy_r_r5;
}
static PyMethodDef stringmodule_methods[] = {
    {"abbr", (PyCFunction)CPyPy_string___abbr, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("abbr(value, limit=79)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___utils___string(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___utils___string__internal, "__name__");
    CPyStatic_string___globals = PyModule_GetDict(CPyModule_faster_eth_abi___utils___string__internal);
    if (unlikely(CPyStatic_string___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_string_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___utils___string__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef stringmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.utils.string",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    stringmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___utils___string(void)
{
    if (CPyModule_faster_eth_abi___utils___string__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___utils___string__internal);
        return CPyModule_faster_eth_abi___utils___string__internal;
    }
    CPyModule_faster_eth_abi___utils___string__internal = PyModule_Create(&stringmodule);
    if (unlikely(CPyModule_faster_eth_abi___utils___string__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___utils___string(CPyModule_faster_eth_abi___utils___string__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___utils___string__internal;
    fail:
    return NULL;
}

PyObject *CPyDef_string___abbr(PyObject *cpy_r_value, CPyTagged cpy_r_limit) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_rep;
    int64_t cpy_r_r1;
    char cpy_r_r2;
    CPyTagged cpy_r_r3;
    int64_t cpy_r_r4;
    char cpy_r_r5;
    int64_t cpy_r_r6;
    char cpy_r_r7;
    char cpy_r_r8;
    char cpy_r_r9;
    int64_t cpy_r_r10;
    char cpy_r_r11;
    int64_t cpy_r_r12;
    char cpy_r_r13;
    char cpy_r_r14;
    char cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject *cpy_r_r17;
    PyObject *cpy_r_r18;
    PyObject *cpy_r_r19;
    PyObject **cpy_r_r21;
    PyObject *cpy_r_r22;
    CPyTagged cpy_r_r23;
    PyObject *cpy_r_r24;
    PyObject *cpy_r_r25;
    PyObject *cpy_r_r26;
    PyObject *cpy_r_r27;
    PyObject *cpy_r_r28;
    if (cpy_r_limit != CPY_INT_TAG) goto CPyL22;
    cpy_r_limit = 158;
CPyL2: ;
    cpy_r_r0 = PyObject_Repr(cpy_r_value);
    if (unlikely(cpy_r_r0 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL23;
    }
    cpy_r_rep = cpy_r_r0;
    cpy_r_r1 = CPyStr_Size_size_t(cpy_r_rep);
    cpy_r_r2 = cpy_r_r1 >= 0;
    if (unlikely(!cpy_r_r2)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL24;
    }
    cpy_r_r3 = cpy_r_r1 << 1;
    cpy_r_r4 = cpy_r_r3 & 1;
    cpy_r_r5 = cpy_r_r4 != 0;
    if (cpy_r_r5) goto CPyL6;
    cpy_r_r6 = cpy_r_limit & 1;
    cpy_r_r7 = cpy_r_r6 != 0;
    if (!cpy_r_r7) goto CPyL7;
CPyL6: ;
    cpy_r_r8 = CPyTagged_IsLt_(cpy_r_limit, cpy_r_r3);
    if (cpy_r_r8) {
        goto CPyL8;
    } else
        goto CPyL25;
CPyL7: ;
    cpy_r_r9 = (Py_ssize_t)cpy_r_r3 > (Py_ssize_t)cpy_r_limit;
    if (!cpy_r_r9) goto CPyL25;
CPyL8: ;
    cpy_r_r10 = cpy_r_limit & 1;
    cpy_r_r11 = cpy_r_r10 != 0;
    if (cpy_r_r11) goto CPyL10;
    cpy_r_r12 = 6 & 1;
    cpy_r_r13 = cpy_r_r12 != 0;
    if (!cpy_r_r13) goto CPyL11;
CPyL10: ;
    cpy_r_r14 = CPyTagged_IsLt_(cpy_r_limit, 6);
    if (cpy_r_r14) {
        goto CPyL26;
    } else
        goto CPyL16;
CPyL11: ;
    cpy_r_r15 = (Py_ssize_t)cpy_r_limit < (Py_ssize_t)6;
    if (cpy_r_r15) {
        goto CPyL26;
    } else
        goto CPyL16;
CPyL12: ;
    cpy_r_r16 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'Abbreviation limit may not be less than 3' */
    cpy_r_r17 = CPyModule_builtins;
    cpy_r_r18 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'ValueError' */
    cpy_r_r19 = CPyObject_GetAttr(cpy_r_r17, cpy_r_r18);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL21;
    }
    PyObject *cpy_r_r20[1] = {cpy_r_r16};
    cpy_r_r21 = (PyObject **)&cpy_r_r20;
    cpy_r_r22 = PyObject_Vectorcall(cpy_r_r19, cpy_r_r21, 1, 0);
    CPy_DECREF(cpy_r_r19);
    if (unlikely(cpy_r_r22 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL21;
    }
    CPy_Raise(cpy_r_r22);
    CPy_DECREF(cpy_r_r22);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL21;
    }
    CPy_Unreachable();
CPyL16: ;
    cpy_r_r23 = CPyTagged_Subtract(cpy_r_limit, 6);
    CPyTagged_DECREF(cpy_r_limit);
    cpy_r_r24 = CPyStr_GetSlice(cpy_r_rep, 0, cpy_r_r23);
    CPy_DECREF(cpy_r_rep);
    CPyTagged_DECREF(cpy_r_r23);
    if (unlikely(cpy_r_r24 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL21;
    }
    if (likely(PyUnicode_Check(cpy_r_r24)))
        cpy_r_r25 = cpy_r_r24;
    else {
        CPy_TypeErrorTraceback("faster_eth_abi/utils/string.py", "abbr", 17, CPyStatic_string___globals, "str", cpy_r_r24);
        goto CPyL21;
    }
    cpy_r_r26 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '...' */
    cpy_r_r27 = PyUnicode_Concat(cpy_r_r25, cpy_r_r26);
    CPy_DECREF(cpy_r_r25);
    if (unlikely(cpy_r_r27 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL21;
    }
    cpy_r_rep = cpy_r_r27;
CPyL20: ;
    return cpy_r_rep;
CPyL21: ;
    cpy_r_r28 = NULL;
    return cpy_r_r28;
CPyL22: ;
    CPyTagged_INCREF(cpy_r_limit);
    goto CPyL2;
CPyL23: ;
    CPyTagged_DecRef(cpy_r_limit);
    goto CPyL21;
CPyL24: ;
    CPyTagged_DecRef(cpy_r_limit);
    CPy_DecRef(cpy_r_rep);
    goto CPyL21;
CPyL25: ;
    CPyTagged_DECREF(cpy_r_limit);
    goto CPyL20;
CPyL26: ;
    CPyTagged_DECREF(cpy_r_limit);
    CPy_DECREF(cpy_r_rep);
    goto CPyL12;
}

PyObject *CPyPy_string___abbr(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"value", "limit", 0};
    static CPyArg_Parser parser = {"O|O:abbr", kwlist, 0};
    PyObject *obj_value;
    PyObject *obj_limit = NULL;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_value, &obj_limit)) {
        return NULL;
    }
    PyObject *arg_value = obj_value;
    CPyTagged arg_limit;
    if (obj_limit == NULL) {
        arg_limit = CPY_INT_TAG;
    } else if (likely(PyLong_Check(obj_limit)))
        arg_limit = CPyTagged_BorrowFromObject(obj_limit);
    else {
        CPy_TypeError("int", obj_limit); goto fail;
    }
    PyObject *retval = CPyDef_string___abbr(arg_value, arg_limit);
    return retval;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/string.py", "abbr", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
    return NULL;
}

char CPyDef_string_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "<module>", -1, CPyStatic_string___globals);
        goto CPyL5;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Any',) */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic_string___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/string.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_string___globals);
        goto CPyL5;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    return 1;
CPyL5: ;
    cpy_r_r9 = 2;
    return cpy_r_r9;
}
static PyMethodDef validationmodule_methods[] = {
    {"validate_bytes_param", (PyCFunction)CPyPy_validation___validate_bytes_param, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate_bytes_param(param, param_name)\n--\n\n") /* docstring */},
    {"validate_list_like_param", (PyCFunction)CPyPy_validation___validate_list_like_param, METH_FASTCALL | METH_KEYWORDS, PyDoc_STR("validate_list_like_param(param, param_name)\n--\n\n") /* docstring */},
    {NULL, NULL, 0, NULL}
};

int CPyExec_faster_eth_abi___utils___validation(PyObject *module)
{
    PyObject* modname = NULL;
    modname = PyObject_GetAttrString((PyObject *)CPyModule_faster_eth_abi___utils___validation__internal, "__name__");
    CPyStatic_validation___globals = PyModule_GetDict(CPyModule_faster_eth_abi___utils___validation__internal);
    if (unlikely(CPyStatic_validation___globals == NULL))
        goto fail;
    if (CPyGlobalsInit() < 0)
        goto fail;
    char result = CPyDef_validation_____top_level__();
    if (result == 2)
        goto fail;
    Py_DECREF(modname);
    return 0;
    fail:
    Py_CLEAR(CPyModule_faster_eth_abi___utils___validation__internal);
    Py_CLEAR(modname);
    return -1;
}
static struct PyModuleDef validationmodule = {
    PyModuleDef_HEAD_INIT,
    "faster_eth_abi.utils.validation",
    NULL, /* docstring */
    0,       /* size of per-interpreter state of the module */
    validationmodule_methods,
    NULL,
};

PyObject *CPyInit_faster_eth_abi___utils___validation(void)
{
    if (CPyModule_faster_eth_abi___utils___validation__internal) {
        Py_INCREF(CPyModule_faster_eth_abi___utils___validation__internal);
        return CPyModule_faster_eth_abi___utils___validation__internal;
    }
    CPyModule_faster_eth_abi___utils___validation__internal = PyModule_Create(&validationmodule);
    if (unlikely(CPyModule_faster_eth_abi___utils___validation__internal == NULL))
        goto fail;
    if (CPyExec_faster_eth_abi___utils___validation(CPyModule_faster_eth_abi___utils___validation__internal) != 0)
        goto fail;
    return CPyModule_faster_eth_abi___utils___validation__internal;
    fail:
    return NULL;
}

char CPyDef_validation___validate_bytes_param(PyObject *cpy_r_param, PyObject *cpy_r_param_name) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    PyObject *cpy_r_r2;
    PyObject *cpy_r_r3;
    tuple_T2OO cpy_r_r4;
    PyObject *cpy_r_r5;
    int32_t cpy_r_r6;
    char cpy_r_r7;
    char cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject *cpy_r_r15;
    PyObject *cpy_r_r16;
    PyObject **cpy_r_r18;
    PyObject *cpy_r_r19;
    char cpy_r_r20;
    cpy_r_r0 = (PyObject *)&PyBytes_Type;
    cpy_r_r1 = CPyModule_builtins;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytearray' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_r1, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    CPy_INCREF(cpy_r_r0);
    cpy_r_r4.f0 = cpy_r_r0;
    cpy_r_r4.f1 = cpy_r_r3;
    cpy_r_r5 = PyTuple_New(2);
    if (unlikely(cpy_r_r5 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp132 = cpy_r_r4.f0;
    PyTuple_SET_ITEM(cpy_r_r5, 0, __tmp132);
    PyObject *__tmp133 = cpy_r_r4.f1;
    PyTuple_SET_ITEM(cpy_r_r5, 1, __tmp133);
    cpy_r_r6 = PyObject_IsInstance(cpy_r_param, cpy_r_r5);
    CPy_DECREF(cpy_r_r5);
    cpy_r_r7 = cpy_r_r6 >= 0;
    if (unlikely(!cpy_r_r7)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    cpy_r_r8 = cpy_r_r6;
    if (cpy_r_r8) goto CPyL9;
    cpy_r_r9 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'The `' */
    cpy_r_r10 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '` value must be of bytes type. Got ' */
    cpy_r_r11 = CPy_TYPE(cpy_r_param);
    cpy_r_r12 = PyObject_Str(cpy_r_r11);
    CPy_DECREF(cpy_r_r11);
    if (unlikely(cpy_r_r12 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    cpy_r_r13 = CPyStr_Build(4, cpy_r_r9, cpy_r_param_name, cpy_r_r10, cpy_r_r12);
    CPy_DECREF(cpy_r_r12);
    if (unlikely(cpy_r_r13 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    cpy_r_r14 = CPyModule_builtins;
    cpy_r_r15 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TypeError' */
    cpy_r_r16 = CPyObject_GetAttr(cpy_r_r14, cpy_r_r15);
    if (unlikely(cpy_r_r16 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL11;
    }
    PyObject *cpy_r_r17[1] = {cpy_r_r13};
    cpy_r_r18 = (PyObject **)&cpy_r_r17;
    cpy_r_r19 = PyObject_Vectorcall(cpy_r_r16, cpy_r_r18, 1, 0);
    CPy_DECREF(cpy_r_r16);
    if (unlikely(cpy_r_r19 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL11;
    }
    CPy_DECREF(cpy_r_r13);
    CPy_Raise(cpy_r_r19);
    CPy_DECREF(cpy_r_r19);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    CPy_Unreachable();
CPyL9: ;
    return 1;
CPyL10: ;
    cpy_r_r20 = 2;
    return cpy_r_r20;
CPyL11: ;
    CPy_DecRef(cpy_r_r13);
    goto CPyL10;
}

PyObject *CPyPy_validation___validate_bytes_param(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"param", "param_name", 0};
    static CPyArg_Parser parser = {"OO:validate_bytes_param", kwlist, 0};
    PyObject *obj_param;
    PyObject *obj_param_name;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_param, &obj_param_name)) {
        return NULL;
    }
    PyObject *arg_param = obj_param;
    PyObject *arg_param_name;
    if (likely(PyUnicode_Check(obj_param_name)))
        arg_param_name = obj_param_name;
    else {
        CPy_TypeError("str", obj_param_name); 
        goto fail;
    }
    char retval = CPyDef_validation___validate_bytes_param(arg_param, arg_param_name);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_bytes_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
    return NULL;
}

char CPyDef_validation___validate_list_like_param(PyObject *cpy_r_param, PyObject *cpy_r_param_name) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    tuple_T2OO cpy_r_r2;
    PyObject *cpy_r_r3;
    int32_t cpy_r_r4;
    char cpy_r_r5;
    char cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    PyObject *cpy_r_r9;
    PyObject *cpy_r_r10;
    PyObject *cpy_r_r11;
    PyObject *cpy_r_r12;
    PyObject *cpy_r_r13;
    PyObject *cpy_r_r14;
    PyObject **cpy_r_r16;
    PyObject *cpy_r_r17;
    char cpy_r_r18;
    cpy_r_r0 = (PyObject *)&PyList_Type;
    cpy_r_r1 = (PyObject *)&PyTuple_Type;
    CPy_INCREF(cpy_r_r0);
    CPy_INCREF(cpy_r_r1);
    cpy_r_r2.f0 = cpy_r_r0;
    cpy_r_r2.f1 = cpy_r_r1;
    cpy_r_r3 = PyTuple_New(2);
    if (unlikely(cpy_r_r3 == NULL))
        CPyError_OutOfMemory();
    PyObject *__tmp134 = cpy_r_r2.f0;
    PyTuple_SET_ITEM(cpy_r_r3, 0, __tmp134);
    PyObject *__tmp135 = cpy_r_r2.f1;
    PyTuple_SET_ITEM(cpy_r_r3, 1, __tmp135);
    cpy_r_r4 = PyObject_IsInstance(cpy_r_param, cpy_r_r3);
    CPy_DECREF(cpy_r_r3);
    cpy_r_r5 = cpy_r_r4 >= 0;
    if (unlikely(!cpy_r_r5)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL9;
    }
    cpy_r_r6 = cpy_r_r4;
    if (cpy_r_r6) goto CPyL8;
    cpy_r_r7 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'The `' */
    cpy_r_r8 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* '` value type must be one of list or tuple. Got ' */
    cpy_r_r9 = CPy_TYPE(cpy_r_param);
    cpy_r_r10 = PyObject_Str(cpy_r_r9);
    CPy_DECREF(cpy_r_r9);
    if (unlikely(cpy_r_r10 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL9;
    }
    cpy_r_r11 = CPyStr_Build(4, cpy_r_r7, cpy_r_param_name, cpy_r_r8, cpy_r_r10);
    CPy_DECREF(cpy_r_r10);
    if (unlikely(cpy_r_r11 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL9;
    }
    cpy_r_r12 = CPyModule_builtins;
    cpy_r_r13 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'TypeError' */
    cpy_r_r14 = CPyObject_GetAttr(cpy_r_r12, cpy_r_r13);
    if (unlikely(cpy_r_r14 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    PyObject *cpy_r_r15[1] = {cpy_r_r11};
    cpy_r_r16 = (PyObject **)&cpy_r_r15;
    cpy_r_r17 = PyObject_Vectorcall(cpy_r_r14, cpy_r_r16, 1, 0);
    CPy_DECREF(cpy_r_r14);
    if (unlikely(cpy_r_r17 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL10;
    }
    CPy_DECREF(cpy_r_r11);
    CPy_Raise(cpy_r_r17);
    CPy_DECREF(cpy_r_r17);
    if (unlikely(!0)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL9;
    }
    CPy_Unreachable();
CPyL8: ;
    return 1;
CPyL9: ;
    cpy_r_r18 = 2;
    return cpy_r_r18;
CPyL10: ;
    CPy_DecRef(cpy_r_r11);
    goto CPyL9;
}

PyObject *CPyPy_validation___validate_list_like_param(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames) {
    static const char * const kwlist[] = {"param", "param_name", 0};
    static CPyArg_Parser parser = {"OO:validate_list_like_param", kwlist, 0};
    PyObject *obj_param;
    PyObject *obj_param_name;
    if (!CPyArg_ParseStackAndKeywordsSimple(args, nargs, kwnames, &parser, &obj_param, &obj_param_name)) {
        return NULL;
    }
    PyObject *arg_param = obj_param;
    PyObject *arg_param_name;
    if (likely(PyUnicode_Check(obj_param_name)))
        arg_param_name = obj_param_name;
    else {
        CPy_TypeError("str", obj_param_name); 
        goto fail;
    }
    char retval = CPyDef_validation___validate_list_like_param(arg_param, arg_param_name);
    if (retval == 2) {
        return NULL;
    }
    PyObject *retbox = Py_None;
    CPy_INCREF(retbox);
    return retbox;
fail: ;
    CPy_AddTraceback("faster_eth_abi/utils/validation.py", "validate_list_like_param", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
    return NULL;
}

char CPyDef_validation_____top_level__(void) {
    PyObject *cpy_r_r0;
    PyObject *cpy_r_r1;
    char cpy_r_r2;
    PyObject *cpy_r_r3;
    PyObject *cpy_r_r4;
    PyObject *cpy_r_r5;
    PyObject *cpy_r_r6;
    PyObject *cpy_r_r7;
    PyObject *cpy_r_r8;
    char cpy_r_r9;
    cpy_r_r0 = CPyModule_builtins;
    cpy_r_r1 = (PyObject *)&_Py_NoneStruct;
    cpy_r_r2 = cpy_r_r0 != cpy_r_r1;
    if (cpy_r_r2) goto CPyL3;
    cpy_r_r3 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'builtins' */
    cpy_r_r4 = PyImport_Import(cpy_r_r3);
    if (unlikely(cpy_r_r4 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "<module>", -1, CPyStatic_validation___globals);
        goto CPyL5;
    }
    CPyModule_builtins = cpy_r_r4;
    CPy_INCREF(CPyModule_builtins);
    CPy_DECREF(cpy_r_r4);
CPyL3: ;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* ('Any',) */
    cpy_r_r6 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'typing' */
    cpy_r_r7 = CPyStatic_validation___globals;
    cpy_r_r8 = CPyImport_ImportFromMany(cpy_r_r6, cpy_r_r5, cpy_r_r5, cpy_r_r7);
    if (unlikely(cpy_r_r8 == NULL)) {
        CPy_AddTraceback("faster_eth_abi/utils/validation.py", "<module>", DIFFCHECK_PLACEHOLDER, CPyStatic_validation___globals);
        goto CPyL5;
    }
    CPyModule_typing = cpy_r_r8;
    CPy_INCREF(CPyModule_typing);
    CPy_DECREF(cpy_r_r8);
    return 1;
CPyL5: ;
    cpy_r_r9 = 2;
    return cpy_r_r9;
}

int CPyGlobalsInit(void)
{
    static int is_initialized = 0;
    if (is_initialized) return 0;
    
    CPy_Init();
    CPyModule_faster_eth_abi____codec = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_eth_typing = Py_None;
    CPyModule_faster_eth_abi___utils___validation = Py_None;
    CPyModule_faster_eth_abi____decoding = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_utils = Py_None;
    CPyModule_faster_eth_abi___exceptions = Py_None;
    CPyModule_faster_eth_abi___io = Py_None;
    CPyModule_faster_eth_abi____encoding = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_abi____grammar = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_re = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_eth_typing___abi = Py_None;
    CPyModule_mypy_extensions = Py_None;
    CPyModule_parsimonious___nodes = Py_None;
    CPyModule_typing_extensions = Py_None;
    CPyModule_faster_eth_abi___exceptions = Py_None;
    CPyModule_faster_eth_abi___abi = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_abi___codec = Py_None;
    CPyModule_faster_eth_abi___registry = Py_None;
    CPyModule_faster_eth_abi___constants = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_abi___from_type_str = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_functools = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_eth_typing = Py_None;
    CPyModule_faster_eth_abi____grammar = Py_None;
    CPyModule_faster_eth_abi___grammar = Py_None;
    CPyModule_faster_eth_abi___packed = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_abi___codec = Py_None;
    CPyModule_faster_eth_abi___registry = Py_None;
    CPyModule_faster_eth_abi___tools = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_faster_eth_abi___tools____strategies = Py_None;
    CPyModule_faster_eth_abi___tools____strategies = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_cchecksum = Py_None;
    CPyModule_eth_typing___abi = Py_None;
    CPyModule_hypothesis = Py_None;
    CPyModule_faster_eth_abi____grammar = Py_None;
    CPyModule_faster_eth_abi___grammar = Py_None;
    CPyModule_faster_eth_abi___registry = Py_None;
    CPyModule_faster_eth_abi___utils___numeric = Py_None;
    CPyModule_faster_eth_abi___utils = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_faster_eth_abi___utils___numeric = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_decimal = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_abi___utils___padding = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_faster_eth_abi___utils___string = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    CPyModule_faster_eth_abi___utils___validation = Py_None;
    CPyModule_builtins = Py_None;
    CPyModule_typing = Py_None;
    if (CPyStatics_Initialize(CPyStatics, CPyLit_Str, CPyLit_Bytes, CPyLit_Int, CPyLit_Float, CPyLit_Complex, CPyLit_Tuple, CPyLit_FrozenSet) < 0) {
        return -1;
    }
    is_initialized = 1;
    return 0;
}

PyObject *CPyStatics[DIFFCHECK_PLACEHOLDER];
const char * const CPyLit_Str[] = {
    "\006\004args\t_registry\021get_tuple_encoder\004data\021get_tuple_decoder\006strict",
    "\a\fstream_class\bbuiltins\rTYPE_CHECKING\003Any\bIterable\005Tuple\006typing",
    "\004\tDecodable\aTypeStr\neth_typing\024validate_bytes_param",
    "\003\030validate_list_like_param\037faster_eth_abi.utils.validation\004read",
    "\003\021big_endian_to_int!Tried to read 32 bytes, only got \a bytes.",
    "\004\025InsufficientDataBytes\016value_bit_size\npush_frame\ftail_decoder",
    "\005\026`tail_decoder` is None\016AssertionError\tpop_frame\bdecoders\004tell",
    "\004\r_no_head_tail\vlen_of_head\tgetbuffer\r_is_head_tail",
    "\004%Invalid pointer in tuple at location \v in payload\016InvalidPointer\004seek",
    "\002%Invalid pointer in array at location \fitem_decoder",
    "\004\026`item_decoder` is None\narray_size\021validate_pointers\016data_byte_size",
    "\004\016Tried to read \021 bytes, only got \ris_big_endian\000",
    "\004\036Padding bytes were not empty: \a{!r:{}}\006format\024NonEmptyPaddingBytes",
    "\002)Boolean must be either 0x0 or 0x1.  Got: \020faster_eth_utils",
    "\003\031faster_eth_abi.exceptions\aBytesIO\024ContextFramesBytesIO",
    "\a\021faster_eth_abi.io\nis_dynamic\005rjust\005ljust\nbit_length\003big\bto_bytes",
    "\n\bCallable\004List\bOptional\bSequence\aTypeVar\001T\b__init__\004node\001<\005{:{}}",
    "\006\f__qualname__\001 \001>\b__repr__\vto_type_str\006__eq__",
    "\002\034Must implement `to_type_str`\023NotImplementedError",
    "\003\032Must implement `item_type`\titem_type\031Must implement `validate`",
    "\b\bvalidate\005For \'\004text\021\' type at column \005start\005 in \'\tfull_text\003\': ",
    "\004\fABITypeError\ninvalidate\bis_array\033Must implement `is_dynamic`",
    "\006\024_has_dynamic_arrlist\004repr\003map\001(\001,\001)",
    "\004/Cannot determine item type for non-array type \'\001\'\nValueError\aarrlist",
    "\004\001x\006string\005bytes\036string type cannot have suffix",
    "\001;bytes type must have either no suffix or a numerical suffix",
    "\003\'maximum 32 bytes for fixed-length bytes\003int\004uint",
    "\001\'integer type must have numerical suffix",
    "\001)integer size out of bounds (max 256 bits)",
    "\003\"integer size must be multiple of 8\005fixed\006ufixed",
    "\001Bfixed type must have suffix of form <bits>x<exponent>, e.g. 128x19",
    "\001\'fixed size out of bounds (max 256 bits)",
    "\002 fixed size must be multiple of 8#fixed exponent size out of bounds, ",
    "\004\020 must be in 1-80\004hash$hash type must have numerical suffix\aaddress",
    "\005\032address cannot have suffix\v__normalize\003sub\005group\002re",
    "\006\032faster_eth_abi/_grammar.py\b<module>\005Final\aNewType\bNoReturn\005Union",
    "\005\005final\016eth_typing.abi\nmypyc_attr\017mypy_extensions\004Node",
    "\006\022parsimonious.nodes\004Self\021typing_extensions\006int256\auint256\vfixed128x18",
    "\t\fufixed128x18\bfunction\abytes24\004byte\006bytes1\fTYPE_ALIASES\003\\b(\001|\006escape",
    "\006\003)\\b\acompile\rTYPE_ALIAS_RE\nIntSubtype\fFixedSubtype\aSubtype",
    "\005\027faster_eth_abi._grammar\017__mypyc_attrs__\aABIType\005TComp\005bound",
    "\006\ncomponents\tTupleType\004base\tBasicType\bABICodec\024faster_eth_abi.codec",
    "\005\bregistry\027faster_eth_abi.registry\rdefault_codec\006encode\006decode",
    "\006\fis_encodable\021is_encodable_type\005TT256\aTT256M1\005TT255\005parse",
    "\004\020 (normalized to \016Cannot create \024 for non-basic type \n for type ",
    "\001\033: expected type with base \'",
    "\001,: expected type with no array dimension list",
    "\003): expected type with array dimension list\005wraps\021new_from_type_str",
    "\003\vclassmethod\024 for non-tuple type \tfunctools",
    "\004\037faster_eth_abi/from_type_str.py\004Type\tnormalize\026faster_eth_abi.grammar",
    "\005\005TType\tBaseCoder\016OldFromTypeStr\016NewFromTypeStr\nABIEncoder",
    "\003\017registry_packed\026default_encoder_packed\rencode_packed",
    "\003\023is_encodable_packed\020get_abi_strategy faster_eth_abi.tools._strategies",
    "\005\021strategy registry\020PredicateMapping\t_register\005label\v_unregister",
    "\006\021_get_registration\002st\016SearchStrategy\bintegers\tmin_value\tmax_value",
    "\b\bdecimals\006places\006binary\bmin_size\bmax_size\005lists\006tuples\004cast",
    "\005\023to_checksum_address\tcchecksum\nstrategies\nhypothesis\nBaseEquals",
    "\005\fBaseRegistry\006Lookup\vhas_arrlist\ris_base_tuple\fscale_places",
    "\003\034faster_eth_abi.utils.numeric\020StrategyRegistry\017StrategyFactory",
    "\005\024StrategyRegistration\v_strategies\b__dict__\020address_strategy\bbooleans",
    "\004\rbool_strategy\016bytes_strategy\017string_strategy\021strategy_registry",
    "\005\021get_uint_strategy\020get_int_strategy\bwith_sub\004bool\023get_ufixed_strategy",
    "\004\022get_fixed_strategy\022get_bytes_strategy\bbytes<M>\022get_array_strategy",
    "\004\022get_tuple_strategy\fget_strategy\b__exit__\t__enter__",
    "\005*Argument `places` must be int.  Got value \t of type \001.\004Eneg\004Epos",
    "\005\tscale_by_\b__name__\adecimal\037faster_eth_abi/utils/numeric.py\004Dict",
    "\005\020ABI_DECIMAL_PREC\aContext\004prec\023abi_decimal_context\flocalcontext",
    "\005\024decimal_localcontext\aDecimal\004ZERO\003TEN\036_unsigned_integer_bounds_cache",
    "\002\034_signed_integer_bounds_cache\034_unsigned_fixed_bounds_cache",
    "\002\032_signed_fixed_bounds_cache)Abbreviation limit may not be less than 3",
    "\005\003...\tbytearray\005The `#` value must be of bytes type. Got \tTypeError",
    "\001/` value type must be one of list or tuple. Got ",
    "",
};
const char * const CPyLit_Bytes[] = {
    "\004\000\001\000\001\001\001\377",
    "",
};
const char * const CPyLit_Int[] = {
    "\00432\0000\0001\000-1",
    "\001115792089237316195423570985008687907853269984665640564039457584007913129639936",
    "\001115792089237316195423570985008687907853269984665640564039457584007913129639935",
    "\00157896044618658097711785492504343953926634992332820282019728792003956564819968",
    "\0052\00020\0004096\000999\00010",
    "",
};
const double CPyLit_Float[] = {0};
const double CPyLit_Complex[] = {0};
const int CPyLit_Tuple[] = {
    45, 4, 11, 12, 13, 14, 2, 16, 17, 2, 19, 20, 3, 11, 12, 14, 1, 23,
    3, 26, 41, 56, 2, 60, 61, 7, 11, 12, 69, 70, 71, 72, 73, 1, 76, 3,
    137, 137, 137, 1, 328, 10, 12, 140, 141, 142, 71, 72, 14, 73, 143,
    144, 1, 17, 1, 146, 1, 148, 1, 150, 1, 98, 1, 174, 1, 140, 1, 179, 1,
    181, 3, 203, 203, 203, 1, 340, 6, 11, 12, 69, 71, 205, 73, 4, 172,
    178, 176, 206, 1, 191, 1, 212, 1, 213, 1, 217, 1, 222, 2, 228, 229, 3,
    228, 229, 231, 2, 233, 234, 6, 69, 140, 71, 14, 143, 237, 1, 238, 1,
    240, 1, 225, 6, 242, 243, 244, 220, 245, 246, 1, 247, 1, 262, 3, 280,
    280, 280, 1, 359, 4, 69, 282, 140, 14, 1, 285, 1, 12
};
const int CPyLit_FrozenSet[] = {0};
CPyModule *CPyModule_faster_eth_abi____codec__internal = NULL;
CPyModule *CPyModule_faster_eth_abi____codec;
PyObject *CPyStatic__codec___globals;
CPyModule *CPyModule_builtins;
CPyModule *CPyModule_typing;
CPyModule *CPyModule_eth_typing;
CPyModule *CPyModule_faster_eth_abi___utils___validation__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___utils___validation;
CPyModule *CPyModule_faster_eth_abi____decoding__internal = NULL;
CPyModule *CPyModule_faster_eth_abi____decoding;
PyObject *CPyStatic__decoding___globals;
CPyModule *CPyModule_faster_eth_utils;
CPyModule *CPyModule_faster_eth_abi___exceptions;
CPyModule *CPyModule_faster_eth_abi___io;
CPyModule *CPyModule_faster_eth_abi____encoding__internal = NULL;
CPyModule *CPyModule_faster_eth_abi____encoding;
PyObject *CPyStatic__encoding___globals;
CPyModule *CPyModule_faster_eth_abi____grammar__internal = NULL;
CPyModule *CPyModule_faster_eth_abi____grammar;
PyObject *CPyStatic__grammar___globals;
CPyModule *CPyModule_re;
CPyModule *CPyModule_eth_typing___abi;
CPyModule *CPyModule_mypy_extensions;
CPyModule *CPyModule_parsimonious___nodes;
CPyModule *CPyModule_typing_extensions;
CPyModule *CPyModule_faster_eth_abi___abi__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___abi;
PyObject *CPyStatic_abi___globals;
CPyModule *CPyModule_faster_eth_abi___codec;
CPyModule *CPyModule_faster_eth_abi___registry;
CPyModule *CPyModule_faster_eth_abi___constants__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___constants;
PyObject *CPyStatic_constants___globals;
CPyModule *CPyModule_faster_eth_abi___from_type_str__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___from_type_str;
PyObject *CPyStatic_from_type_str___globals;
CPyModule *CPyModule_functools;
CPyModule *CPyModule_faster_eth_abi___grammar;
CPyModule *CPyModule_faster_eth_abi___packed__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___packed;
PyObject *CPyStatic_packed___globals;
CPyModule *CPyModule_faster_eth_abi___tools__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___tools;
PyObject *CPyStatic_tools___globals;
CPyModule *CPyModule_faster_eth_abi___tools____strategies__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___tools____strategies;
PyObject *CPyStatic__strategies___globals;
CPyModule *CPyModule_cchecksum;
CPyModule *CPyModule_hypothesis;
CPyModule *CPyModule_faster_eth_abi___utils___numeric__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___utils___numeric;
CPyModule *CPyModule_faster_eth_abi___utils__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___utils;
PyObject *CPyStatic_utils___globals;
PyObject *CPyStatic_numeric___globals;
CPyModule *CPyModule_decimal;
CPyModule *CPyModule_faster_eth_abi___utils___padding__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___utils___padding;
PyObject *CPyStatic_padding___globals;
CPyModule *CPyModule_faster_eth_abi___utils___string__internal = NULL;
CPyModule *CPyModule_faster_eth_abi___utils___string;
PyObject *CPyStatic_string___globals;
PyObject *CPyStatic_validation___globals;
PyObject *CPyDef__codec___encode_c(PyObject *cpy_r_self, PyObject *cpy_r_types, PyObject *cpy_r_args);
PyObject *CPyPy__codec___encode_c(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__codec___decode_c(PyObject *cpy_r_self, PyObject *cpy_r_types, PyObject *cpy_r_data, char cpy_r_strict);
PyObject *CPyPy__codec___decode_c(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__codec_____top_level__(void);
CPyTagged CPyDef__decoding___decode_uint_256(PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___decode_uint_256(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
CPyTagged CPyDef__decoding___get_value_byte_size(PyObject *cpy_r_decoder);
PyObject *CPyPy__decoding___get_value_byte_size(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__decoding___decode_head_tail(PyObject *cpy_r_self, PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___decode_head_tail(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__decoding___decode_tuple(PyObject *cpy_r_self, PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___decode_tuple(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__decoding___validate_pointers_tuple(PyObject *cpy_r_self, PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___validate_pointers_tuple(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__decoding___validate_pointers_array(PyObject *cpy_r_self, PyObject *cpy_r_stream, CPyTagged cpy_r_array_size);
PyObject *CPyPy__decoding___validate_pointers_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__decoding___decode_sized_array(PyObject *cpy_r_self, PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___decode_sized_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__decoding___decode_dynamic_array(PyObject *cpy_r_self, PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___decode_dynamic_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__decoding___read_fixed_byte_size_data_from_stream(PyObject *cpy_r_self, PyObject *cpy_r_stream);
PyObject *CPyPy__decoding___read_fixed_byte_size_data_from_stream(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
tuple_T2OO CPyDef__decoding___split_data_and_padding_fixed_byte_size(PyObject *cpy_r_self, PyObject *cpy_r_raw_data);
PyObject *CPyPy__decoding___split_data_and_padding_fixed_byte_size(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__decoding___validate_padding_bytes_fixed_byte_size(PyObject *cpy_r_self, PyObject *cpy_r_value, PyObject *cpy_r_padding_bytes);
PyObject *CPyPy__decoding___validate_padding_bytes_fixed_byte_size(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__decoding___decoder_fn_boolean(PyObject *cpy_r_data);
PyObject *CPyPy__decoding___decoder_fn_boolean(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__decoding_____top_level__(void);
PyObject *CPyDef__encoding___encode_tuple(PyObject *cpy_r_values, PyObject *cpy_r_encoders);
PyObject *CPyPy__encoding___encode_tuple(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__encoding___encode_fixed(PyObject *cpy_r_value, PyObject *cpy_r_encode_fn, char cpy_r_is_big_endian, CPyTagged cpy_r_data_byte_size);
PyObject *CPyPy__encoding___encode_fixed(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__encoding___encode_signed(PyObject *cpy_r_value, PyObject *cpy_r_encode_fn, CPyTagged cpy_r_data_byte_size);
PyObject *CPyPy__encoding___encode_signed(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__encoding___encode_elements(PyObject *cpy_r_item_encoder, PyObject *cpy_r_value);
PyObject *CPyPy__encoding___encode_elements(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__encoding___encode_elements_dynamic(PyObject *cpy_r_item_encoder, PyObject *cpy_r_value);
PyObject *CPyPy__encoding___encode_elements_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__encoding___encode_uint_256(CPyTagged cpy_r_i);
PyObject *CPyPy__encoding___encode_uint_256(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__encoding___int_to_big_endian(CPyTagged cpy_r_value);
PyObject *CPyPy__encoding___int_to_big_endian(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__encoding_____top_level__(void);
PyObject *CPyStatic__grammar___TYPE_ALIASES = NULL;
PyObject *CPyStatic__grammar___TYPE_ALIAS_RE = NULL;
PyTypeObject *CPyType__grammar___ABIType;
PyObject *CPyDef__grammar___ABIType(PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyTypeObject *CPyType__grammar___TupleType;
PyObject *CPyDef__grammar___TupleType(PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyTypeObject *CPyType__grammar___BasicType;
PyObject *CPyDef__grammar___BasicType(PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
char CPyDef__grammar___ABIType_____init__(PyObject *cpy_r_self, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyObject *CPyPy__grammar___ABIType_____init__(PyObject *self, PyObject *args, PyObject *kw);
char CPyDef__grammar___ABIType_____init___3__ABIType_glue(PyObject *cpy_r_self, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyObject *CPyPy__grammar___ABIType_____init___3__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType_____repr__(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType_____repr__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType_____repr___3__ABIType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType_____repr___3__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType_____eq__(PyObject *cpy_r_self, PyObject *cpy_r_other);
PyObject *CPyPy__grammar___ABIType_____eq__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType_____eq___3__ABIType_glue(PyObject *cpy_r_self, PyObject *cpy_r_other);
PyObject *CPyPy__grammar___ABIType_____eq___3__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType___to_type_str(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___to_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType___to_type_str__ABIType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___to_type_str__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType___item_type(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___item_type(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType___item_type__ABIType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___ABIType___item_type__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType___validate(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___validate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType___validate__ABIType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___validate__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType___invalidate(PyObject *cpy_r_self, PyObject *cpy_r_error_msg);
PyObject *CPyPy__grammar___ABIType___invalidate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___ABIType___invalidate__ABIType_glue(PyObject *cpy_r_self, PyObject *cpy_r_error_msg);
PyObject *CPyPy__grammar___ABIType___invalidate__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType___is_array(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___is_array(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType___is_array__ABIType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___ABIType___is_array__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType___is_dynamic(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType___is_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType___is_dynamic__ABIType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___ABIType___is_dynamic__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType____has_dynamic_arrlist(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___ABIType____has_dynamic_arrlist(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType____has_dynamic_arrlist__ABIType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___ABIType____has_dynamic_arrlist__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___ABIType_____ne__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_rhs);
PyObject *CPyPy__grammar___ABIType_____ne__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___TupleType_____init__(PyObject *cpy_r_self, PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyObject *CPyPy__grammar___TupleType_____init__(PyObject *self, PyObject *args, PyObject *kw);
char CPyDef__grammar___TupleType_____init___3__TupleType_glue(PyObject *cpy_r_self, PyObject *cpy_r_components, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyObject *CPyPy__grammar___TupleType_____init___3__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___TupleType___to_type_str(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___TupleType___to_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___TupleType___to_type_str__TupleType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___TupleType___to_type_str__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___TupleType___item_type(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___TupleType___item_type(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___TupleType___item_type__ABIType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___TupleType___item_type__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___TupleType___item_type__TupleType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___TupleType___item_type__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___TupleType___validate(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___TupleType___validate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___TupleType___validate__TupleType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___TupleType___validate__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___TupleType___is_dynamic(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___TupleType___is_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___TupleType___is_dynamic__TupleType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___TupleType___is_dynamic__TupleType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___BasicType_____init__(PyObject *cpy_r_self, PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyObject *CPyPy__grammar___BasicType_____init__(PyObject *self, PyObject *args, PyObject *kw);
char CPyDef__grammar___BasicType_____init___3__BasicType_glue(PyObject *cpy_r_self, PyObject *cpy_r_base, PyObject *cpy_r_sub, PyObject *cpy_r_arrlist, PyObject *cpy_r_node);
PyObject *CPyPy__grammar___BasicType_____init___3__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___BasicType___to_type_str(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___BasicType___to_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___BasicType___to_type_str__BasicType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___BasicType___to_type_str__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___BasicType___item_type(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___BasicType___item_type(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___BasicType___item_type__ABIType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___BasicType___item_type__ABIType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___BasicType___item_type__BasicType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___BasicType___item_type__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___BasicType___is_dynamic(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___BasicType___is_dynamic(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___BasicType___is_dynamic__BasicType_glue(PyObject *cpy_r___mypyc_self__);
PyObject *CPyPy__grammar___BasicType___is_dynamic__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___BasicType___validate(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___BasicType___validate(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar___BasicType___validate__BasicType_glue(PyObject *cpy_r_self);
PyObject *CPyPy__grammar___BasicType___validate__BasicType_glue(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar___normalize(PyObject *cpy_r_type_str);
PyObject *CPyPy__grammar___normalize(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__grammar_____normalize(PyObject *cpy_r_match);
PyObject *CPyPy__grammar_____normalize(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__grammar_____top_level__(void);
PyObject *CPyStatic_abi___default_codec = NULL;
PyObject *CPyStatic_abi___encode = NULL;
PyObject *CPyStatic_abi___decode = NULL;
PyObject *CPyStatic_abi___is_encodable = NULL;
PyObject *CPyStatic_abi___is_encodable_type = NULL;
char CPyDef_abi_____top_level__(void);
char CPyDef_constants_____top_level__(void);
PyTypeObject *CPyType_from_type_str___parse_type_str_env;
PyObject *CPyDef_from_type_str___parse_type_str_env(void);
CPyThreadLocal faster_eth_abi___from_type_str___parse_type_str_envObject *from_type_str___parse_type_str_env_free_instance;
PyTypeObject *CPyType_from_type_str___decorator_parse_type_str_env;
PyObject *CPyDef_from_type_str___decorator_parse_type_str_env(void);
CPyThreadLocal faster_eth_abi___from_type_str___decorator_parse_type_str_envObject *from_type_str___decorator_parse_type_str_env_free_instance;
PyTypeObject *CPyType_from_type_str___decorator_parse_type_str_obj;
PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj(void);
CPyThreadLocal faster_eth_abi___from_type_str___decorator_parse_type_str_objObject *from_type_str___decorator_parse_type_str_obj_free_instance;
PyTypeObject *CPyType_from_type_str___new_from_type_str_parse_type_str_decorator_obj;
PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj(void);
CPyThreadLocal faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject *from_type_str___new_from_type_str_parse_type_str_decorator_obj_free_instance;
PyTypeObject *CPyType_from_type_str___parse_tuple_type_str_env;
PyObject *CPyDef_from_type_str___parse_tuple_type_str_env(void);
CPyThreadLocal faster_eth_abi___from_type_str___parse_tuple_type_str_envObject *from_type_str___parse_tuple_type_str_env_free_instance;
PyTypeObject *CPyType_from_type_str___new_from_type_str_parse_tuple_type_str_obj;
PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj(void);
CPyThreadLocal faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject *from_type_str___new_from_type_str_parse_tuple_type_str_obj_free_instance;
PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner);
PyObject *CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_cls, PyObject *cpy_r_type_str, PyObject *cpy_r_registry);
PyObject *CPyPy_from_type_str___new_from_type_str_parse_type_str_decorator_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner);
PyObject *CPyPy_from_type_str___decorator_parse_type_str_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___decorator_parse_type_str_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_old_from_type_str);
PyObject *CPyPy_from_type_str___decorator_parse_type_str_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___parse_type_str(PyObject *cpy_r_expected_base, char cpy_r_with_arrlist);
PyObject *CPyPy_from_type_str___parse_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner);
PyObject *CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_cls, PyObject *cpy_r_type_str, PyObject *cpy_r_registry);
PyObject *CPyPy_from_type_str___new_from_type_str_parse_tuple_type_str_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_from_type_str___parse_tuple_type_str(PyObject *cpy_r_old_from_type_str);
PyObject *CPyPy_from_type_str___parse_tuple_type_str(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef_from_type_str_____top_level__(void);
PyObject *CPyStatic_packed___default_encoder_packed = NULL;
PyObject *CPyStatic_packed___encode_packed = NULL;
PyObject *CPyStatic_packed___is_encodable_packed = NULL;
char CPyDef_packed_____top_level__(void);
char CPyDef_tools_____top_level__(void);
PyObject *CPyStatic__strategies___address_strategy = NULL;
PyObject *CPyStatic__strategies___bool_strategy = NULL;
PyObject *CPyStatic__strategies___bytes_strategy = NULL;
PyObject *CPyStatic__strategies___string_strategy = NULL;
PyObject *CPyStatic__strategies___strategy_registry = NULL;
PyObject *CPyStatic__strategies___get_abi_strategy = NULL;
PyTypeObject *CPyType__strategies___StrategyRegistry;
PyObject *CPyDef__strategies___StrategyRegistry(void);
char CPyDef__strategies___StrategyRegistry_____init__(PyObject *cpy_r_self);
PyObject *CPyPy__strategies___StrategyRegistry_____init__(PyObject *self, PyObject *args, PyObject *kw);
char CPyDef__strategies___StrategyRegistry___register_strategy(PyObject *cpy_r_self, PyObject *cpy_r_lookup, PyObject *cpy_r_registration, PyObject *cpy_r_label);
PyObject *CPyPy__strategies___StrategyRegistry___register_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__strategies___StrategyRegistry___unregister_strategy(PyObject *cpy_r_self, PyObject *cpy_r_lookup_or_label);
PyObject *CPyPy__strategies___StrategyRegistry___unregister_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___StrategyRegistry___get_strategy(PyObject *cpy_r_self, PyObject *cpy_r_type_str);
PyObject *CPyPy__strategies___StrategyRegistry___get_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_uint_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_uint_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_int_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_int_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_ufixed_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_ufixed_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_fixed_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_fixed_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_bytes_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_bytes_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_array_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_array_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef__strategies___get_tuple_strategy(PyObject *cpy_r_abi_type, PyObject *cpy_r_registry);
PyObject *CPyPy__strategies___get_tuple_strategy(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef__strategies_____top_level__(void);
char CPyDef_utils_____top_level__(void);
PyObject *CPyStatic_numeric___abi_decimal_context = NULL;
PyObject *CPyStatic_numeric___decimal_localcontext = NULL;
PyObject *CPyStatic_numeric___ZERO = NULL;
PyObject *CPyStatic_numeric___TEN = NULL;
PyObject *CPyStatic_numeric___Decimal = NULL;
PyObject *CPyStatic_numeric____unsigned_integer_bounds_cache = NULL;
PyObject *CPyStatic_numeric____signed_integer_bounds_cache = NULL;
PyObject *CPyStatic_numeric____unsigned_fixed_bounds_cache = NULL;
PyObject *CPyStatic_numeric____signed_fixed_bounds_cache = NULL;
PyTypeObject *CPyType_numeric___scale_places_env;
PyObject *CPyDef_numeric___scale_places_env(void);
CPyThreadLocal faster_eth_abi___utils___numeric___scale_places_envObject *numeric___scale_places_env_free_instance;
PyTypeObject *CPyType_numeric___f_scale_places_obj;
PyObject *CPyDef_numeric___f_scale_places_obj(void);
CPyThreadLocal faster_eth_abi___utils___numeric___f_scale_places_objObject *numeric___f_scale_places_obj_free_instance;
CPyTagged CPyDef_numeric___ceil32(CPyTagged cpy_r_x);
PyObject *CPyPy_numeric___ceil32(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
tuple_T2II CPyDef_numeric___compute_unsigned_integer_bounds(CPyTagged cpy_r_num_bits);
PyObject *CPyPy_numeric___compute_unsigned_integer_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
tuple_T2II CPyDef_numeric___compute_signed_integer_bounds(CPyTagged cpy_r_num_bits);
PyObject *CPyPy_numeric___compute_signed_integer_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
tuple_T2OO CPyDef_numeric___compute_unsigned_fixed_bounds(CPyTagged cpy_r_num_bits, CPyTagged cpy_r_frac_places);
PyObject *CPyPy_numeric___compute_unsigned_fixed_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
tuple_T2OO CPyDef_numeric___compute_signed_fixed_bounds(CPyTagged cpy_r_num_bits, CPyTagged cpy_r_frac_places);
PyObject *CPyPy_numeric___compute_signed_fixed_bounds(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_numeric___f_scale_places_obj_____get__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_instance, PyObject *cpy_r_owner);
PyObject *CPyPy_numeric___f_scale_places_obj_____get__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_numeric___f_scale_places_obj_____call__(PyObject *cpy_r___mypyc_self__, PyObject *cpy_r_x);
PyObject *CPyPy_numeric___f_scale_places_obj_____call__(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_numeric___scale_places(CPyTagged cpy_r_places);
PyObject *CPyPy_numeric___scale_places(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef_numeric_____top_level__(void);
PyObject *CPyDef_padding___zpad(PyObject *cpy_r_value, CPyTagged cpy_r_length);
PyObject *CPyPy_padding___zpad(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_padding___zpad32(PyObject *cpy_r_value);
PyObject *CPyPy_padding___zpad32(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_padding___zpad_right(PyObject *cpy_r_value, CPyTagged cpy_r_length);
PyObject *CPyPy_padding___zpad_right(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_padding___zpad32_right(PyObject *cpy_r_value);
PyObject *CPyPy_padding___zpad32_right(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_padding___fpad(PyObject *cpy_r_value, CPyTagged cpy_r_length);
PyObject *CPyPy_padding___fpad(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
PyObject *CPyDef_padding___fpad32(PyObject *cpy_r_value);
PyObject *CPyPy_padding___fpad32(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef_padding_____top_level__(void);
PyObject *CPyDef_string___abbr(PyObject *cpy_r_value, CPyTagged cpy_r_limit);
PyObject *CPyPy_string___abbr(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef_string_____top_level__(void);
char CPyDef_validation___validate_bytes_param(PyObject *cpy_r_param, PyObject *cpy_r_param_name);
PyObject *CPyPy_validation___validate_bytes_param(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef_validation___validate_list_like_param(PyObject *cpy_r_param, PyObject *cpy_r_param_name);
PyObject *CPyPy_validation___validate_list_like_param(PyObject *self, PyObject *const *args, size_t nargs, PyObject *kwnames);
char CPyDef_validation_____top_level__(void);

static int exec_faster_eth_abi__mypyc(PyObject *module)
{
    int res;
    PyObject *capsule;
    PyObject *tmp;
    
    extern PyObject *CPyInit_faster_eth_abi____codec(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi____codec, "faster_eth_abi__mypyc.init_faster_eth_abi____codec", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi____codec", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi____decoding(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi____decoding, "faster_eth_abi__mypyc.init_faster_eth_abi____decoding", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi____decoding", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi____encoding(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi____encoding, "faster_eth_abi__mypyc.init_faster_eth_abi____encoding", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi____encoding", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi____grammar(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi____grammar, "faster_eth_abi__mypyc.init_faster_eth_abi____grammar", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi____grammar", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___abi(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___abi, "faster_eth_abi__mypyc.init_faster_eth_abi___abi", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___abi", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___constants(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___constants, "faster_eth_abi__mypyc.init_faster_eth_abi___constants", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___constants", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___from_type_str(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___from_type_str, "faster_eth_abi__mypyc.init_faster_eth_abi___from_type_str", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___from_type_str", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___packed(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___packed, "faster_eth_abi__mypyc.init_faster_eth_abi___packed", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___packed", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___tools(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___tools, "faster_eth_abi__mypyc.init_faster_eth_abi___tools", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___tools", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___tools____strategies(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___tools____strategies, "faster_eth_abi__mypyc.init_faster_eth_abi___tools____strategies", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___tools____strategies", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___utils(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___utils, "faster_eth_abi__mypyc.init_faster_eth_abi___utils", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___utils", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___utils___numeric(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___utils___numeric, "faster_eth_abi__mypyc.init_faster_eth_abi___utils___numeric", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___utils___numeric", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___utils___padding(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___utils___padding, "faster_eth_abi__mypyc.init_faster_eth_abi___utils___padding", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___utils___padding", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___utils___string(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___utils___string, "faster_eth_abi__mypyc.init_faster_eth_abi___utils___string", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___utils___string", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    extern PyObject *CPyInit_faster_eth_abi___utils___validation(void);
    capsule = PyCapsule_New((void *)CPyInit_faster_eth_abi___utils___validation, "faster_eth_abi__mypyc.init_faster_eth_abi___utils___validation", NULL);
    if (!capsule) {
        goto fail;
    }
    res = PyObject_SetAttrString(module, "init_faster_eth_abi___utils___validation", capsule);
    Py_DECREF(capsule);
    if (res < 0) {
        goto fail;
    }
    
    return 0;
    fail:
    return -1;
}
static PyModuleDef module_def_faster_eth_abi__mypyc = {
    PyModuleDef_HEAD_INIT,
    .m_name = "faster_eth_abi__mypyc",
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = NULL,
};
PyMODINIT_FUNC PyInit_faster_eth_abi__mypyc(void) {
    static PyObject *module = NULL;
    if (module) {
        Py_INCREF(module);
        return module;
    }
    module = PyModule_Create(&module_def_faster_eth_abi__mypyc);
    if (!module) {
        return NULL;
    }
    if (exec_faster_eth_abi__mypyc(module) < 0) {
        Py_DECREF(module);
        return NULL;
    }
    return module;
}
