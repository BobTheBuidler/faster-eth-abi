    PyObject *cpy_r_r1;
    PyObject **cpy_r_r7;
    PyObject *cpy_r_r10;
        goto CPyL6;
    cpy_r_r1 = cpy_r_r0;
    cpy_r_r2 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'bytes_errors' */
    cpy_r_r3 = CPyObject_GetAttr(cpy_r_self, cpy_r_r2);
    if (unlikely(cpy_r_r3 == NULL)) {
    if (likely(PyUnicode_Check(cpy_r_r3)))
        cpy_r_r4 = cpy_r_r3;
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "decode_string", 372, CPyStatic__decoding___globals, "str", cpy_r_r3);
        goto CPyL7;
    cpy_r_r5 = CPyStatics[DIFFCHECK_PLACEHOLDER]; /* 'decoder_fn' */
    PyObject *cpy_r_r6[3] = {cpy_r_self, cpy_r_r1, cpy_r_r4};
    cpy_r_r7 = (PyObject **)&cpy_r_r6;
    cpy_r_r8 = PyObject_VectorcallMethod(cpy_r_r5, cpy_r_r7, 9223372036854775811ULL, 0);
    if (unlikely(cpy_r_r8 == NULL)) {
        goto CPyL8;
    CPy_DECREF(cpy_r_r1);
    if (likely(PyUnicode_Check(cpy_r_r8)))
        cpy_r_r9 = cpy_r_r8;
        CPy_TypeErrorTraceback("faster_eth_abi/_decoding.py", "decode_string", 372, CPyStatic__decoding___globals, "str", cpy_r_r8);
        goto CPyL6;
    return cpy_r_r9;
CPyL6: ;
    cpy_r_r10 = NULL;
    return cpy_r_r10;
    CPy_DecRef(cpy_r_r1);
    goto CPyL6;
    CPy_DecRef(cpy_r_r1);
    goto CPyL6;
