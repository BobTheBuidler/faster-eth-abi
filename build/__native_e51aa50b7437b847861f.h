#ifndef MYPYC_NATIVE_e51aa50b7437b847861f_H
#define MYPYC_NATIVE_e51aa50b7437b847861f_H
#include <Python.h>
#include <CPy.h>
#ifndef MYPYC_DECLARED_tuple_T2OC
#define MYPYC_DECLARED_tuple_T2OC
typedef struct tuple_T2OC {
    PyObject *f0;
    char f1;
} tuple_T2OC;
#endif

#ifndef MYPYC_DECLARED_tuple_T2OO
#define MYPYC_DECLARED_tuple_T2OO
typedef struct tuple_T2OO {
    PyObject *f0;
    PyObject *f1;
} tuple_T2OO;
#endif

#ifndef MYPYC_DECLARED_tuple_T3OOO
#define MYPYC_DECLARED_tuple_T3OOO
typedef struct tuple_T3OOO {
    PyObject *f0;
    PyObject *f1;
    PyObject *f2;
} tuple_T3OOO;
#endif

#ifndef MYPYC_DECLARED_tuple_T2II
#define MYPYC_DECLARED_tuple_T2II
typedef struct tuple_T2II {
    CPyTagged f0;
    CPyTagged f1;
} tuple_T2II;
#endif

#ifndef MYPYC_DECLARED_tuple_T2IO
#define MYPYC_DECLARED_tuple_T2IO
typedef struct tuple_T2IO {
    CPyTagged f0;
    PyObject *f1;
} tuple_T2IO;
#endif

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *__func;
    PyObject *__cache;
} faster_eth_abi____cache____CacheBaseObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *__func;
    PyObject *__cache;
} faster_eth_abi____cache___EncoderCacheObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *__func;
    PyObject *__cache;
} faster_eth_abi____cache___DecoderCacheObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *__func;
    PyObject *__cache;
} faster_eth_abi____cache___TupleDecoderCacheObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_self__;
    PyObject *_old_method;
    PyObject *_new_method;
} faster_eth_abi____cache____clear_encoder_cache_envObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *___mypyc_env__;
} faster_eth_abi____cache___new_method__clear_encoder_cache_objObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_self__;
    PyObject *_old_method;
    PyObject *_new_method;
} faster_eth_abi____cache____clear_decoder_cache_envObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *___mypyc_env__;
} faster_eth_abi____cache___new_method__clear_decoder_cache_objObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *_arrlist;
    PyObject *_node;
} faster_eth_abi____grammar___ABITypeObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *_arrlist;
    PyObject *_node;
    PyObject *_components;
} faster_eth_abi____grammar___TupleTypeObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *_arrlist;
    PyObject *_node;
    PyObject *_base;
    PyObject *_sub;
} faster_eth_abi____grammar___BasicTypeObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_self__;
    PyObject *_expected_base;
    char _with_arrlist;
    char _None;
    PyObject *_decorator;
} faster_eth_abi___from_type_str___parse_type_str_envObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_self__;
    PyObject *___mypyc_env__;
    PyObject *_old_from_type_str;
    PyObject *_new_from_type_str;
    PyObject *_expected_base;
    char _with_arrlist;
    char _None;
    PyObject *_decorator;
} faster_eth_abi___from_type_str___decorator_parse_type_str_envObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *___mypyc_env__;
} faster_eth_abi___from_type_str___decorator_parse_type_str_objObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *___mypyc_env__;
} faster_eth_abi___from_type_str___new_from_type_str_parse_type_str_decorator_objObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_self__;
    PyObject *_old_from_type_str;
    PyObject *_new_from_type_str;
} faster_eth_abi___from_type_str___parse_tuple_type_str_envObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *___mypyc_env__;
} faster_eth_abi___from_type_str___new_from_type_str_parse_tuple_type_str_objObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *__strategies;
} faster_eth_abi___tools____strategies___StrategyRegistryObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_self__;
    PyObject *_scaling_factor;
    PyObject *_f;
    CPyTagged _places;
} faster_eth_abi___utils___numeric___scale_places_envObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *___mypyc_env__;
} faster_eth_abi___utils___numeric___f_scale_places_objObject;

#endif
