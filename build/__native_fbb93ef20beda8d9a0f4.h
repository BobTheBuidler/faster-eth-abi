#ifndef MYPYC_NATIVE_fbb93ef20beda8d9a0f4_H
#define MYPYC_NATIVE_fbb93ef20beda8d9a0f4_H
#include <Python.h>
#include <CPy.h>
#ifndef MYPYC_DECLARED_tuple_T3OOO
#define MYPYC_DECLARED_tuple_T3OOO
typedef struct tuple_T3OOO {
    PyObject *f0;
    PyObject *f1;
    PyObject *f2;
} tuple_T3OOO;
#endif

#ifndef MYPYC_DECLARED_tuple_T2OO
#define MYPYC_DECLARED_tuple_T2OO
typedef struct tuple_T2OO {
    PyObject *f0;
    PyObject *f1;
} tuple_T2OO;
#endif

#ifndef MYPYC_DECLARED_tuple_T4CIOO
#define MYPYC_DECLARED_tuple_T4CIOO
typedef struct tuple_T4CIOO {
    char f0;
    CPyTagged f1;
    PyObject *f2;
    PyObject *f3;
} tuple_T4CIOO;
#endif

#ifndef MYPYC_DECLARED_tuple_T1O
#define MYPYC_DECLARED_tuple_T1O
typedef struct tuple_T1O {
    PyObject *f0;
} tuple_T1O;
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
} faster_eth_abi____registry___CopyableObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *__name;
    PyObject *__values;
    PyObject *__labeled_predicates;
} faster_eth_abi____registry___PredicateMappingObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
} faster_eth_abi____registry___PredicateObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *_value;
} faster_eth_abi____registry___EqualsObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    vectorcallfunc vectorcall;
    PyObject *_base;
    PyObject *_with_sub;
} faster_eth_abi____registry___BaseEqualsObject;

typedef struct {
    PyObject_HEAD
    CPyVTableItem *vtable;
    PyObject *___mypyc_generator_attribute__self;
    int32_t ___mypyc_next_label__;
    PyObject *___mypyc_temp__0;
    int64_t ___mypyc_temp__1;
    int64_t ___mypyc_temp__2;
    PyObject *___mypyc_generator_attribute__attr;
} faster_eth_abi____registry_____iter___3_Predicate_genObject;

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
