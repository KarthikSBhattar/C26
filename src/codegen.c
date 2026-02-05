/*
 * C26 Compiler - LLVM Code Generator Implementation
 */

#include "codegen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SymbolTable *symtable_new(void) {
  SymbolTable *st = malloc(sizeof(SymbolTable));
  st->capacity = 64;
  st->count = 0;
  st->symbols = malloc(sizeof(Symbol) * st->capacity);
  return st;
}

static void symtable_free(SymbolTable *st) {
  for (int i = 0; i < st->count; i++)
    free(st->symbols[i].name);
  free(st->symbols);
  free(st);
}

static void symtable_add(SymbolTable *st, const char *name, LLVMValueRef alloca,
                         LLVMTypeRef type, TypeInfo *c26_type, int is_local,
                         char *source_file) {
  if (st->count >= st->capacity) {
    st->capacity *= 2;
    st->symbols = realloc(st->symbols, sizeof(Symbol) * st->capacity);
  }
  st->symbols[st->count].name = strdup(name);
  st->symbols[st->count].alloca = alloca;
  st->symbols[st->count].type = type;
  st->symbols[st->count].c26_type = c26_type;
  st->symbols[st->count].is_local = is_local;
  st->symbols[st->count].source_file = source_file ? strdup(source_file) : NULL;
  st->count++;
}

static Symbol *symtable_lookup(SymbolTable *st, const char *name) {
  for (int i = st->count - 1; i >= 0; i--)
    if (strcmp(st->symbols[i].name, name) == 0)
      return &st->symbols[i];
  return NULL;
}

static void symtable_clear(SymbolTable *st) {
  for (int i = 0; i < st->count; i++) {
    free(st->symbols[i].name);
    if (st->symbols[i].source_file)
      free(st->symbols[i].source_file);
  }
  st->count = 0;
}

static StructInfo *lookup_struct(CodeGen *gen, const char *name) {
  for (int i = 0; i < gen->struct_count; i++) {
    if (strcmp(gen->structs[i].name, name) == 0)
      return &gen->structs[i];
  }
  return NULL;
}

static StructInfo *ensure_struct(CodeGen *gen, const char *name) {
  StructInfo *info = lookup_struct(gen, name);
  if (info)
    return info;
  if (gen->struct_count >= gen->struct_capacity) {
    gen->struct_capacity =
        gen->struct_capacity < 8 ? 8 : gen->struct_capacity * 2;
    gen->structs =
        realloc(gen->structs, sizeof(StructInfo) * gen->struct_capacity);
  }
  gen->structs[gen->struct_count].name = strdup(name);
  gen->structs[gen->struct_count].llvm_type =
      LLVMStructCreateNamed(gen->context, name);
  gen->structs[gen->struct_count].decl = NULL;
  return &gen->structs[gen->struct_count++];
}

static MethodInfo *lookup_method(CodeGen *gen, const char *struct_name,
                                 const char *method_name) {
  for (int i = 0; i < gen->method_count; i++) {
    if (strcmp(gen->methods[i].struct_name, struct_name) == 0 &&
        strcmp(gen->methods[i].method_name, method_name) == 0)
      return &gen->methods[i];
  }
  return NULL;
}

static void register_method(CodeGen *gen, ASTNode *func) {
  if (!func || func->type != NODE_FUNC_DECL || !func->data.func.method_of)
    return;
  if (lookup_method(gen, func->data.func.method_of,
                    func->data.func.original_name))
    return;
  if (gen->method_count >= gen->method_capacity) {
    gen->method_capacity =
        gen->method_capacity < 8 ? 8 : gen->method_capacity * 2;
    gen->methods =
        realloc(gen->methods, sizeof(MethodInfo) * gen->method_capacity);
  }
  MethodInfo *m = &gen->methods[gen->method_count++];
  m->struct_name = strdup(func->data.func.method_of);
  m->method_name = strdup(func->data.func.original_name);
  m->func = func;
  m->expects_self = 0;
  m->self_is_pointer = 0;
  if (func->data.func.param_count > 0) {
    TypeInfo *p0 = func->data.func.param_types[0];
    if (p0->kind == TYPE_STRUCT &&
        strcmp(p0->name, func->data.func.method_of) == 0) {
      m->expects_self = 1;
      m->self_is_pointer = 0;
    } else if (p0->kind == TYPE_POINTER && p0->element_type &&
               p0->element_type->kind == TYPE_STRUCT &&
               strcmp(p0->element_type->name, func->data.func.method_of) == 0) {
      m->expects_self = 1;
      m->self_is_pointer = 1;
    }
  }
}

static void register_struct_decl(CodeGen *gen, ASTNode *decl) {
  if (!decl || decl->type != NODE_STRUCT_DECL)
    return;
  StructInfo *info = ensure_struct(gen, decl->data.struct_decl.type->name);
  if (!info->decl)
    info->decl = decl;
}

CodeGen *codegen_init(const char *module_name) {
  CodeGen *gen = malloc(sizeof(CodeGen));
  gen->context = LLVMContextCreate();
  gen->module = LLVMModuleCreateWithNameInContext(module_name, gen->context);
  gen->builder = LLVMCreateBuilderInContext(gen->context);
  gen->symbols = symtable_new();
  gen->globals = symtable_new();
  gen->structs = NULL;
  gen->struct_count = 0;
  gen->struct_capacity = 0;
  gen->methods = NULL;
  gen->method_count = 0;
  gen->method_capacity = 0;
  gen->current_source_file = NULL;
  gen->printf_func = NULL;
  gen->printf_type = NULL;
  gen->malloc_func = NULL;
  gen->free_func = NULL;
  gen->exit_func = NULL;
  gen->realloc_func = NULL;
  gen->calloc_func = NULL;
  gen->gc_malloc_func = NULL;
  gen->gc_realloc_func = NULL;
  gen->gc_free_func = NULL;
  gen->gc_init_func = NULL;
  gen->gc_enable_incremental_func = NULL;
  gen->had_error = 0;
  gen->error_msg = NULL;
  return gen;
}

void codegen_free(CodeGen *gen) {
  if (gen->error_msg)
    free(gen->error_msg);
  for (int i = 0; i < gen->struct_count; i++)
    free(gen->structs[i].name);
  free(gen->structs);
  for (int i = 0; i < gen->method_count; i++) {
    free(gen->methods[i].struct_name);
    free(gen->methods[i].method_name);
  }
  free(gen->methods);
  symtable_free(gen->symbols);
  LLVMDisposeBuilder(gen->builder);
  LLVMDisposeModule(gen->module);
  LLVMContextDispose(gen->context);
  free(gen);
}

// Ensure printf is declared and cache its type
static void ensure_printf(CodeGen *gen) {
  if (gen->printf_func)
    return;
  LLVMTypeRef char_ptr =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  gen->printf_type =
      LLVMFunctionType(LLVMInt32TypeInContext(gen->context), &char_ptr, 1, 1);
  gen->printf_func = LLVMAddFunction(gen->module, "printf", gen->printf_type);
}

// Ensure malloc is declared
static void ensure_malloc(CodeGen *gen) {
  if (gen->malloc_func)
    return;
  LLVMTypeRef size_t_type = LLVMInt64TypeInContext(gen->context);
  LLVMTypeRef ret_type =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, &size_t_type, 1, 0);
  gen->malloc_func = LLVMAddFunction(gen->module, "malloc", fn_type);
}

// Ensure free is declared
static void ensure_free(CodeGen *gen) {
  if (gen->free_func)
    return;
  LLVMTypeRef void_ptr =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef ret_type = LLVMVoidTypeInContext(gen->context);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, &void_ptr, 1, 0);
  gen->free_func = LLVMAddFunction(gen->module, "free", fn_type);
}

// Ensure exit is declared
static void ensure_exit(CodeGen *gen) {
  if (gen->exit_func)
    return;
  LLVMTypeRef arg_type = LLVMInt32TypeInContext(gen->context);
  LLVMTypeRef ret_type = LLVMVoidTypeInContext(gen->context);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, &arg_type, 1, 0);
  gen->exit_func = LLVMAddFunction(gen->module, "exit", fn_type);
}

// Ensure realloc is declared
static void ensure_realloc(CodeGen *gen) {
  if (gen->realloc_func)
    return;
  LLVMTypeRef ptr_type =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef size_t_type = LLVMInt64TypeInContext(gen->context);
  LLVMTypeRef args[] = {ptr_type, size_t_type};
  LLVMTypeRef fn_type = LLVMFunctionType(ptr_type, args, 2, 0);
  gen->realloc_func = LLVMAddFunction(gen->module, "realloc", fn_type);
}

// Ensure calloc is declared
static void ensure_calloc(CodeGen *gen) {
  if (gen->calloc_func)
    return;
  LLVMTypeRef ptr_type =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef size_t_type = LLVMInt64TypeInContext(gen->context);
  LLVMTypeRef args[] = {size_t_type, size_t_type};
  LLVMTypeRef fn_type = LLVMFunctionType(ptr_type, args, 2, 0);
  gen->calloc_func = LLVMAddFunction(gen->module, "calloc", fn_type);
}

// Ensure GC_init is declared
static void ensure_gc_init(CodeGen *gen) {
  if (gen->gc_init_func)
    return;
  LLVMTypeRef ret_type = LLVMVoidTypeInContext(gen->context);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, NULL, 0, 0);
  gen->gc_init_func = LLVMAddFunction(gen->module, "GC_init", fn_type);
}

// Ensure GC_malloc is declared
static void ensure_gc_malloc(CodeGen *gen) {
  if (gen->gc_malloc_func)
    return;
  LLVMTypeRef size_t_type = LLVMInt64TypeInContext(gen->context);
  LLVMTypeRef ret_type =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, &size_t_type, 1, 0);
  gen->gc_malloc_func = LLVMAddFunction(gen->module, "GC_malloc", fn_type);
}

// Ensure GC_realloc is declared
static void ensure_gc_realloc(CodeGen *gen) {
  if (gen->gc_realloc_func)
    return;
  LLVMTypeRef ptr_type =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef size_t_type = LLVMInt64TypeInContext(gen->context);
  LLVMTypeRef args[] = {ptr_type, size_t_type};
  LLVMTypeRef fn_type = LLVMFunctionType(ptr_type, args, 2, 0);
  gen->gc_realloc_func = LLVMAddFunction(gen->module, "GC_realloc", fn_type);
}

// Ensure GC_free is declared
static void ensure_gc_free(CodeGen *gen) {
  if (gen->gc_free_func)
    return;
  LLVMTypeRef ptr_type =
      LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  LLVMTypeRef ret_type = LLVMVoidTypeInContext(gen->context);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, &ptr_type, 1, 0);
  gen->gc_free_func = LLVMAddFunction(gen->module, "GC_free", fn_type);
}

// Ensure GC_enable_incremental is declared
static void ensure_gc_enable_incremental(CodeGen *gen) {
  if (gen->gc_enable_incremental_func)
    return;
  LLVMTypeRef ret_type = LLVMVoidTypeInContext(gen->context);
  LLVMTypeRef fn_type = LLVMFunctionType(ret_type, NULL, 0, 0);
  gen->gc_enable_incremental_func =
      LLVMAddFunction(gen->module, "GC_enable_incremental", fn_type);
}

static LLVMValueRef get_strlen(CodeGen *gen) {
  LLVMValueRef fn = LLVMGetNamedFunction(gen->module, "strlen");
  if (!fn) {
    LLVMTypeRef args[] = {
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0)};
    LLVMTypeRef fn_type =
        LLVMFunctionType(LLVMInt64TypeInContext(gen->context), args, 1, 0);
    fn = LLVMAddFunction(gen->module, "strlen", fn_type);
  }
  return fn;
}

static LLVMValueRef get_strcpy(CodeGen *gen) {
  LLVMValueRef fn = LLVMGetNamedFunction(gen->module, "strcpy");
  if (!fn) {
    LLVMTypeRef args[] = {
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0),
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0)};
    LLVMTypeRef fn_type = LLVMFunctionType(
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0), args, 2, 0);
    fn = LLVMAddFunction(gen->module, "strcpy", fn_type);
  }
  return fn;
}

static LLVMValueRef get_strcat(CodeGen *gen) {
  LLVMValueRef fn = LLVMGetNamedFunction(gen->module, "strcat");
  if (!fn) {
    LLVMTypeRef args[] = {
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0),
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0)};
    LLVMTypeRef fn_type = LLVMFunctionType(
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0), args, 2, 0);
    fn = LLVMAddFunction(gen->module, "strcat", fn_type);
  }
  return fn;
}

static LLVMValueRef get_snprintf(CodeGen *gen) {
  LLVMValueRef fn = LLVMGetNamedFunction(gen->module, "snprintf");
  if (!fn) {
    LLVMTypeRef ptr = LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
    LLVMTypeRef args[] = {ptr, LLVMInt64TypeInContext(gen->context), ptr};
    LLVMTypeRef fn_type = LLVMFunctionType(LLVMInt32TypeInContext(gen->context),
                                           args, 3, 1); // varargs
    fn = LLVMAddFunction(gen->module, "snprintf", fn_type);
  }
  return fn;
}

static LLVMTypeRef type_info_to_llvm(CodeGen *gen, TypeInfo *type) {
  if (!type)
    return LLVMInt32TypeInContext(gen->context);
  switch (type->kind) {
  case TYPE_PRIMITIVE: {
    const char *n = type->name;
    if (strcmp(n, "i8") == 0)
      return LLVMInt8TypeInContext(gen->context);
    if (strcmp(n, "i16") == 0)
      return LLVMInt16TypeInContext(gen->context);
    if (strcmp(n, "i32") == 0)
      return LLVMInt32TypeInContext(gen->context);
    if (strcmp(n, "i64") == 0)
      return LLVMInt64TypeInContext(gen->context);
    if (strcmp(n, "i128") == 0)
      return LLVMInt128TypeInContext(gen->context);
    if (strcmp(n, "isize") == 0)
      return LLVMInt64TypeInContext(gen->context);
    if (strcmp(n, "u8") == 0)
      return LLVMInt8TypeInContext(gen->context);
    if (strcmp(n, "u16") == 0)
      return LLVMInt16TypeInContext(gen->context);
    if (strcmp(n, "u32") == 0)
      return LLVMInt32TypeInContext(gen->context);
    if (strcmp(n, "u64") == 0)
      return LLVMInt64TypeInContext(gen->context);
    if (strcmp(n, "u128") == 0)
      return LLVMInt128TypeInContext(gen->context);
    if (strcmp(n, "usize") == 0)
      return LLVMInt64TypeInContext(gen->context);
    if (strcmp(n, "f32") == 0)
      return LLVMFloatTypeInContext(gen->context);
    if (strcmp(n, "f64") == 0)
      return LLVMDoubleTypeInContext(gen->context);
    if (strcmp(n, "bool") == 0)
      return LLVMInt1TypeInContext(gen->context);
    if (strcmp(n, "char") == 0)
      return LLVMInt32TypeInContext(gen->context);
    if (strcmp(n, "void") == 0)
      return LLVMVoidTypeInContext(gen->context);
    if (strcmp(n, "str") == 0)
      return LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
    return LLVMInt32TypeInContext(gen->context);
  }
  case TYPE_ARRAY: {
    LLVMTypeRef elem_type = type_info_to_llvm(gen, type->element_type);
    LLVMTypeRef fields[] = {
        LLVMPointerType(elem_type, 0),        // data
        LLVMInt64TypeInContext(gen->context), // len
        LLVMInt64TypeInContext(gen->context)  // cap
    };
    return LLVMStructTypeInContext(gen->context, fields, 3, 0);
  }
  case TYPE_AUTO:
    // This shouldn't happen during normal codegen if inference worked,
    // unless we look up type of an auto variable before it's resolved or in a
    // context where it's not allowed. For now, return void pointer or similar
    // as placeholder? Actually, llvm type of 'auto' is meaningless until
    // inferred. But to satisfy the switch:
    fprintf(stderr, "Error: Unexpected TYPE_AUTO in codegen\n");
    exit(1);
  case TYPE_TUPLE: {
    LLVMTypeRef *fields = malloc(sizeof(LLVMTypeRef) * type->tuple_count);
    for (int i = 0; i < type->tuple_count; i++)
      fields[i] = type_info_to_llvm(gen, type->tuple_types[i]);
    LLVMTypeRef t =
        LLVMStructTypeInContext(gen->context, fields, type->tuple_count, 0);
    free(fields);
    return t;
  }
  case TYPE_DICT:
  case TYPE_SET:
    return LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0);
  case TYPE_POINTER:
    return LLVMPointerType(type_info_to_llvm(gen, type->element_type), 0);
  case TYPE_STRUCT: {
    StructInfo *info = ensure_struct(gen, type->name);
    if (!info)
      return LLVMInt32TypeInContext(gen->context);
    return info->llvm_type;
  }
  }
  return LLVMInt32TypeInContext(gen->context);
}

static int struct_field_index(TypeInfo *type, const char *field) {
  if (!type || type->kind != TYPE_STRUCT)
    return -1;
  TypeInfo *target = type->struct_def ? type->struct_def : type;
  for (int i = 0; i < target->field_count; i++) {
    if (strcmp(target->field_names[i], field) == 0)
      return i;
  }
  return -1;
}

static void finalize_struct_bodies(CodeGen *gen) {
  for (int i = 0; i < gen->struct_count; i++) {
    StructInfo *info = &gen->structs[i];
    if (!info->decl || !LLVMIsOpaqueStruct(info->llvm_type))
      continue;
    int field_count = info->decl->data.struct_decl.type->field_count;
    LLVMTypeRef *fields = NULL;
    if (field_count > 0)
      fields = malloc(sizeof(LLVMTypeRef) * field_count);
    for (int f = 0; f < field_count; f++) {
      fields[f] = type_info_to_llvm(
          gen, info->decl->data.struct_decl.type->field_types[f]);
    }
    LLVMStructSetBody(info->llvm_type, fields, field_count, 0);
    if (fields)
      free(fields);
  }
}

static LLVMValueRef cast_value_to_type(CodeGen *gen, LLVMValueRef val,
                                       TypeInfo *target) {
  if (!target)
    return val;
  LLVMTypeRef target_ty = type_info_to_llvm(gen, target);
  LLVMTypeRef val_ty = LLVMTypeOf(val);
  if (target_ty == val_ty)
    return val;

  LLVMTypeKind tk = LLVMGetTypeKind(target_ty);
  LLVMTypeKind vk = LLVMGetTypeKind(val_ty);

  if (tk == LLVMFloatTypeKind || tk == LLVMDoubleTypeKind) {
    if (vk == LLVMIntegerTypeKind)
      return LLVMBuildSIToFP(gen->builder, val, target_ty, "inttofp");
    if (vk == LLVMDoubleTypeKind && tk == LLVMFloatTypeKind)
      return LLVMBuildFPTrunc(gen->builder, val, target_ty, "fptrunc");
    if (vk == LLVMFloatTypeKind && tk == LLVMDoubleTypeKind)
      return LLVMBuildFPExt(gen->builder, val, target_ty, "fpext");
  }
  if (tk == LLVMIntegerTypeKind && vk == LLVMIntegerTypeKind) {
    unsigned tw = LLVMGetIntTypeWidth(target_ty);
    unsigned vw = LLVMGetIntTypeWidth(val_ty);
    if (vw > tw)
      return LLVMBuildTrunc(gen->builder, val, target_ty, "trunc");
    if (vw < tw)
      return LLVMBuildZExt(gen->builder, val, target_ty, "zext");
  }

  return val;
}

static TypeInfo *resolve_type(CodeGen *gen, ASTNode *node);

static const char *get_struct_name_for_receiver(CodeGen *gen, ASTNode *recv,
                                                TypeInfo **out_type,
                                                int *is_pointer) {
  if (is_pointer)
    *is_pointer = 0;
  TypeInfo *rt = resolve_type(gen, recv);
  if (out_type)
    *out_type = rt;
  if (rt) {
    if (rt->kind == TYPE_POINTER && rt->element_type &&
        rt->element_type->kind == TYPE_STRUCT) {
      if (is_pointer)
        *is_pointer = 1;
      return rt->element_type->name;
    }
    if (rt->kind == TYPE_STRUCT)
      return rt->name;
  }
  if (recv->type == NODE_IDENT) {
    const char *nm = recv->data.ident.name;
    if (lookup_struct(gen, nm))
      return nm;
  }
  return NULL;
}

static LLVMValueRef emit_expression(CodeGen *gen, ASTNode *node);

// Call printf with given format string and value
static void call_printf(CodeGen *gen, const char *fmt, LLVMValueRef val) {
  ensure_printf(gen);
  LLVMValueRef fmt_str = LLVMBuildGlobalStringPtr(gen->builder, fmt, "fmt");
  if (val) {
    LLVMValueRef args[2] = {fmt_str, val};
    LLVMBuildCall2(gen->builder, gen->printf_type, gen->printf_func, args, 2,
                   "");
  } else {
    LLVMBuildCall2(gen->builder, gen->printf_type, gen->printf_func, &fmt_str,
                   1, "");
  }
}

// Forward declare for emit_interpolated_string
static void emit_print_value(CodeGen *gen, LLVMValueRef val, TypeInfo *type);

static LLVMValueRef emit_expression(CodeGen *gen, ASTNode *node);
static void emit_print_value(CodeGen *gen, LLVMValueRef val, TypeInfo *type);

// Emit interpolated string by constructing a new string
static LLVMValueRef emit_interpolated_string_val(CodeGen *gen, ASTNode *node) {
  if (node->type != NODE_INTERPOLATED_STRING)
    return LLVMBuildGlobalStringPtr(gen->builder, "", "empty");

  ensure_gc_malloc(gen);
  LLVMValueRef current_str =
      LLVMBuildGlobalStringPtr(gen->builder, "", "empty_start");

  // Create buffer for int conversion (static sized buffer hack? better to
  // allocate) We'll alloc small buffer for numbers

  for (int i = 0; i < node->data.interpolated_string.count; i++) {
    ASTNode *part = node->data.interpolated_string.parts[i];
    LLVMValueRef part_str = NULL;

    if (part->type == NODE_STRING_LIT) {
      part_str = LLVMBuildGlobalStringPtr(gen->builder, part->data.string.value,
                                          "part_lit");
    } else {
      LLVMValueRef val = emit_expression(gen, part);
      LLVMTypeRef type = LLVMTypeOf(val);
      if (LLVMGetTypeKind(type) == LLVMPointerTypeKind) {
        // Assume string
        part_str = val;
      } else if (LLVMGetTypeKind(type) == LLVMIntegerTypeKind) {
        // Convert int to string
        LLVMValueRef buf = LLVMBuildCall2(
            gen->builder, LLVMGlobalGetValueType(gen->gc_malloc_func),
            gen->gc_malloc_func,
            (LLVMValueRef[]){
                LLVMConstInt(LLVMInt64TypeInContext(gen->context), 64, 0)},
            1, "int_buf");
        LLVMValueRef fmt =
            LLVMBuildGlobalStringPtr(gen->builder, "%lld", "fmt_int");
        // Cast val to i64 for snprintf
        LLVMValueRef val64 = LLVMBuildZExtOrBitCast(
            gen->builder, val, LLVMInt64TypeInContext(gen->context), "val64");

        LLVMValueRef args[] = {
            buf, LLVMConstInt(LLVMInt64TypeInContext(gen->context), 64, 0), fmt,
            val64};
        LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(get_snprintf(gen)),
                       get_snprintf(gen), args, 4, "sprintf_res");
        part_str = buf;
      } else if (LLVMGetTypeKind(type) == LLVMDoubleTypeKind ||
                 LLVMGetTypeKind(type) == LLVMFloatTypeKind) {
        // Float
        LLVMValueRef buf = LLVMBuildCall2(
            gen->builder, LLVMGlobalGetValueType(gen->gc_malloc_func),
            gen->gc_malloc_func,
            (LLVMValueRef[]){
                LLVMConstInt(LLVMInt64TypeInContext(gen->context), 64, 0)},
            1, "flt_buf");
        LLVMValueRef fmt =
            LLVMBuildGlobalStringPtr(gen->builder, "%g", "fmt_flt");
        LLVMValueRef val_dbl =
            LLVMBuildFPExt(gen->builder, val,
                           LLVMDoubleTypeInContext(gen->context), "val_dbl");
        LLVMValueRef args[] = {
            buf, LLVMConstInt(LLVMInt64TypeInContext(gen->context), 64, 0), fmt,
            val_dbl};
        LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(get_snprintf(gen)),
                       get_snprintf(gen), args, 4, "sprintf_res");
        part_str = buf;
      } else {
        // Fallback for unknown
        part_str = LLVMBuildGlobalStringPtr(gen->builder, "<unknown>", "unk");
      }
    }

    // Concat current_str and part_str
    LLVMValueRef len1 =
        LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(get_strlen(gen)),
                       get_strlen(gen), &current_str, 1, "l1");
    LLVMValueRef len2 =
        LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(get_strlen(gen)),
                       get_strlen(gen), &part_str, 1, "l2");
    LLVMValueRef total_len =
        LLVMBuildAdd(gen->builder, len1, len2, "total_len");
    LLVMValueRef total_len_plus_1 = LLVMBuildAdd(
        gen->builder, total_len,
        LLVMConstInt(LLVMInt64TypeInContext(gen->context), 1, 0), "alloc_len");

    // Alloc new string
    LLVMValueRef new_str = LLVMBuildCall2(
        gen->builder, LLVMGlobalGetValueType(gen->gc_malloc_func),
        gen->gc_malloc_func, &total_len_plus_1, 1, "new_str");

    // strcpy(new_str, current_str)
    LLVMValueRef args_cpy[] = {new_str, current_str};
    LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(get_strcpy(gen)),
                   get_strcpy(gen), args_cpy, 2, "");

    // strcat(new_str, part_str)
    LLVMValueRef args_cat[] = {new_str, part_str};
    LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(get_strcat(gen)),
                   get_strcat(gen), args_cat, 2, "");

    current_str = new_str;
  }

  return current_str;
}

// Emit print call for a value
static void emit_print_value(CodeGen *gen, LLVMValueRef val, TypeInfo *type) {
  LLVMTypeRef llvm_type = LLVMTypeOf(val);
  LLVMTypeKind kind = LLVMGetTypeKind(llvm_type);

  // Handle tuples
  if (type && type->kind == TYPE_TUPLE) {
    call_printf(gen, "(", NULL);
    // Need to store tuple to memory to extract fields
    LLVMValueRef tuple_alloca =
        LLVMBuildAlloca(gen->builder, llvm_type, "tup_print");
    LLVMBuildStore(gen->builder, val, tuple_alloca);
    for (int i = 0; i < type->tuple_count; i++) {
      if (i > 0)
        call_printf(gen, ", ", NULL);
      LLVMTypeRef field_type = type_info_to_llvm(gen, type->tuple_types[i]);
      LLVMValueRef field_ptr =
          LLVMBuildStructGEP2(gen->builder, llvm_type, tuple_alloca, i, "fp");
      LLVMValueRef field_val =
          LLVMBuildLoad2(gen->builder, field_type, field_ptr, "fv");
      emit_print_value(gen, field_val, type->tuple_types[i]);
    }
    call_printf(gen, ")", NULL);
    return;
  }

  // Handle arrays - print elements
  if (type && type->kind == TYPE_ARRAY) {
    call_printf(gen, "[", NULL);
    // LLVMTypeRef elem_llvm_type = type_info_to_llvm(gen, type->element_type);
    // We don't know array length at runtime, so print as pointer for now
    // For array literals, we know the count but it's not stored
    // Just print the pointer address for now
    call_printf(gen, "<array>", NULL);
    call_printf(gen, "]", NULL);
    return;
  }

  // Handle primitives
  if (type && type->kind == TYPE_PRIMITIVE) {
    const char *n = type->name;
    if (strcmp(n, "str") == 0) {
      call_printf(gen, "%s", val);
      return;
    }
    if (strcmp(n, "char") == 0) {
      call_printf(gen, "%c", val);
      return;
    }
    if (strcmp(n, "bool") == 0) {
      ensure_printf(gen);
      LLVMValueRef t = LLVMBuildGlobalStringPtr(gen->builder, "true", "t");
      LLVMValueRef f = LLVMBuildGlobalStringPtr(gen->builder, "false", "f");
      call_printf(gen, "%s", LLVMBuildSelect(gen->builder, val, t, f, "b"));
      return;
    }
    if (strcmp(n, "f32") == 0) {
      val = LLVMBuildFPExt(gen->builder, val,
                           LLVMDoubleTypeInContext(gen->context), "ext");
      call_printf(gen, "%g", val);
      return;
    }
    if (strcmp(n, "f64") == 0) {
      call_printf(gen, "%g", val);
      return;
    }
    if (strcmp(n, "i64") == 0 || strcmp(n, "u64") == 0 ||
        strcmp(n, "isize") == 0 || strcmp(n, "usize") == 0) {
      call_printf(gen, "%lld", val);
      return;
    }
    // Default integer
    if (LLVMGetIntTypeWidth(llvm_type) < 32)
      val = LLVMBuildSExt(gen->builder, val,
                          LLVMInt32TypeInContext(gen->context), "ext");
    call_printf(gen, "%d", val);
    return;
  }

  // Fallback based on LLVM type
  if (kind == LLVMPointerTypeKind) {
    call_printf(gen, "%s", val);
    return;
  }
  if (kind == LLVMIntegerTypeKind) {
    unsigned w = LLVMGetIntTypeWidth(llvm_type);
    if (w == 1) {
      ensure_printf(gen);
      LLVMValueRef t = LLVMBuildGlobalStringPtr(gen->builder, "true", "t");
      LLVMValueRef f = LLVMBuildGlobalStringPtr(gen->builder, "false", "f");
      call_printf(gen, "%s", LLVMBuildSelect(gen->builder, val, t, f, "b"));
    } else if (w <= 32) {
      if (w < 32)
        val = LLVMBuildSExt(gen->builder, val,
                            LLVMInt32TypeInContext(gen->context), "ext");
      call_printf(gen, "%d", val);
    } else {
      call_printf(gen, "%lld", val);
    }
    return;
  }
  if (kind == LLVMFloatTypeKind) {
    val = LLVMBuildFPExt(gen->builder, val,
                         LLVMDoubleTypeInContext(gen->context), "ext");
    call_printf(gen, "%g", val);
    return;
  }
  if (kind == LLVMDoubleTypeKind) {
    call_printf(gen, "%g", val);
    return;
  }
  if (kind == LLVMStructTypeKind) {
    // Unknown struct - print as tuple-like
    call_printf(gen, "(...)", NULL);
    return;
  }
  call_printf(gen, "<value>", NULL);
}

static TypeInfo *resolve_type(CodeGen *gen, ASTNode *node) {
  if (!node)
    return NULL;
  switch (node->type) {
  case NODE_IDENT: {
    Symbol *sym = symtable_lookup(gen->symbols, node->data.ident.name);
    return sym ? sym->c26_type : NULL;
  }
  case NODE_DEREF: {
    TypeInfo *sub = resolve_type(gen, node->data.unary.operand);
    return (sub && sub->kind == TYPE_POINTER) ? sub->element_type : NULL;
  }
  case NODE_ADDR_OF: {
    TypeInfo *sub = resolve_type(gen, node->data.unary.operand);
    if (!sub)
      return NULL;
    TypeInfo *ptr = type_info_new(TYPE_POINTER, NULL);
    ptr->element_type = sub;
    return ptr;
  }
  case NODE_INDEX: {
    TypeInfo *sub = resolve_type(gen, node->data.index.array);
    return (sub && (sub->kind == TYPE_POINTER || sub->kind == TYPE_ARRAY))
               ? sub->element_type
               : NULL;
  }
  case NODE_FIELD_ACCESS: {
    TypeInfo *obj = resolve_type(gen, node->data.field_access.object);
    if (obj && obj->kind == TYPE_ARRAY &&
        strcmp(node->data.field_access.field, "len") == 0) {
      return type_info_new(TYPE_PRIMITIVE, "i64");
    }
    int via_ptr = node->data.field_access.via_pointer;
    if (!via_ptr && obj && obj->kind == TYPE_POINTER)
      via_ptr = 1;
    if (via_ptr && obj && obj->kind == TYPE_POINTER)
      obj = obj->element_type;
    if (obj && obj->kind == TYPE_STRUCT) {
      int idx = struct_field_index(obj, node->data.field_access.field);
      if (idx >= 0)
        return obj->field_types[idx];
    }
    return NULL;
  }
  case NODE_STRUCT_LIT:
    return node->data.struct_lit.type;
  case NODE_METHOD_CALL: {
    const char *struct_name = NULL;
    TypeInfo *recv = resolve_type(gen, node->data.method_call.receiver);
    if (recv) {
      if (recv->kind == TYPE_POINTER && recv->element_type &&
          recv->element_type->kind == TYPE_STRUCT) {
        struct_name = recv->element_type->name;
      } else if (recv->kind == TYPE_STRUCT) {
        struct_name = recv->name;
      }
    } else if (node->data.method_call.receiver->type == NODE_IDENT) {
      const char *name = node->data.method_call.receiver->data.ident.name;
      if (lookup_struct(gen, name))
        struct_name = name;
    }
    if (struct_name) {
      MethodInfo *m =
          lookup_method(gen, struct_name, node->data.method_call.method);
      if (m)
        return m->func->data.func.return_type;
    }
    return NULL;
  }
  case NODE_ARRAY_LIT: {
    if (node->data.array.type)
      return node->data.array.type;
    if (node->data.array.count > 0) {
      TypeInfo *elem = resolve_type(gen, node->data.array.elements[0]);
      if (elem) {
        TypeInfo *at = type_info_new(TYPE_ARRAY, NULL);
        at->element_type = elem;
        return at;
      }
    }
    return NULL; // Empty array literal needs context
  }
  default:
    return NULL;
  }
}

// Helper to get the address of an expression (L-value)
static LLVMValueRef emit_lvalue(CodeGen *gen, ASTNode *node) {
  switch (node->type) {
  case NODE_IDENT: {
    Symbol *sym = symtable_lookup(gen->symbols, node->data.ident.name);
    if (sym)
      return sym->alloca;
    fprintf(stderr, "Undefined: %s\n", node->data.ident.name);
    return NULL;
  }
  case NODE_INDEX: {
    LLVMValueRef arr = emit_expression(gen, node->data.index.array);
    LLVMValueRef idx = emit_expression(gen, node->data.index.index);
    TypeInfo *arr_type = resolve_type(gen, node->data.index.array);
    LLVMTypeRef elem_ll_type = LLVMInt32TypeInContext(gen->context);

    LLVMValueRef data_ptr = arr;
    if (arr_type && arr_type->kind == TYPE_ARRAY) {
      // Extract data pointer from descriptor Struct { T* data, i64 len, i64 cap
      // }
      data_ptr = LLVMBuildExtractValue(gen->builder, arr, 0, "array.data");
    }

    if (arr_type && arr_type->element_type) {
      elem_ll_type = type_info_to_llvm(gen, arr_type->element_type);
    }
    return LLVMBuildGEP2(gen->builder, elem_ll_type, data_ptr, &idx, 1,
                         "index.ptr");
  }
  case NODE_DEREF:
    // Dereference of a pointer is its value (address)
    return emit_expression(gen, node->data.unary.operand);
  case NODE_FIELD_ACCESS: {
    TypeInfo *obj_type = resolve_type(gen, node->data.field_access.object);
    int via_ptr = node->data.field_access.via_pointer;

    // Auto-dereference: allow '.' on pointers
    if (!via_ptr && obj_type && obj_type->kind == TYPE_POINTER) {
      via_ptr = 1;
    }

    if (via_ptr && obj_type && obj_type->kind == TYPE_POINTER)
      obj_type = obj_type->element_type;

    if (!obj_type || obj_type->kind != TYPE_STRUCT) {
      fprintf(stderr, "Field access on non-struct type\n");
      return NULL;
    }
    int idx = struct_field_index(obj_type, node->data.field_access.field);
    if (idx < 0) {
      fprintf(stderr, "Unknown field: %s\n", node->data.field_access.field);
      return NULL;
    }

    LLVMValueRef base_ptr = NULL;
    if (via_ptr) {
      base_ptr = emit_expression(gen, node->data.field_access.object);
    } else {
      base_ptr = emit_lvalue(gen, node->data.field_access.object);
    }
    if (!base_ptr) {
      LLVMValueRef base_val =
          emit_expression(gen, node->data.field_access.object);
      base_ptr = LLVMBuildAlloca(gen->builder, type_info_to_llvm(gen, obj_type),
                                 "struct.tmp");
      LLVMBuildStore(gen->builder, base_val, base_ptr);
    }
    LLVMValueRef idxs[] = {
        LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0),
        LLVMConstInt(LLVMInt32TypeInContext(gen->context), idx, 0)};
    return LLVMBuildGEP2(gen->builder, type_info_to_llvm(gen, obj_type),
                         base_ptr, idxs, 2, "field.ptr");
  }
  default:
    fprintf(stderr, "Expression is not an L-value\n");
    return NULL;
  }
}

static LLVMValueRef emit_expression(CodeGen *gen, ASTNode *node) {
  if (!node)
    return NULL;

  switch (node->type) {
  case NODE_INT_LIT:
    return LLVMConstInt(LLVMInt32TypeInContext(gen->context),
                        atoll(node->data.literal.value), 1);
  case NODE_FLOAT_LIT:
    return LLVMConstReal(LLVMDoubleTypeInContext(gen->context),
                         atof(node->data.literal.value));
  case NODE_BOOL_LIT:
    return LLVMConstInt(LLVMInt1TypeInContext(gen->context),
                        node->data.boolean.value, 0);
  case NODE_CHAR_LIT: {
    char c = node->data.character.value[0];
    if (c == '\\' && node->data.character.value[1]) {
      switch (node->data.character.value[1]) {
      case 'n':
        c = '\n';
        break;
      case 't':
        c = '\t';
        break;
      case 'r':
        c = '\r';
        break;
      case '0':
        c = '\0';
        break;
      default:
        c = node->data.character.value[1];
      }
    }
    return LLVMConstInt(LLVMInt32TypeInContext(gen->context), c, 0);
  }
  case NODE_STRING_LIT:
    return LLVMBuildGlobalStringPtr(gen->builder, node->data.string.value,
                                    "str");
  case NODE_IDENT: {
    Symbol *sym = symtable_lookup(gen->symbols, node->data.ident.name);
    if (sym)
      return LLVMBuildLoad2(gen->builder, sym->type, sym->alloca,
                            node->data.ident.name);
    fprintf(stderr, "Undefined: %s\n", node->data.ident.name);
    return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
  }
  case NODE_FIELD_ACCESS: {
    TypeInfo *obj_type = resolve_type(gen, node->data.field_access.object);
    if (obj_type && obj_type->kind == TYPE_ARRAY &&
        strcmp(node->data.field_access.field, "len") == 0) {
      LLVMValueRef arr = emit_expression(gen, node->data.field_access.object);
      return LLVMBuildExtractValue(gen->builder, arr, 1, "array.len");
    }
    LLVMValueRef ptr = emit_lvalue(gen, node);
    if (!ptr)
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    TypeInfo *ftype = resolve_type(gen, node);
    LLVMTypeRef ll_type = ftype ? type_info_to_llvm(gen, ftype)
                                : LLVMInt32TypeInContext(gen->context);
    return LLVMBuildLoad2(gen->builder, ll_type, ptr, "field");
  }
  case NODE_DEREF: {
    LLVMValueRef ptr = emit_expression(gen, node->data.unary.operand);
    TypeInfo *elem_type_info = resolve_type(gen, node);
    LLVMTypeRef elem_type = elem_type_info
                                ? type_info_to_llvm(gen, elem_type_info)
                                : LLVMInt32TypeInContext(gen->context);
    return LLVMBuildLoad2(gen->builder, elem_type, ptr, "deref");
  }
  case NODE_ADDR_OF:
    return emit_lvalue(gen, node->data.unary.operand);
  case NODE_ASSIGN: {
    if (node->data.assign.value &&
        node->data.assign.value->type == NODE_STRUCT_LIT &&
        !node->data.assign.value->data.struct_lit.type) {
      node->data.assign.value->data.struct_lit.type =
          resolve_type(gen, node->data.assign.lhs);
    }
    LLVMValueRef lval = emit_lvalue(gen, node->data.assign.lhs);
    LLVMValueRef rval = emit_expression(gen, node->data.assign.value);
    if (lval) {
      LLVMTypeRef rtype = LLVMTypeOf(rval);
      // Heuristic: get type from lval if it's an alloca or GEP
      // Actually, it's safer to resolve it via AST if possible.
      TypeInfo *ltinfo = resolve_type(gen, node->data.assign.lhs);
      if (ltinfo) {
        LLVMTypeRef ltype = type_info_to_llvm(gen, ltinfo);
        if (LLVMGetTypeKind(ltype) == LLVMIntegerTypeKind &&
            LLVMGetTypeKind(rtype) == LLVMIntegerTypeKind) {
          unsigned tw = LLVMGetIntTypeWidth(ltype);
          unsigned vw = LLVMGetIntTypeWidth(rtype);
          if (vw > tw)
            rval = LLVMBuildTrunc(gen->builder, rval, ltype, "trunc");
          else if (vw < tw)
            rval = LLVMBuildZExt(gen->builder, rval, ltype, "zext");
        }
      }
      LLVMBuildStore(gen->builder, rval, lval);
    }
    return rval;
  }
  case NODE_CAST: {
    LLVMValueRef val = emit_expression(gen, node->data.cast.expr);
    LLVMTypeRef target_ll = type_info_to_llvm(gen, node->data.cast.target_type);
    LLVMTypeRef src_ll = LLVMTypeOf(val);
    LLVMTypeKind target_kind = LLVMGetTypeKind(target_ll);
    LLVMTypeKind src_kind = LLVMGetTypeKind(src_ll);

    if (src_kind == target_kind) {
      if (src_kind == LLVMIntegerTypeKind) {
        unsigned sw = LLVMGetIntTypeWidth(src_ll);
        unsigned tw = LLVMGetIntTypeWidth(target_ll);
        if (sw < tw)
          return LLVMBuildZExt(gen->builder, val, target_ll, "zext");
        if (sw > tw)
          return LLVMBuildTrunc(gen->builder, val, target_ll, "trunc");
        return val;
      }
      if (src_kind == LLVMFloatTypeKind || src_kind == LLVMDoubleTypeKind) {
        return LLVMBuildFPCast(gen->builder, val, target_ll, "fpcast");
      }
      return LLVMBuildBitCast(gen->builder, val, target_ll, "bitcast");
    }

    // Float <-> Int
    if (target_kind == LLVMIntegerTypeKind &&
        (src_kind == LLVMFloatTypeKind || src_kind == LLVMDoubleTypeKind)) {
      return LLVMBuildFPToSI(gen->builder, val, target_ll, "fp2int");
    }
    if ((target_kind == LLVMFloatTypeKind ||
         target_kind == LLVMDoubleTypeKind) &&
        src_kind == LLVMIntegerTypeKind) {
      return LLVMBuildSIToFP(gen->builder, val, target_ll, "int2fp");
    }

    // Ptr <-> Int
    if (target_kind == LLVMPointerTypeKind && src_kind == LLVMIntegerTypeKind) {
      return LLVMBuildIntToPtr(gen->builder, val, target_ll, "int2ptr");
    }
    if (target_kind == LLVMIntegerTypeKind && src_kind == LLVMPointerTypeKind) {
      return LLVMBuildPtrToInt(gen->builder, val, target_ll, "ptr2int");
    }

    // Ptr <-> Ptr
    if (target_kind == LLVMPointerTypeKind && src_kind == LLVMPointerTypeKind) {
      return LLVMBuildBitCast(gen->builder, val, target_ll, "ptr_cast");
    }

    return LLVMBuildBitCast(gen->builder, val, target_ll, "cast");
  }
  case NODE_BINARY_OP: {
    const char *op = node->data.binary.op;

    // Short-circuiting AND (&&)
    // Short-circuiting AND (&&)
    if (strcmp(op, "&&") == 0) {
      LLVMValueRef l = emit_expression(gen, node->data.binary.left);
      LLVMBasicBlockRef lhs_end_bb = LLVMGetInsertBlock(gen->builder);
      LLVMValueRef fn = LLVMGetBasicBlockParent(lhs_end_bb);

      // Ensure bool
      if (LLVMGetTypeKind(LLVMTypeOf(l)) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(LLVMTypeOf(l)) != 1) {
        l = LLVMBuildICmp(gen->builder, LLVMIntNE, l,
                          LLVMConstInt(LLVMTypeOf(l), 0, 0), "tobool");
      }

      LLVMBasicBlockRef rhs_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "and.rhs");
      LLVMBasicBlockRef end_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "and.end");

      LLVMBuildCondBr(gen->builder, l, rhs_bb, end_bb);

      LLVMPositionBuilderAtEnd(gen->builder, rhs_bb);
      LLVMValueRef r = emit_expression(gen, node->data.binary.right);
      LLVMBasicBlockRef rhs_end_bb = LLVMGetInsertBlock(gen->builder);

      // Ensure bool
      if (LLVMGetTypeKind(LLVMTypeOf(r)) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(LLVMTypeOf(r)) != 1) {
        r = LLVMBuildICmp(gen->builder, LLVMIntNE, r,
                          LLVMConstInt(LLVMTypeOf(r), 0, 0), "tobool");
      }

      LLVMBuildBr(gen->builder, end_bb);

      LLVMPositionBuilderAtEnd(gen->builder, end_bb);
      LLVMValueRef phi = LLVMBuildPhi(
          gen->builder, LLVMInt1TypeInContext(gen->context), "and.res");
      LLVMValueRef vals[] = {
          LLVMConstInt(LLVMInt1TypeInContext(gen->context), 0, 0), r};
      LLVMBasicBlockRef blocks[] = {lhs_end_bb, rhs_end_bb};
      LLVMAddIncoming(phi, vals, blocks, 2);
      return phi;
    }

    // Short-circuiting OR (||)
    if (strcmp(op, "||") == 0) {
      LLVMValueRef l = emit_expression(gen, node->data.binary.left);
      LLVMBasicBlockRef lhs_end_bb = LLVMGetInsertBlock(gen->builder);
      LLVMValueRef fn = LLVMGetBasicBlockParent(lhs_end_bb);

      // Ensure bool
      if (LLVMGetTypeKind(LLVMTypeOf(l)) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(LLVMTypeOf(l)) != 1) {
        l = LLVMBuildICmp(gen->builder, LLVMIntNE, l,
                          LLVMConstInt(LLVMTypeOf(l), 0, 0), "tobool");
      }

      LLVMBasicBlockRef rhs_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "or.rhs");
      LLVMBasicBlockRef end_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "or.end");

      LLVMBuildCondBr(gen->builder, l, end_bb, rhs_bb);

      LLVMPositionBuilderAtEnd(gen->builder, rhs_bb);
      LLVMValueRef r = emit_expression(gen, node->data.binary.right);
      LLVMBasicBlockRef rhs_end_bb = LLVMGetInsertBlock(gen->builder);

      // Ensure bool
      if (LLVMGetTypeKind(LLVMTypeOf(r)) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(LLVMTypeOf(r)) != 1) {
        r = LLVMBuildICmp(gen->builder, LLVMIntNE, r,
                          LLVMConstInt(LLVMTypeOf(r), 0, 0), "tobool");
      }

      LLVMBuildBr(gen->builder, end_bb);

      LLVMPositionBuilderAtEnd(gen->builder, end_bb);
      LLVMValueRef phi = LLVMBuildPhi(
          gen->builder, LLVMInt1TypeInContext(gen->context), "or.res");
      LLVMValueRef vals[] = {
          LLVMConstInt(LLVMInt1TypeInContext(gen->context), 1, 0), r};
      LLVMBasicBlockRef blocks[] = {lhs_end_bb, rhs_end_bb};
      LLVMAddIncoming(phi, vals, blocks, 2);
      return phi;
    }

    LLVMValueRef l = emit_expression(gen, node->data.binary.left);
    LLVMValueRef r = emit_expression(gen, node->data.binary.right);

    // Integer promotion
    if (LLVMGetTypeKind(LLVMTypeOf(l)) == LLVMIntegerTypeKind &&
        LLVMGetTypeKind(LLVMTypeOf(r)) == LLVMIntegerTypeKind) {
      unsigned lw = LLVMGetIntTypeWidth(LLVMTypeOf(l));
      unsigned rw = LLVMGetIntTypeWidth(LLVMTypeOf(r));
      if (lw < rw) {
        l = LLVMBuildZExt(gen->builder, l, LLVMTypeOf(r), "zext.l");
      } else if (rw < lw) {
        r = LLVMBuildZExt(gen->builder, r, LLVMTypeOf(l), "zext.r");
      }
    }

    LLVMTypeRef lt = LLVMTypeOf(l);
    LLVMTypeRef rt = LLVMTypeOf(r);
    int is_float = (LLVMGetTypeKind(lt) == LLVMDoubleTypeKind ||
                    LLVMGetTypeKind(lt) == LLVMFloatTypeKind ||
                    LLVMGetTypeKind(rt) == LLVMDoubleTypeKind ||
                    LLVMGetTypeKind(rt) == LLVMFloatTypeKind);

    if (is_float) {
      if (strcmp(op, "+") == 0)
        return LLVMBuildFAdd(gen->builder, l, r, "fadd");
      if (strcmp(op, "-") == 0)
        return LLVMBuildFSub(gen->builder, l, r, "fsub");
      if (strcmp(op, "*") == 0)
        return LLVMBuildFMul(gen->builder, l, r, "fmul");
      if (strcmp(op, "/") == 0)
        return LLVMBuildFDiv(gen->builder, l, r, "fdiv");
      if (strcmp(op, "==") == 0)
        return LLVMBuildFCmp(gen->builder, LLVMRealOEQ, l, r, "feq");
      if (strcmp(op, "!=") == 0)
        return LLVMBuildFCmp(gen->builder, LLVMRealONE, l, r, "fne");
      if (strcmp(op, "<") == 0)
        return LLVMBuildFCmp(gen->builder, LLVMRealOLT, l, r, "flt");
      if (strcmp(op, ">") == 0)
        return LLVMBuildFCmp(gen->builder, LLVMRealOGT, l, r, "fgt");
      if (strcmp(op, "<=") == 0)
        return LLVMBuildFCmp(gen->builder, LLVMRealOLE, l, r, "fle");
      if (strcmp(op, ">=") == 0)
        return LLVMBuildFCmp(gen->builder, LLVMRealOGE, l, r, "fge");
    } else {
      if (strcmp(op, "+") == 0)
        return LLVMBuildAdd(gen->builder, l, r, "add");
      if (strcmp(op, "-") == 0)
        return LLVMBuildSub(gen->builder, l, r, "sub");
      if (strcmp(op, "*") == 0)
        return LLVMBuildMul(gen->builder, l, r, "mul");
      if (strcmp(op, "/") == 0)
        return LLVMBuildSDiv(gen->builder, l, r, "div");
      if (strcmp(op, "%") == 0)
        return LLVMBuildSRem(gen->builder, l, r, "mod");
      if (strcmp(op, "==") == 0)
        return LLVMBuildICmp(gen->builder, LLVMIntEQ, l, r, "eq");
      if (strcmp(op, "!=") == 0)
        return LLVMBuildICmp(gen->builder, LLVMIntNE, l, r, "ne");
      if (strcmp(op, "<") == 0)
        return LLVMBuildICmp(gen->builder, LLVMIntSLT, l, r, "lt");
      if (strcmp(op, ">") == 0)
        return LLVMBuildICmp(gen->builder, LLVMIntSGT, l, r, "gt");
      if (strcmp(op, "<=") == 0)
        return LLVMBuildICmp(gen->builder, LLVMIntSLE, l, r, "le");
      if (strcmp(op, ">=") == 0)
        return LLVMBuildICmp(gen->builder, LLVMIntSGE, l, r, "ge");
    }
    break;
  }
  case NODE_UNARY_OP: {
    const char *op = node->data.unary.op;
    if (strcmp(op, "-") == 0) {
      LLVMValueRef o = emit_expression(gen, node->data.unary.operand);
      if (LLVMGetTypeKind(LLVMTypeOf(o)) == LLVMDoubleTypeKind ||
          LLVMGetTypeKind(LLVMTypeOf(o)) == LLVMFloatTypeKind)
        return LLVMBuildFNeg(gen->builder, o, "fneg");
      return LLVMBuildNeg(gen->builder, o, "neg");
    }
    if (strcmp(op, "!") == 0) {
      LLVMValueRef o = emit_expression(gen, node->data.unary.operand);
      return LLVMBuildNot(gen->builder, o, "not");
    }
    if (strcmp(op, "++") == 0 || strcmp(op, "--") == 0) {
      LLVMValueRef ptr = emit_lvalue(gen, node->data.unary.operand);
      if (!ptr)
        return NULL;
      TypeInfo *type = resolve_type(gen, node->data.unary.operand);
      LLVMTypeRef ll_type = type ? type_info_to_llvm(gen, type)
                                 : LLVMInt32TypeInContext(gen->context);
      LLVMValueRef val =
          LLVMBuildLoad2(gen->builder, ll_type, ptr, "postfix.val");
      LLVMValueRef result;
      if (strcmp(op, "++") == 0) {
        if (LLVMGetTypeKind(ll_type) == LLVMDoubleTypeKind ||
            LLVMGetTypeKind(ll_type) == LLVMFloatTypeKind)
          result = LLVMBuildFAdd(gen->builder, val, LLVMConstReal(ll_type, 1.0),
                                 "finc");
        else
          result = LLVMBuildAdd(gen->builder, val, LLVMConstInt(ll_type, 1, 0),
                                "inc");
      } else {
        if (LLVMGetTypeKind(ll_type) == LLVMDoubleTypeKind ||
            LLVMGetTypeKind(ll_type) == LLVMFloatTypeKind)
          result = LLVMBuildFSub(gen->builder, val, LLVMConstReal(ll_type, 1.0),
                                 "fdec");
        else
          result = LLVMBuildSub(gen->builder, val, LLVMConstInt(ll_type, 1, 0),
                                "dec");
      }
      LLVMBuildStore(gen->builder, result, ptr);
      return val; // Postfix: return old value
    }
    break;
  }
  case NODE_TYPEOF: {
    LLVMValueRef val = emit_expression(gen, node->data.typeof_expr.expr);
    LLVMTypeRef type = LLVMTypeOf(val);
    LLVMTypeKind kind = LLVMGetTypeKind(type);
    const char *type_str = "unknown";

    if (kind == LLVMIntegerTypeKind) {
      if (LLVMGetIntTypeWidth(type) == 1)
        type_str = "bool";
      else
        type_str = "int";
    } else if (kind == LLVMDoubleTypeKind || kind == LLVMFloatTypeKind) {
      type_str = "float";
    } else if (kind == LLVMPointerTypeKind) {
      type_str = "string"; // Heuristic
    } else if (kind == LLVMArrayTypeKind) {
      type_str = "array";
    } else if (kind == LLVMStructTypeKind) {
      type_str = "tuple";
    }

    return LLVMBuildGlobalStringPtr(gen->builder, type_str, "typeof");
  }
  case NODE_ARRAY_LIT: {
    int cnt = node->data.array.count;
    TypeInfo *arr_type = resolve_type(gen, node);
    if (!arr_type || arr_type->kind != TYPE_ARRAY) {
      // Fallback or error
      return LLVMConstNull(
          LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0));
    }
    LLVMTypeRef elem_ll_type = type_info_to_llvm(gen, arr_type->element_type);
    LLVMTypeRef desc_ll_type = type_info_to_llvm(gen, arr_type);

    LLVMValueRef data_ptr = NULL;
    if (cnt > 0) {
      ensure_gc_malloc(gen);
      LLVMTypeRef size_type = LLVMInt64TypeInContext(gen->context);
      LLVMValueRef elem_size = LLVMSizeOf(elem_ll_type);
      LLVMValueRef total_size =
          LLVMBuildMul(gen->builder, elem_size, LLVMConstInt(size_type, cnt, 0),
                       "total_size");
      LLVMValueRef malloc_args[] = {total_size};
      LLVMValueRef raw_ptr = LLVMBuildCall2(
          gen->builder, LLVMGlobalGetValueType(gen->gc_malloc_func),
          gen->gc_malloc_func, malloc_args, 1, "malloc_res");
      data_ptr = LLVMBuildBitCast(
          gen->builder, raw_ptr, LLVMPointerType(elem_ll_type, 0), "typed_ptr");

      for (int i = 0; i < cnt; i++) {
        LLVMValueRef v = emit_expression(gen, node->data.array.elements[i]);
        LLVMValueRef idx =
            LLVMConstInt(LLVMInt64TypeInContext(gen->context), i, 0);
        LLVMValueRef e_ptr = LLVMBuildGEP2(gen->builder, elem_ll_type, data_ptr,
                                           &idx, 1, "e_ptr");
        LLVMBuildStore(gen->builder, v, e_ptr);
      }
    } else {
      data_ptr = LLVMConstNull(LLVMPointerType(elem_ll_type, 0));
    }

    LLVMValueRef desc = LLVMGetUndef(desc_ll_type);
    desc = LLVMBuildInsertValue(gen->builder, desc, data_ptr, 0, "set_data");
    desc = LLVMBuildInsertValue(
        gen->builder, desc,
        LLVMConstInt(LLVMInt64TypeInContext(gen->context), cnt, 0), 1,
        "set_len");
    desc = LLVMBuildInsertValue(
        gen->builder, desc,
        LLVMConstInt(LLVMInt64TypeInContext(gen->context), cnt, 0), 2,
        "set_cap");
    return desc;
  }
  case NODE_TUPLE_LIT: {
    int cnt = node->data.array.count;
    LLVMTypeRef *types = malloc(sizeof(LLVMTypeRef) * cnt);
    LLVMValueRef *vals = malloc(sizeof(LLVMValueRef) * cnt);
    for (int i = 0; i < cnt; i++) {
      vals[i] = emit_expression(gen, node->data.array.elements[i]);
      types[i] = LLVMTypeOf(vals[i]);
    }
    LLVMTypeRef tup_type = LLVMStructTypeInContext(gen->context, types, cnt, 0);
    LLVMValueRef tup = LLVMBuildAlloca(gen->builder, tup_type, "tuple");
    for (int i = 0; i < cnt; i++)
      LLVMBuildStore(gen->builder, vals[i],
                     LLVMBuildStructGEP2(gen->builder, tup_type, tup, i, "f"));
    LLVMValueRef result = LLVMBuildLoad2(gen->builder, tup_type, tup, "ld");
    free(types);
    free(vals);
    return result;
  }
  case NODE_STRUCT_LIT: {
    TypeInfo *stype = node->data.struct_lit.type;
    if (!stype && node->data.struct_lit.type_name) {
      StructInfo *info = lookup_struct(gen, node->data.struct_lit.type_name);
      if (info && info->decl)
        stype = info->decl->data.struct_decl.type;
    }
    if (!stype || stype->kind != TYPE_STRUCT) {
      fprintf(stderr, "Struct literal without known type\n");
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }
    ensure_struct(gen, stype->name);
    TypeInfo *target = stype->struct_def ? stype->struct_def : stype;
    int field_total = target->field_count;
    LLVMValueRef *field_vals =
        field_total > 0 ? calloc(field_total, sizeof(LLVMValueRef)) : NULL;

    for (int i = 0; i < node->data.struct_lit.field_count; i++) {
      const char *fname = node->data.struct_lit.field_names[i];
      int idx = struct_field_index(target, fname);
      if (idx < 0) {
        fprintf(stderr, "Unknown field in literal: %s\n", fname);
        continue;
      }
      ASTNode *fval_node = node->data.struct_lit.field_values[i];
      if (fval_node->type == NODE_ARRAY_LIT) {
        // Pass target type to array literal
        fval_node->data.array.type = target->field_types[idx];
      }
      LLVMValueRef fv = emit_expression(gen, fval_node);
      fv = cast_value_to_type(gen, fv, target->field_types[idx]);
      field_vals[idx] = fv;
    }

    LLVMValueRef result = LLVMGetUndef(type_info_to_llvm(gen, target));
    for (int i = 0; i < field_total; i++) {
      if (!field_vals || !field_vals[i]) {
        fprintf(stderr, "Missing field in struct literal\n");
        continue;
      }
      result = LLVMBuildInsertValue(gen->builder, result, field_vals[i], i,
                                    "setfield");
    }
    if (field_vals)
      free(field_vals);
    return result;
  }
  case NODE_CALL: {
    const char *name = node->data.call.name;
    // Built-in print/println
    if (strcmp(name, "print") == 0 || strcmp(name, "println") == 0) {
      int newline = strcmp(name, "println") == 0;
      for (int i = 0; i < node->data.call.arg_count; i++) {
        ASTNode *arg = node->data.call.args[i];
        if (arg->type == NODE_INTERPOLATED_STRING) {
          LLVMValueRef res = emit_interpolated_string_val(gen, arg);
          call_printf(gen, "%s", res);
        } else {
          LLVMValueRef val = emit_expression(gen, arg);
          TypeInfo *type = NULL;
          if (arg->type == NODE_IDENT) {
            Symbol *sym = symtable_lookup(gen->symbols, arg->data.ident.name);
            if (sym)
              type = sym->c26_type;
          }
          emit_print_value(gen, val, type);
        }
      }
      if (newline)
        call_printf(gen, "\n", NULL);
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }
    if (strcmp(name, "exit") == 0) {
      ensure_exit(gen);
      LLVMValueRef arg = emit_expression(gen, node->data.call.args[0]);
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->exit_func),
                            gen->exit_func, &arg, 1, "");
    }
    if (strcmp(name, "realloc") == 0) {
      ensure_gc_realloc(gen);
      LLVMValueRef args[2];
      args[0] = emit_expression(gen, node->data.call.args[0]);
      args[1] = emit_expression(gen, node->data.call.args[1]);
      if (LLVMGetIntTypeWidth(LLVMTypeOf(args[1])) < 64) {
        args[1] = LLVMBuildZExt(gen->builder, args[1],
                                LLVMInt64TypeInContext(gen->context), "szext");
      }
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->gc_realloc_func),
                            gen->gc_realloc_func, args, 2, "realloc_res");
    }
    if (strcmp(name, "calloc") == 0) {
      ensure_calloc(gen);
      LLVMValueRef args[2];
      args[0] = emit_expression(gen, node->data.call.args[0]);
      args[1] = emit_expression(gen, node->data.call.args[1]);
      if (LLVMGetIntTypeWidth(LLVMTypeOf(args[0])) < 64) {
        args[0] = LLVMBuildZExt(gen->builder, args[0],
                                LLVMInt64TypeInContext(gen->context), "szext");
      }
      if (LLVMGetIntTypeWidth(LLVMTypeOf(args[1])) < 64) {
        args[1] = LLVMBuildZExt(gen->builder, args[1],
                                LLVMInt64TypeInContext(gen->context), "szext");
      }
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->calloc_func),
                            gen->calloc_func, args, 2, "calloc_res");
    }
    if (strcmp(name, "malloc") == 0) {
      ensure_gc_malloc(gen);
      LLVMValueRef arg = emit_expression(gen, node->data.call.args[0]);
      if (LLVMGetIntTypeWidth(LLVMTypeOf(arg)) < 64) {
        arg = LLVMBuildZExt(gen->builder, arg,
                            LLVMInt64TypeInContext(gen->context), "szext");
      }
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->gc_malloc_func),
                            gen->gc_malloc_func, &arg, 1, "malloc_res");
    }
    if (strcmp(name, "free") == 0) {
      ensure_gc_free(gen);
      LLVMValueRef arg = emit_expression(gen, node->data.call.args[0]);
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->gc_free_func),
                            gen->gc_free_func, &arg, 1, "");
    }

    // Explicit manual versions
    if (strcmp(name, "manual_malloc") == 0) {
      ensure_malloc(gen);
      LLVMValueRef arg = emit_expression(gen, node->data.call.args[0]);
      if (LLVMGetIntTypeWidth(LLVMTypeOf(arg)) < 64) {
        arg = LLVMBuildZExt(gen->builder, arg,
                            LLVMInt64TypeInContext(gen->context), "szext");
      }
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->malloc_func),
                            gen->malloc_func, &arg, 1, "malloc_res");
    }
    if (strcmp(name, "manual_realloc") == 0) {
      ensure_realloc(gen);
      LLVMValueRef args[2];
      args[0] = emit_expression(gen, node->data.call.args[0]);
      args[1] = emit_expression(gen, node->data.call.args[1]);
      if (LLVMGetIntTypeWidth(LLVMTypeOf(args[1])) < 64) {
        args[1] = LLVMBuildZExt(gen->builder, args[1],
                                LLVMInt64TypeInContext(gen->context), "szext");
      }
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->realloc_func),
                            gen->realloc_func, args, 2, "realloc_res");
    }
    if (strcmp(name, "manual_free") == 0) {
      ensure_free(gen);
      LLVMValueRef arg = emit_expression(gen, node->data.call.args[0]);
      return LLVMBuildCall2(gen->builder,
                            LLVMGlobalGetValueType(gen->free_func),
                            gen->free_func, &arg, 1, "");
    }
    // General function call
    LLVMValueRef func = LLVMGetNamedFunction(gen->module, name);

    // Check visibility
    Symbol *sym = symtable_lookup(gen->globals, name);
    if (sym) {
      if (sym->is_local) {
        // Check if current file matches source file
        // If main (source_file might be NULL or set), logic handles it.
        // Using logic: if sym->source_file != NULL and gen->current != NULL and
        // mismatch -> Error
        if (sym->source_file && gen->current_source_file &&
            strcmp(sym->source_file, gen->current_source_file) != 0) {
          // But wait, included files can access each other if not local?
          // "local" means private to file.
          // So mismatch is error.
          fprintf(stderr,
                  "Error: Function '%s' is local to '%s' and cannot be "
                  "accessed from '%s'\n",
                  name, sym->source_file, gen->current_source_file);
          exit(1);
        }
      }
    }

    if (!func) {
      fprintf(stderr, "Undefined function: %s\n", name);
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }
    int arg_count = node->data.call.arg_count;
    LLVMValueRef *args = NULL;
    if (arg_count > 0) {
      args = malloc(sizeof(LLVMValueRef) * arg_count);
      for (int i = 0; i < arg_count; i++)
        args[i] = emit_expression(gen, node->data.call.args[i]);
    }
    LLVMTypeRef fn_type = LLVMGlobalGetValueType(func);
    LLVMValueRef result =
        LLVMBuildCall2(gen->builder, fn_type, func, args, arg_count, "call");
    if (args)
      free(args);
    return result;
  }
  case NODE_METHOD_CALL: {
    TypeInfo *recv_type = NULL;
    int recv_is_ptr = 0;

    TypeInfo *rt = resolve_type(gen, node->data.method_call.receiver);
    if (rt && rt->kind == TYPE_ARRAY &&
        strcmp(node->data.method_call.method, "append") == 0) {
      // Special case: array.append(val)
      // We need the L-value to update the descriptor
      LLVMValueRef desc_ptr = emit_lvalue(gen, node->data.method_call.receiver);
      if (!desc_ptr) {
        fprintf(stderr, "Cannot append to non-L-value array\n");
        return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
      }
      LLVMTypeRef desc_ll_type = type_info_to_llvm(gen, rt);
      LLVMValueRef desc =
          LLVMBuildLoad2(gen->builder, desc_ll_type, desc_ptr, "array.desc");

      LLVMValueRef data =
          LLVMBuildExtractValue(gen->builder, desc, 0, "array.data");
      LLVMValueRef len =
          LLVMBuildExtractValue(gen->builder, desc, 1, "array.len");
      LLVMValueRef cap =
          LLVMBuildExtractValue(gen->builder, desc, 2, "array.cap");

      // Check if len == cap
      LLVMValueRef full =
          LLVMBuildICmp(gen->builder, LLVMIntEQ, len, cap, "is_full");

      LLVMBasicBlockRef current_bb = LLVMGetInsertBlock(gen->builder);
      LLVMValueRef fn = LLVMGetBasicBlockParent(current_bb);
      LLVMBasicBlockRef grow_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "array.grow");
      LLVMBasicBlockRef next_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "array.append.next");

      LLVMBuildCondBr(gen->builder, full, grow_bb, next_bb);

      // Grow logic
      LLVMPositionBuilderAtEnd(gen->builder, grow_bb);
      LLVMValueRef new_cap =
          LLVMBuildAdd(gen->builder, cap,
                       LLVMConstInt(LLVMInt64TypeInContext(gen->context), 4, 0),
                       "new_cap_inc"); // Simplistic: +4
      // Double it instead?
      LLVMValueRef zero =
          LLVMConstInt(LLVMInt64TypeInContext(gen->context), 0, 0);
      LLVMValueRef is_zero =
          LLVMBuildICmp(gen->builder, LLVMIntEQ, cap, zero, "cap_is_zero");
      LLVMValueRef non_zero_grow =
          LLVMBuildMul(gen->builder, cap,
                       LLVMConstInt(LLVMInt64TypeInContext(gen->context), 2, 0),
                       "double_cap");
      new_cap = LLVMBuildSelect(
          gen->builder, is_zero,
          LLVMConstInt(LLVMInt64TypeInContext(gen->context), 4, 0),
          non_zero_grow, "new_cap");

      ensure_gc_realloc(gen);
      LLVMTypeRef elem_ll_type = type_info_to_llvm(gen, rt->element_type);
      LLVMValueRef elem_size = LLVMSizeOf(elem_ll_type);
      LLVMValueRef new_byte_size =
          LLVMBuildMul(gen->builder, new_cap, elem_size, "new_byte_size");

      LLVMValueRef realloc_args[] = {
          LLVMBuildBitCast(
              gen->builder, data,
              LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0),
              "data_void"),
          new_byte_size};
      LLVMValueRef new_data_raw = LLVMBuildCall2(
          gen->builder, LLVMGlobalGetValueType(gen->gc_realloc_func),
          gen->gc_realloc_func, realloc_args, 2, "realloc_res");
      LLVMValueRef new_data = LLVMBuildBitCast(gen->builder, new_data_raw,
                                               LLVMTypeOf(data), "new_data");

      // Update descriptor in memory
      LLVMValueRef data_ptr_in_desc = LLVMBuildStructGEP2(
          gen->builder, desc_ll_type, desc_ptr, 0, "desc.data");
      LLVMValueRef cap_ptr_in_desc = LLVMBuildStructGEP2(
          gen->builder, desc_ll_type, desc_ptr, 2, "desc.cap");
      LLVMBuildStore(gen->builder, new_data, data_ptr_in_desc);
      LLVMBuildStore(gen->builder, new_cap, cap_ptr_in_desc);

      LLVMBuildBr(gen->builder, next_bb);

      // Append logic
      LLVMPositionBuilderAtEnd(gen->builder, next_bb);
      // Reload len and data (since they might have changed)
      LLVMValueRef final_len =
          LLVMBuildLoad2(gen->builder, LLVMInt64TypeInContext(gen->context),
                         LLVMBuildStructGEP2(gen->builder, desc_ll_type,
                                             desc_ptr, 1, "ptr_len"),
                         "curr_len");
      LLVMValueRef final_data =
          LLVMBuildLoad2(gen->builder, LLVMPointerType(elem_ll_type, 0),
                         LLVMBuildStructGEP2(gen->builder, desc_ll_type,
                                             desc_ptr, 0, "ptr_data"),
                         "curr_data");

      LLVMValueRef new_elem =
          emit_expression(gen, node->data.method_call.args[0]);
      LLVMValueRef target_ptr = LLVMBuildGEP2(
          gen->builder, elem_ll_type, final_data, &final_len, 1, "target_ptr");
      LLVMBuildStore(gen->builder, new_elem, target_ptr);

      // Increment len
      LLVMValueRef inc_len = LLVMBuildAdd(
          gen->builder, final_len,
          LLVMConstInt(LLVMInt64TypeInContext(gen->context), 1, 0), "inc_len");
      LLVMBuildStore(gen->builder, inc_len,
                     LLVMBuildStructGEP2(gen->builder, desc_ll_type, desc_ptr,
                                         1, "ptr_len"));

      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }

    const char *struct_name = get_struct_name_for_receiver(
        gen, node->data.method_call.receiver, &recv_type, &recv_is_ptr);
    if (!struct_name) {
      fprintf(stderr, "Unknown receiver type for method call\n");
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }
    if (node->data.method_call.via_pointer)
      recv_is_ptr = 1;
    MethodInfo *m =
        lookup_method(gen, struct_name, node->data.method_call.method);
    if (!m) {
      fprintf(stderr, "Unknown method %s on %s\n",
              node->data.method_call.method, struct_name);
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }
    int total_args =
        node->data.method_call.arg_count + (m->expects_self ? 1 : 0);
    LLVMValueRef *args =
        total_args ? malloc(sizeof(LLVMValueRef) * total_args) : NULL;
    int arg_idx = 0;

    if (m->expects_self) {
      if (!recv_type && !recv_is_ptr) {
        fprintf(stderr, "Method %s expects receiver\n", m->method_name);
        if (args)
          free(args);
        return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
      }
      LLVMValueRef self_val = NULL;
      if (m->self_is_pointer) {
        if (recv_is_ptr) {
          self_val = emit_expression(gen, node->data.method_call.receiver);
        } else {
          LLVMValueRef lptr = emit_lvalue(gen, node->data.method_call.receiver);
          if (!lptr) {
            LLVMValueRef tmp_val =
                emit_expression(gen, node->data.method_call.receiver);
            LLVMValueRef tmp = LLVMBuildAlloca(
                gen->builder, type_info_to_llvm(gen, recv_type), "self.tmp");
            LLVMBuildStore(gen->builder, tmp_val, tmp);
            lptr = tmp;
          }
          self_val = lptr;
        }
      } else {
        if (recv_is_ptr) {
          TypeInfo *val_type = recv_type && recv_type->kind == TYPE_POINTER
                                   ? recv_type->element_type
                                   : recv_type;
          LLVMValueRef ptr =
              emit_expression(gen, node->data.method_call.receiver);
          self_val = LLVMBuildLoad2(
              gen->builder, type_info_to_llvm(gen, val_type), ptr, "self.val");
        } else {
          self_val = emit_expression(gen, node->data.method_call.receiver);
        }
      }
      args[arg_idx++] = self_val;
    }

    for (int i = 0; i < node->data.method_call.arg_count; i++) {
      LLVMValueRef a = emit_expression(gen, node->data.method_call.args[i]);
      int param_index = i + (m->expects_self ? 1 : 0);
      if (param_index < m->func->data.func.param_count)
        a = cast_value_to_type(gen, a,
                               m->func->data.func.param_types[param_index]);
      args[arg_idx++] = a;
    }

    LLVMValueRef func =
        LLVMGetNamedFunction(gen->module, m->func->data.func.name);
    if (!func) {
      fprintf(stderr, "Undefined function: %s\n", m->func->data.func.name);
      if (args)
        free(args);
      return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
    }
    LLVMTypeRef fn_type = LLVMGlobalGetValueType(func);
    LLVMValueRef result =
        LLVMBuildCall2(gen->builder, fn_type, func, args, total_args, "call");
    if (args)
      free(args);
    return result;
  }
  case NODE_DEST_ASSIGN: {
    LLVMValueRef rhs_val = emit_expression(gen, node->data.dest_assign.rhs);
    ASTNode *lhs = node->data.dest_assign.lhs;
    if (lhs->type != NODE_TUPLE_LIT) {
      fprintf(stderr, "Destructuring LHS must be a tuple literal\n");
      exit(1);
    }

    for (int i = 0; i < lhs->data.array.count; i++) {
      ASTNode *el = lhs->data.array.elements[i];
      if (el->type != NODE_IDENT) {
        fprintf(stderr, "Destructuring target must be identifier\n");
        exit(1);
      }
      char *name = el->data.ident.name;
      Symbol *sym = symtable_lookup(gen->symbols, name);
      if (!sym) {
        fprintf(stderr, "Unknown variable in destructuring: %s\n", name);
        exit(1);
      }
      // Use LLVMBuildExtractValue to get the element from the tuple/structure
      LLVMValueRef extracted =
          LLVMBuildExtractValue(gen->builder, rhs_val, i, "extract");
      LLVMBuildStore(gen->builder, extracted, sym->alloca);
    }
    return rhs_val;
  }
  case NODE_NULL_LIT:
    return LLVMConstNull(
        LLVMPointerType(LLVMInt8TypeInContext(gen->context), 0));
  case NODE_INDEX: {
    LLVMValueRef ptr = emit_lvalue(gen, node);
    TypeInfo *type = resolve_type(gen, node);
    LLVMTypeRef ll_type = type ? type_info_to_llvm(gen, type)
                               : LLVMInt32TypeInContext(gen->context);
    return LLVMBuildLoad2(gen->builder, ll_type, ptr, "index.val");
  }
  case NODE_TERNARY: {
    // Emit condition
    LLVMValueRef cond = emit_expression(gen, node->data.ternary.condition);
    // Ensure it's i1
    if (LLVMGetTypeKind(LLVMTypeOf(cond)) != LLVMIntegerTypeKind ||
        LLVMGetIntTypeWidth(LLVMTypeOf(cond)) != 1) {
      cond = LLVMBuildICmp(gen->builder, LLVMIntNE, cond,
                           LLVMConstInt(LLVMTypeOf(cond), 0, 0), "tobool");
    }
    LLVMValueRef then_val = emit_expression(gen, node->data.ternary.then_expr);
    LLVMValueRef else_val = emit_expression(gen, node->data.ternary.else_expr);
    return LLVMBuildSelect(gen->builder, cond, then_val, else_val, "ternary");
  }
  case NODE_MATCH_EXPR: {
    LLVMValueRef match_val = emit_expression(gen, node->data.match_expr.value);
    LLVMBasicBlockRef current_bb = LLVMGetInsertBlock(gen->builder);
    LLVMValueRef fn = LLVMGetBasicBlockParent(current_bb);

    LLVMBasicBlockRef end_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "match.end");

    int case_count = node->data.match_expr.case_count;
    LLVMValueRef *incoming_vals =
        malloc(sizeof(LLVMValueRef) * (case_count + 1));
    LLVMBasicBlockRef *incoming_blocks =
        malloc(sizeof(LLVMBasicBlockRef) * (case_count + 1));
    int incoming_count = 0;

    int default_idx = -1;

    // Process non-default cases
    for (int i = 0; i < case_count; i++) {
      if (node->data.match_expr.case_values[i] == NULL) {
        default_idx = i;
        continue;
      }

      LLVMBasicBlockRef case_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "match.case");
      LLVMBasicBlockRef next_bb =
          LLVMAppendBasicBlockInContext(gen->context, fn, "match.next");

      // Check condition in current block
      LLVMValueRef case_pat =
          emit_expression(gen, node->data.match_expr.case_values[i]);
      LLVMValueRef cond = LLVMBuildICmp(gen->builder, LLVMIntEQ, match_val,
                                        case_pat, "match.cmp");
      LLVMBuildCondBr(gen->builder, cond, case_bb, next_bb);

      // Emit body in case_bb
      LLVMPositionBuilderAtEnd(gen->builder, case_bb);
      LLVMValueRef res =
          emit_expression(gen, node->data.match_expr.case_bodies[i]);
      incoming_vals[incoming_count] = res;
      incoming_blocks[incoming_count] = LLVMGetInsertBlock(gen->builder);
      incoming_count++;
      LLVMBuildBr(gen->builder, end_bb);

      // Move to next_bb
      LLVMPositionBuilderAtEnd(gen->builder, next_bb);
      current_bb = next_bb;
    }

    // Handle default or fallthrough
    if (default_idx != -1) {
      LLVMValueRef res =
          emit_expression(gen, node->data.match_expr.case_bodies[default_idx]);
      incoming_vals[incoming_count] = res;
      incoming_blocks[incoming_count] = LLVMGetInsertBlock(gen->builder);
      incoming_count++;
      LLVMBuildBr(gen->builder, end_bb);
    } else {
      LLVMValueRef res =
          LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
      incoming_vals[incoming_count] = res;
      incoming_blocks[incoming_count] = LLVMGetInsertBlock(gen->builder);
      incoming_count++;
      LLVMBuildBr(gen->builder, end_bb);
    }

    LLVMPositionBuilderAtEnd(gen->builder, end_bb);
    if (incoming_count > 0) {
      LLVMValueRef phi = LLVMBuildPhi(
          gen->builder, LLVMTypeOf(incoming_vals[0]), "match.result");
      LLVMAddIncoming(phi, incoming_vals, incoming_blocks, incoming_count);
      free(incoming_vals);
      free(incoming_blocks);
      return phi;
    }
    free(incoming_vals);
    free(incoming_blocks);
    return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
  }
  case NODE_INTERPOLATED_STRING: {
    return emit_interpolated_string_val(gen, node);
  }
  case NODE_SIZEOF: {
    LLVMTypeRef ll_type;
    if (node->data.s_of.target_type) {
      ll_type = type_info_to_llvm(gen, node->data.s_of.target_type);
    } else {
      ll_type = LLVMTypeOf(emit_expression(gen, node->data.s_of.expr));
    }
    return LLVMSizeOf(ll_type);
  }
  default:
    break;
  }
  return LLVMConstInt(LLVMInt32TypeInContext(gen->context), 0, 0);
}

static void emit_statement(CodeGen *gen, ASTNode *node) {
  if (!node)
    return;
  switch (node->type) {
  case NODE_RETURN_STMT:
    if (node->data.ret.value)
      LLVMBuildRet(gen->builder, emit_expression(gen, node->data.ret.value));
    else
      LLVMBuildRetVoid(gen->builder);
    break;
  case NODE_BLOCK:
    for (int i = 0; i < node->data.block.count; i++)
      emit_statement(gen, node->data.block.statements[i]);
    break;
  case NODE_VAR_DECL: {
    // Handle auto type inference
    LLVMTypeRef t;
    if (node->data.var.var_type->kind == TYPE_AUTO) {
      if (!node->data.var.init) {
        fprintf(stderr, "Error: auto variable must have an initializer\n");
        exit(1);
      }
      LLVMValueRef init_val_temp = emit_expression(gen, node->data.var.init);
      t = LLVMTypeOf(init_val_temp);
      TypeInfo *sym_type = node->data.var.var_type;
      if (node->data.var.init->type == NODE_STRUCT_LIT &&
          node->data.var.init->data.struct_lit.type) {
        sym_type = node->data.var.init->data.struct_lit.type;
      }
      // We need to re-emit or just save the value?
      // emit_expression might have side effects.
      // But LLVM IR generation is adding instructions.
      // We can't easily "undo" emit.
      // So we should capture the value and reuse it.
      LLVMValueRef a = LLVMBuildAlloca(gen->builder, t, node->data.var.name);
      symtable_add(gen->symbols, node->data.var.name, a, t, sym_type, 0, NULL);
      LLVMBuildStore(gen->builder, init_val_temp, a);
    } else {
      if (node->data.var.init && node->data.var.init->type == NODE_STRUCT_LIT &&
          !node->data.var.init->data.struct_lit.type) {
        node->data.var.init->data.struct_lit.type = node->data.var.var_type;
      }
      t = type_info_to_llvm(gen, node->data.var.var_type);
      LLVMValueRef a = LLVMBuildAlloca(gen->builder, t, node->data.var.name);
      symtable_add(gen->symbols, node->data.var.name, a, t,
                   node->data.var.var_type, 0, NULL);
      if (node->data.var.init) {
        LLVMValueRef init_val = emit_expression(gen, node->data.var.init);
        LLVMTypeRef val_type = LLVMTypeOf(init_val);
        // Auto-cast double to float (f64 -> f32)
        if (LLVMGetTypeKind(t) == LLVMFloatTypeKind &&
            LLVMGetTypeKind(val_type) == LLVMDoubleTypeKind) {
          init_val = LLVMBuildFPTrunc(gen->builder, init_val, t, "ftrunc");
        }
        // Auto-cast int to float
        if (LLVMGetTypeKind(t) == LLVMFloatTypeKind &&
            LLVMGetTypeKind(val_type) == LLVMIntegerTypeKind) {
          init_val = LLVMBuildSIToFP(gen->builder, init_val, t, "sitofp");
        }
        // Auto-cast int to double
        if (LLVMGetTypeKind(t) == LLVMDoubleTypeKind &&
            LLVMGetTypeKind(val_type) == LLVMIntegerTypeKind) {
          init_val = LLVMBuildSIToFP(gen->builder, init_val, t, "sitofp");
        }
        // Integer width conversion
        if (LLVMGetTypeKind(t) == LLVMIntegerTypeKind &&
            LLVMGetTypeKind(val_type) == LLVMIntegerTypeKind) {
          unsigned tw = LLVMGetIntTypeWidth(t);
          unsigned vw = LLVMGetIntTypeWidth(val_type);
          if (vw > tw)
            init_val = LLVMBuildTrunc(gen->builder, init_val, t, "itrunc");
          else if (vw < tw)
            init_val = LLVMBuildZExt(gen->builder, init_val, t, "izext");
        }
        LLVMBuildStore(gen->builder, init_val, a);
      }
    }
    break;
  }
  case NODE_EXPR_STMT:
    emit_expression(gen, node->data.ret.value);
    break;
  case NODE_IF_STMT: {
    // Get parent function for basic blocks
    LLVMValueRef fn = LLVMGetBasicBlockParent(LLVMGetInsertBlock(gen->builder));

    // Create basic blocks
    LLVMBasicBlockRef then_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "then");
    LLVMBasicBlockRef else_bb =
        node->data.if_stmt.else_block
            ? LLVMAppendBasicBlockInContext(gen->context, fn, "else")
            : NULL;
    LLVMBasicBlockRef merge_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "ifcont");

    // Emit condition
    LLVMValueRef cond = emit_expression(gen, node->data.if_stmt.condition);
    // Ensure condition is i1
    if (LLVMGetTypeKind(LLVMTypeOf(cond)) != LLVMIntegerTypeKind ||
        LLVMGetIntTypeWidth(LLVMTypeOf(cond)) != 1) {
      cond = LLVMBuildICmp(gen->builder, LLVMIntNE, cond,
                           LLVMConstInt(LLVMTypeOf(cond), 0, 0), "tobool");
    }

    // Branch
    LLVMBuildCondBr(gen->builder, cond, then_bb, else_bb ? else_bb : merge_bb);

    // Emit then block
    LLVMPositionBuilderAtEnd(gen->builder, then_bb);
    emit_statement(gen, node->data.if_stmt.then_block);
    // Only add branch if block doesn't already have a terminator
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(gen->builder)))
      LLVMBuildBr(gen->builder, merge_bb);

    // Emit else block
    if (else_bb) {
      LLVMPositionBuilderAtEnd(gen->builder, else_bb);
      emit_statement(gen, node->data.if_stmt.else_block);
      if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(gen->builder)))
        LLVMBuildBr(gen->builder, merge_bb);
    }

    // Continue in merge block
    LLVMPositionBuilderAtEnd(gen->builder, merge_bb);
    break;
  }
  case NODE_WHILE_STMT: {
    LLVMValueRef fn = LLVMGetBasicBlockParent(LLVMGetInsertBlock(gen->builder));
    LLVMBasicBlockRef cond_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "while.cond");
    LLVMBasicBlockRef body_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "while.body");
    LLVMBasicBlockRef end_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "while.end");

    // Jump to condition
    LLVMBuildBr(gen->builder, cond_bb);

    // Condition block
    LLVMPositionBuilderAtEnd(gen->builder, cond_bb);
    LLVMValueRef cond = emit_expression(gen, node->data.while_stmt.condition);
    if (LLVMGetTypeKind(LLVMTypeOf(cond)) != LLVMIntegerTypeKind ||
        LLVMGetIntTypeWidth(LLVMTypeOf(cond)) != 1) {
      cond = LLVMBuildICmp(gen->builder, LLVMIntNE, cond,
                           LLVMConstInt(LLVMTypeOf(cond), 0, 0), "tobool");
    }
    LLVMBuildCondBr(gen->builder, cond, body_bb, end_bb);

    // Body block
    LLVMPositionBuilderAtEnd(gen->builder, body_bb);
    emit_statement(gen, node->data.while_stmt.body);
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(gen->builder)))
      LLVMBuildBr(gen->builder, cond_bb); // Loop back

    // End block
    LLVMPositionBuilderAtEnd(gen->builder, end_bb);
    break;
  }

  case NODE_DO_WHILE: {
    LLVMValueRef fn = LLVMGetBasicBlockParent(LLVMGetInsertBlock(gen->builder));
    LLVMBasicBlockRef body_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "do.body");
    LLVMBasicBlockRef cond_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "do.cond");
    LLVMBasicBlockRef end_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "do.end");

    LLVMBuildBr(gen->builder, body_bb);

    // Body block
    LLVMPositionBuilderAtEnd(gen->builder, body_bb);
    LLVMBasicBlockRef old_break = gen->break_target;
    gen->break_target = end_bb;
    emit_statement(gen, node->data.do_while.body);
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(gen->builder)))
      LLVMBuildBr(gen->builder, cond_bb);

    // Condition block
    LLVMPositionBuilderAtEnd(gen->builder, cond_bb);
    LLVMValueRef cond = emit_expression(gen, node->data.do_while.condition);
    if (LLVMGetTypeKind(LLVMTypeOf(cond)) != LLVMIntegerTypeKind ||
        LLVMGetIntTypeWidth(LLVMTypeOf(cond)) != 1) {
      cond = LLVMBuildICmp(gen->builder, LLVMIntNE, cond,
                           LLVMConstInt(LLVMTypeOf(cond), 0, 0), "tobool");
    }
    LLVMBuildCondBr(gen->builder, cond, body_bb, end_bb);

    // End block
    LLVMPositionBuilderAtEnd(gen->builder, end_bb);
    gen->break_target = old_break;
    break;
  }

  case NODE_BREAK_STMT:
    if (gen->break_target)
      LLVMBuildBr(gen->builder, gen->break_target);
    break;
  case NODE_FOR_STMT: {
    LLVMValueRef fn = LLVMGetBasicBlockParent(LLVMGetInsertBlock(gen->builder));
    LLVMBasicBlockRef cond_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "for.cond");
    LLVMBasicBlockRef body_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "for.body");
    LLVMBasicBlockRef update_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "for.update");
    LLVMBasicBlockRef end_bb =
        LLVMAppendBasicBlockInContext(gen->context, fn, "for.end");

    // Save old break target
    LLVMBasicBlockRef old_break = gen->break_target;
    gen->break_target = end_bb;

    // Init
    if (node->data.for_stmt.init)
      emit_statement(gen, node->data.for_stmt.init);
    LLVMBuildBr(gen->builder, cond_bb);

    // Condition
    LLVMPositionBuilderAtEnd(gen->builder, cond_bb);
    if (node->data.for_stmt.condition) {
      LLVMValueRef cond = emit_expression(gen, node->data.for_stmt.condition);
      if (LLVMGetTypeKind(LLVMTypeOf(cond)) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(LLVMTypeOf(cond)) != 1) {
        cond = LLVMBuildICmp(gen->builder, LLVMIntNE, cond,
                             LLVMConstInt(LLVMTypeOf(cond), 0, 0), "tobool");
      }
      LLVMBuildCondBr(gen->builder, cond, body_bb, end_bb);
    } else {
      LLVMBuildBr(gen->builder, body_bb); // Infinite loop if no condition
    }

    // Body
    LLVMPositionBuilderAtEnd(gen->builder, body_bb);
    emit_statement(gen, node->data.for_stmt.body);
    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(gen->builder)))
      LLVMBuildBr(gen->builder, update_bb);

    // Update
    LLVMPositionBuilderAtEnd(gen->builder, update_bb);
    if (node->data.for_stmt.update)
      emit_expression(gen, node->data.for_stmt.update);
    LLVMBuildBr(gen->builder, cond_bb);

    // End
    LLVMPositionBuilderAtEnd(gen->builder, end_bb);
    gen->break_target = old_break;
    break;
  }
  default:
    break;
  }
}

static void emit_function(CodeGen *gen, ASTNode *node) {
  symtable_clear(gen->symbols);

  // Build function type with parameters
  LLVMTypeRef ret = type_info_to_llvm(gen, node->data.func.return_type);
  int param_count = node->data.func.param_count;
  LLVMTypeRef *param_types = NULL;
  if (param_count > 0) {
    param_types = malloc(sizeof(LLVMTypeRef) * param_count);
    for (int i = 0; i < param_count; i++)
      param_types[i] = type_info_to_llvm(gen, node->data.func.param_types[i]);
  }
  LLVMTypeRef fn_type = LLVMFunctionType(ret, param_types, param_count, 0);
  LLVMValueRef fn = LLVMAddFunction(gen->module, node->data.func.name, fn_type);
  if (param_types)
    free(param_types);

  if (node->data.func.is_inline) {
    unsigned kind_id = LLVMGetEnumAttributeKindForName("alwaysinline", 12);
    LLVMAttributeRef attr = LLVMCreateEnumAttribute(gen->context, kind_id, 0);
    LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attr);
  }

  if (node->data.func.is_local) {
    LLVMSetLinkage(fn, LLVMInternalLinkage);
  }

  // Register in globals
  symtable_add(gen->globals, node->data.func.name, fn, fn_type,
               node->data.func.return_type, node->data.func.is_local,
               node->data.func.source_file);

  gen->current_source_file = node->data.func.source_file;

  LLVMBasicBlockRef entry =
      LLVMAppendBasicBlockInContext(gen->context, fn, "entry");
  LLVMPositionBuilderAtEnd(gen->builder, entry);

  if (strcmp(node->data.func.name, "main") == 0) {
    ensure_gc_init(gen);
    LLVMBuildCall2(gen->builder, LLVMGlobalGetValueType(gen->gc_init_func),
                   gen->gc_init_func, NULL, 0, "");
    ensure_gc_enable_incremental(gen);
    LLVMBuildCall2(gen->builder,
                   LLVMGlobalGetValueType(gen->gc_enable_incremental_func),
                   gen->gc_enable_incremental_func, NULL, 0, "");
  }

  // Parameters
  for (int i = 0; i < param_count; i++) {
    LLVMTypeRef ptype = type_info_to_llvm(gen, node->data.func.param_types[i]);
    LLVMValueRef alloca =
        LLVMBuildAlloca(gen->builder, ptype, node->data.func.param_names[i]);
    LLVMBuildStore(gen->builder, LLVMGetParam(fn, i), alloca);
    symtable_add(gen->symbols, node->data.func.param_names[i], alloca, ptype,
                 node->data.func.param_types[i], 0, NULL);
  }

  if (node->data.func.body)
    emit_statement(gen, node->data.func.body);

  // Add implicit return if the function doesn't have a terminator
  // This is necessary for void functions and prevents LLVM crashes
  if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(gen->builder))) {
    if (node->data.func.return_type->kind == TYPE_PRIMITIVE &&
        strcmp(node->data.func.return_type->name, "void") == 0) {
      LLVMBuildRetVoid(gen->builder);
    } else {
      // Non-void function without return - this is an error but we'll insert a
      // dummy return
      LLVMBuildRet(gen->builder, LLVMConstInt(ret, 0, 0));
    }
  }
}

void codegen_generate(CodeGen *gen, ASTNode *ast) {
  if (!ast || ast->type != NODE_PROGRAM)
    return;
  for (int i = 0; i < ast->data.program.count; i++) {
    ASTNode *decl = ast->data.program.decls[i];
    if (decl->type == NODE_STRUCT_DECL)
      register_struct_decl(gen, decl);
  }
  for (int i = 0; i < ast->data.program.count; i++) {
    ASTNode *decl = ast->data.program.decls[i];
    if (decl->type == NODE_FUNC_DECL)
      register_method(gen, decl);
  }
  finalize_struct_bodies(gen);
  for (int i = 0; i < ast->data.program.count; i++)
    if (ast->data.program.decls[i]->type == NODE_FUNC_DECL)
      emit_function(gen, ast->data.program.decls[i]);
}

void codegen_dump_ir(CodeGen *gen) {
  char *ir = LLVMPrintModuleToString(gen->module);
  printf("%s\n", ir);
  LLVMDisposeMessage(ir);
}

int codegen_write_ir(CodeGen *gen, const char *filename) {
  char *err = NULL;
  if (LLVMPrintModuleToFile(gen->module, filename, &err)) {
    fprintf(stderr, "Error: %s\n", err);
    LLVMDisposeMessage(err);
    return 1;
  }
  return 0;
}

int codegen_compile_object(CodeGen *gen, const char *filename) {
  LLVMInitializeAllTargetInfos();
  LLVMInitializeAllTargets();
  LLVMInitializeAllTargetMCs();
  LLVMInitializeAllAsmParsers();
  LLVMInitializeAllAsmPrinters();
  char *triple = LLVMGetDefaultTargetTriple();
  LLVMSetTarget(gen->module, triple);
  char *err = NULL;
  LLVMTargetRef target;
  if (LLVMGetTargetFromTriple(triple, &target, &err)) {
    fprintf(stderr, "Error: %s\n", err);
    LLVMDisposeMessage(err);
    LLVMDisposeMessage(triple);
    return 1;
  }
  LLVMTargetMachineRef m = LLVMCreateTargetMachine(
      target, triple, "generic", "", LLVMCodeGenLevelDefault, LLVMRelocDefault,
      LLVMCodeModelDefault);
  LLVMTargetDataRef d = LLVMCreateTargetDataLayout(m);
  char *l = LLVMCopyStringRepOfTargetData(d);
  LLVMSetDataLayout(gen->module, l);
  LLVMDisposeMessage(l);
  if (LLVMTargetMachineEmitToFile(m, gen->module, (char *)filename,
                                  LLVMObjectFile, &err)) {
    fprintf(stderr, "Error: %s\n", err);
    LLVMDisposeMessage(err);
    LLVMDisposeTargetMachine(m);
    LLVMDisposeMessage(triple);
    return 1;
  }
  LLVMDisposeTargetMachine(m);
  LLVMDisposeMessage(triple);
  return 0;
}
