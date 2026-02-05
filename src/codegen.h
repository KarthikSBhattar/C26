/*
 * C26 Compiler - LLVM Code Generator
 * Generates native code via LLVM IR
 */

#ifndef CODEGEN_H
#define CODEGEN_H

#include "parser.h"
#include <llvm-c/Analysis.h>
#include <llvm-c/Core.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

// Symbol table entry
typedef struct {
  char *name;
  LLVMValueRef alloca;
  LLVMTypeRef type;
  TypeInfo *c26_type;
  int is_local;
  char *source_file;
} Symbol;

typedef struct {
  Symbol *symbols;
  int count;
  int capacity;
} SymbolTable;

typedef struct {
  char *name;
  LLVMTypeRef llvm_type;
  ASTNode *decl;
} StructInfo;

typedef struct {
  char *struct_name;
  char *method_name;
  ASTNode *func;
  int expects_self;
  int self_is_pointer;
} MethodInfo;

typedef struct {
  LLVMContextRef context;
  LLVMModuleRef module;
  LLVMBuilderRef builder;
  SymbolTable *symbols;
  SymbolTable *globals;
  // Struct + method metadata
  StructInfo *structs;
  int struct_count;
  int struct_capacity;
  MethodInfo *methods;
  int method_count;
  int method_capacity;
  char *current_source_file;
  LLVMValueRef printf_func;
  LLVMTypeRef printf_type; // Store the function type too
  LLVMValueRef malloc_func;
  LLVMValueRef free_func;
  LLVMValueRef exit_func;
  LLVMValueRef realloc_func;
  LLVMValueRef calloc_func;
  LLVMValueRef gc_malloc_func;
  LLVMValueRef gc_realloc_func;
  LLVMValueRef gc_free_func;
  LLVMValueRef gc_init_func;
  LLVMValueRef gc_enable_incremental_func;
  LLVMBasicBlockRef break_target; // Target block for break statements
  int had_error;
  char *error_msg;
} CodeGen;

CodeGen *codegen_init(const char *module_name);
void codegen_free(CodeGen *gen);
void codegen_generate(CodeGen *gen, ASTNode *ast);
void codegen_dump_ir(CodeGen *gen);
int codegen_write_ir(CodeGen *gen, const char *filename);
int codegen_compile_object(CodeGen *gen, const char *filename);

#endif // CODEGEN_H
