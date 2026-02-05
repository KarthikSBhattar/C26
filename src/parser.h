/*
 * C26 Compiler - Parser
 * Parses tokens into an AST
 */

#ifndef PARSER_H
#define PARSER_H

#include "lexer.h"

// Type Kind enumeration
typedef enum {
  TYPE_PRIMITIVE, // i32, f64, str, etc.
  TYPE_AUTO,      // Inferred type
  TYPE_ARRAY,     // T[]
  TYPE_TUPLE,     // (T1, T2, ...)
  TYPE_DICT,      // dict<K, V>
  TYPE_SET,       // set<T>
  TYPE_STRUCT,    // struct Name { ... }
  TYPE_POINTER,   // T*
} TypeKind;

// Type representation
typedef struct TypeInfo TypeInfo;
struct TypeInfo {
  TypeKind kind;
  char *name;             // For primitives: "i32", "str", etc.
  TypeInfo *element_type; // For arrays, sets
  TypeInfo *key_type;     // For dicts
  TypeInfo *value_type;   // For dicts
  TypeInfo **tuple_types; // For tuples
  int tuple_count;        // Number of types in tuple
  char **field_names;     // For structs
  TypeInfo **field_types; // For structs
  int field_count;        // Number of struct fields
  int owns_fields;        // Whether this TypeInfo owns the field arrays
  TypeInfo *struct_def;   // Pointer to canonical struct definition (if any)
};

// AST Node Types
typedef enum {
  NODE_PROGRAM,
  NODE_FUNC_DECL,
  NODE_BLOCK,
  NODE_RETURN_STMT,
  NODE_VAR_DECL,
  NODE_DESTRUCT_DECL,
  NODE_EXPR_STMT,
  NODE_INT_LIT,
  NODE_FLOAT_LIT,
  NODE_STRING_LIT,
  NODE_NULL_LIT,
  NODE_DEST_ASSIGN,
  NODE_CHAR_LIT,
  NODE_BOOL_LIT,
  NODE_IDENT,
  NODE_BINARY_OP,
  NODE_UNARY_OP,
  NODE_TYPEOF,
  NODE_CALL,
  NODE_ARRAY_LIT,
  NODE_TUPLE_LIT,
  NODE_INDEX,
  NODE_IF_STMT,
  NODE_WHILE_STMT,
  NODE_TERNARY,
  NODE_ASSIGN,
  NODE_BREAK_STMT,
  NODE_FOR_STMT,
  NODE_MATCH_EXPR,
  NODE_DO_WHILE,
  NODE_INTERPOLATED_STRING,
  NODE_DEREF,
  NODE_ADDR_OF,
  NODE_CAST,
  NODE_SIZEOF,
  NODE_STRUCT_DECL,
  NODE_STRUCT_LIT,
  NODE_FIELD_ACCESS,
  NODE_METHOD_CALL,
  NODE_DESTRUCT_ASSIGN,
} NodeType;

typedef enum {
  PATTERN_BIND,
  PATTERN_TUPLE,
  PATTERN_ARRAY,
  PATTERN_IGNORE,
  PATTERN_REST,
} PatternKind;

typedef struct Pattern Pattern;
struct Pattern {
  PatternKind kind;
  int is_const;
  char *name;
  TypeInfo *type;
  Pattern **elements;
  int count;
  Pattern *rest;
};

typedef struct ASTNode ASTNode;

struct ASTNode {
  NodeType type;

  union {
    // Literals
    struct {
      char *value;
    } literal;
    struct {
      char *value;
    } string;
    struct {
      char *value;
    } character;
    struct {
      int value;
    } boolean;

    // IDENT
    struct {
      char *name;
    } ident;

    // BINARY_OP
    struct {
      char *op;
      ASTNode *left;
      ASTNode *right;
    } binary;

    // UNARY_OP
    struct {
      char *op;
      ASTNode *operand;
    } unary;

    struct {
      ASTNode *expr;
    } typeof_expr;

    struct {
      ASTNode *lhs;
      ASTNode *rhs;
    } dest_assign;

    // FUNC_DECL
    struct {
      TypeInfo *return_type;
      char *name;
      // Parameters
      char **param_names;
      TypeInfo **param_types;
      int param_count;
      ASTNode *body;
      int is_inline;
      int is_local;
      char *source_file;
      char *method_of; // Owning struct if inside an impl
      char *original_name;
    } func;

    // VAR_DECL
    struct {
      TypeInfo *var_type;
      char *name;
      ASTNode *init;
      int is_const;
    } var;

    struct {
      Pattern *pattern;
      ASTNode *init;
    } destruct_decl;

    // BLOCK
    struct {
      ASTNode **statements;
      int count;
    } block;

    // RETURN_STMT, EXPR_STMT
    struct {
      ASTNode *value;
    } ret;

    // CALL
    struct {
      char *name;
      ASTNode **args;
      int arg_count;
    } call;

    // PROGRAM
    struct {
      ASTNode **decls;
      int count;
    } program;

    // ARRAY_LIT, TUPLE_LIT
    struct {
      ASTNode **elements;
      int count;
      TypeInfo *type; // Context-provided type
    } array;

    // INDEX (array[idx])
    struct {
      ASTNode *array;
      ASTNode *index;
    } index;

    // IF_STMT
    struct {
      ASTNode *condition;
      ASTNode *then_block;
      ASTNode *else_block; // Can be another IF_STMT for else if
    } if_stmt;

    // WHILE_STMT
    struct {
      ASTNode *condition;
      ASTNode *body;
    } while_stmt;

    // DO_WHILE_STMT
    struct {
      ASTNode *body;
      ASTNode *condition;
    } do_while;

    // TERNARY (cond ? then : else)
    struct {
      ASTNode *condition;
      ASTNode *then_expr;
      ASTNode *else_expr;
    } ternary;

    // ASSIGN (target = value)
    struct {
      ASTNode *lhs;
      ASTNode *value;
    } assign;

    struct {
      Pattern *pattern;
      ASTNode *rhs;
    } destruct_assign;

    // FOR_STMT
    struct {
      ASTNode *init;      // Init statement (var decl or expr)
      ASTNode *condition; // Loop condition
      ASTNode *update;    // Update expression
      ASTNode *body;      // Loop body
    } for_stmt;

    // MATCH_EXPR
    struct {
      ASTNode *value;        // Expression to match on
      ASTNode **case_values; // Array of match patterns (NULL for _)
      ASTNode **case_bodies; // Array of result expressions
      int case_count;
    } match_expr;

    // INTERPOLATED_STRING
    struct {
      ASTNode **parts;
      int count;
    } interpolated_string;

    // CAST (target_type) expr
    struct {
      TypeInfo *target_type;
      ASTNode *expr;
    } cast;

    // SIZEOF
    struct {
      TypeInfo *target_type;
      ASTNode *expr;
    } s_of;

    // STRUCT_DECL
    struct {
      char *name;
      TypeInfo *type;
    } struct_decl;

    // STRUCT_LIT
    struct {
      char *type_name; // Optional explicit type
      TypeInfo *type;  // Resolved struct type if known
      char **field_names;
      ASTNode **field_values;
      int field_count;
    } struct_lit;

    // FIELD_ACCESS
    struct {
      ASTNode *object;
      char *field;
      int via_pointer; // true if using ->
    } field_access;

    // METHOD_CALL
    struct {
      ASTNode *receiver;
      char *method;
      ASTNode **args;
      int arg_count;
      int via_pointer;
    } method_call;
  } data;

  int line;
  int col;
};

typedef struct {
  char *alias;
  char *prefix;
} ImportEntry;

typedef struct {
  Lexer *lexer;
  Token current;
  Token previous;
  int had_error;
  int panic_mode;
  char *error_msg;
  char *current_file;
  char *current_prefix; // For name mangling locally

  // Import aliases for the current file
  ImportEntry *imports;
  int import_count;
  int import_capacity;

  // Known structs for type resolution
  TypeInfo **struct_types;
  char **struct_names;
  int struct_count;
  int struct_capacity;

  // Current impl context
  char *current_impl;
} Parser;

ASTNode *parse(Parser *parser);
Parser *parser_init(Lexer *lexer);
void parser_free(Parser *parser);
ASTNode *parse_expression(Parser *parser);
ASTNode *ast_copy(ASTNode *node);
TypeInfo *type_info_copy(TypeInfo *type);
void ast_free(ASTNode *node);
void ast_print(ASTNode *node, int indent);

// Type utilities
TypeInfo *type_info_new(TypeKind kind, const char *name);
void type_info_free(TypeInfo *type);
char *type_info_to_string(TypeInfo *type);

#endif // PARSER_H
