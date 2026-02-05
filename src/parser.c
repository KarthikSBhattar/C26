/*
 * C26 Compiler - Parser Implementation
 */

#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Type utilities
TypeInfo *type_info_new(TypeKind kind, const char *name) {
  TypeInfo *t = malloc(sizeof(TypeInfo));
  memset(t, 0, sizeof(TypeInfo));
  t->kind = kind;
  t->name = name ? strdup(name) : NULL;
  t->owns_fields = 1;
  return t;
}

void type_info_free(TypeInfo *type) {
  if (!type)
    return;
  if (type->name)
    free(type->name);
  if (type->element_type)
    type_info_free(type->element_type);
  if (type->key_type)
    type_info_free(type->key_type);
  if (type->value_type)
    type_info_free(type->value_type);
  if (type->tuple_types) {
    for (int i = 0; i < type->tuple_count; i++)
      type_info_free(type->tuple_types[i]);
    free(type->tuple_types);
  }
  if (type->kind == TYPE_STRUCT && type->owns_fields) {
    if (type->field_names) {
      for (int i = 0; i < type->field_count; i++)
        free(type->field_names[i]);
      free(type->field_names);
    }
    if (type->field_types) {
      for (int i = 0; i < type->field_count; i++)
        type_info_free(type->field_types[i]);
      free(type->field_types);
    }
  }
  free(type);
}

char *type_info_to_string(TypeInfo *type) {
  if (!type)
    return strdup("unknown");
  char buf[256];
  switch (type->kind) {
  case TYPE_PRIMITIVE:
    return strdup(type->name);
  case TYPE_AUTO:
    return strdup("auto");
  case TYPE_ARRAY: {
    char *elem = type_info_to_string(type->element_type);
    snprintf(buf, sizeof(buf), "%s[]", elem);
    free(elem);
    return strdup(buf);
  }
  case TYPE_SET: {
    char *elem = type_info_to_string(type->element_type);
    snprintf(buf, sizeof(buf), "set<%s>", elem);
    free(elem);
    return strdup(buf);
  }
  case TYPE_DICT: {
    char *k = type_info_to_string(type->key_type);
    char *v = type_info_to_string(type->value_type);
    snprintf(buf, sizeof(buf), "dict<%s, %s>", k, v);
    free(k);
    free(v);
    return strdup(buf);
  }
  case TYPE_TUPLE: {
    strcpy(buf, "(");
    for (int i = 0; i < type->tuple_count; i++) {
      if (i > 0)
        strcat(buf, ", ");
      char *t = type_info_to_string(type->tuple_types[i]);
      strcat(buf, t);
      free(t);
    }
    strcat(buf, ")");
    return strdup(buf);
  }
  case TYPE_POINTER: {
    char *elem = type_info_to_string(type->element_type);
    snprintf(buf, sizeof(buf), "%s*", elem);
    free(elem);
    return strdup(buf);
  }
  case TYPE_STRUCT:
    return type->name ? strdup(type->name) : strdup("struct");
  }
  return strdup("unknown");
}

Parser *parser_init(Lexer *lexer) {
  Parser *parser = malloc(sizeof(Parser));
  parser->lexer = lexer;
  parser->had_error = 0;
  parser->error_msg = NULL;
  parser->current = lexer_next(lexer);
  parser->current_file = NULL;
  parser->current_prefix = NULL;
  parser->current_impl = NULL;
  parser->imports = NULL;
  parser->import_count = 0;
  parser->import_capacity = 0;
  parser->struct_types = NULL;
  parser->struct_names = NULL;
  parser->struct_count = 0;
  parser->struct_capacity = 0;
  return parser;
}

void parser_free(Parser *parser) {
  if (parser->error_msg)
    free(parser->error_msg);
  if (parser->current_file)
    free(parser->current_file);
  if (parser->current_prefix)
    free(parser->current_prefix);
  if (parser->current_impl)
    free(parser->current_impl);
  if (parser->imports) {
    for (int i = 0; i < parser->import_count; i++) {
      free(parser->imports[i].alias);
      free(parser->imports[i].prefix);
    }
    free(parser->imports);
  }
  if (parser->struct_names) {
    for (int i = 0; i < parser->struct_count; i++) {
      free(parser->struct_names[i]);
    }
    free(parser->struct_names);
  }
  if (parser->struct_types)
    free(parser->struct_types);
  token_free(&parser->current);
  free(parser);
}

void parser_add_import(Parser *parser, const char *alias, const char *prefix) {
  if (parser->import_count >= parser->import_capacity) {
    parser->import_capacity =
        parser->import_capacity < 8 ? 8 : parser->import_capacity * 2;
    parser->imports =
        realloc(parser->imports, sizeof(ImportEntry) * parser->import_capacity);
    if (!parser->imports) {
      fprintf(stderr, "Memory allocation failed for imports\n");
      exit(1);
    }
  }
  parser->imports[parser->import_count].alias = strdup(alias);
  parser->imports[parser->import_count].prefix = strdup(prefix);
  parser->import_count++;
}

char *parser_resolve_alias(Parser *parser, const char *alias) {
  for (int i = 0; i < parser->import_count; i++) {
    if (strcmp(parser->imports[i].alias, alias) == 0) {
      return parser->imports[i].prefix;
    }
  }
  return NULL;
}

static TypeInfo *parser_lookup_struct(Parser *parser, const char *name) {
  for (int i = 0; i < parser->struct_count; i++) {
    if (strcmp(parser->struct_names[i], name) == 0)
      return parser->struct_types[i];
  }
  return NULL;
}

static void parser_add_struct(Parser *parser, TypeInfo *type) {
  if (!type || !type->name)
    return;
  if (parser_lookup_struct(parser, type->name))
    return; // Already present
  if (parser->struct_count >= parser->struct_capacity) {
    parser->struct_capacity =
        parser->struct_capacity < 8 ? 8 : parser->struct_capacity * 2;
    parser->struct_types = realloc(
        parser->struct_types, sizeof(TypeInfo *) * parser->struct_capacity);
    parser->struct_names =
        realloc(parser->struct_names, sizeof(char *) * parser->struct_capacity);
    if (!parser->struct_types || !parser->struct_names) {
      fprintf(stderr, "Memory allocation failed for structs\n");
      exit(1);
    }
  }
  parser->struct_types[parser->struct_count] = type;
  parser->struct_names[parser->struct_count] = strdup(type->name);
  parser->struct_count++;
}

static int parser_has_struct(Parser *parser, const char *name) {
  return parser_lookup_struct(parser, name) != NULL;
}

char *canonicalize_path_to_prefix(const char *path) {
  char *prefix = strdup(path);
  char *p = prefix;
  while (*p) {
    if (*p == '/' || *p == '.' || *p == '-') {
      *p = '_';
    }
    p++;
  }
  // Strip trailing .c26 if handled elsewhere, but path usually doesn't have it
  // if from include parser before extension Actually include parser has path
  // like "base/path/file"
  return prefix;
}

void advance(Parser *parser) {
  token_free(&parser->previous);
  parser->previous = parser->current;
  parser->current = lexer_next(parser->lexer);
}

static int check(Parser *parser, TokenType type) {
  return parser->current.type == type;
}
static int match(Parser *parser, TokenType type) {
  if (!check(parser, type))
    return 0;
  advance(parser);
  return 1;
}

static void error(Parser *parser, const char *msg) {
  if (parser->had_error)
    return;
  parser->had_error = 1;
  parser->error_msg = malloc(256);
  snprintf(parser->error_msg, 256, "Error at line %d, col %d: %s",
           parser->current.line, parser->current.col, msg);
  fprintf(stderr, "%s\n", parser->error_msg);
}

static int expect(Parser *parser, TokenType type, const char *msg) {
  if (check(parser, type)) {
    advance(parser);
    return 1;
  }
  error(parser, msg);
  return 0;
}

static ASTNode *make_node(NodeType type, int line, int col) {
  ASTNode *node = malloc(sizeof(ASTNode));
  memset(node, 0, sizeof(ASTNode));
  node->type = type;
  node->line = line;
  node->col = col;
  return node;
}

static int is_type_token(TokenType type) {
  return type == TOK_I8 || type == TOK_I16 || type == TOK_I32 ||
         type == TOK_I64 || type == TOK_I128 || type == TOK_ISIZE ||
         type == TOK_U8 || type == TOK_U16 || type == TOK_U32 ||
         type == TOK_U64 || type == TOK_U128 || type == TOK_USIZE ||
         type == TOK_F32 || type == TOK_F64 || type == TOK_BOOL ||
         type == TOK_CHAR || type == TOK_STR || type == TOK_VOID ||
         type == TOK_DICT || type == TOK_SET || type == TOK_LPAREN ||
         type == TOK_AUTO || type == TOK_STAR;
}

static int is_type_start(Parser *parser) {
  return is_type_token(parser->current.type) ||
         (parser->current.type == TOK_IDENT &&
          parser_has_struct(parser, parser->current.value));
}

static const char *token_to_type_name(TokenType type) {
  switch (type) {
  case TOK_I8:
    return "i8";
  case TOK_I16:
    return "i16";
  case TOK_I32:
    return "i32";
  case TOK_I64:
    return "i64";
  case TOK_I128:
    return "i128";
  case TOK_ISIZE:
    return "isize";
  case TOK_U8:
    return "u8";
  case TOK_U16:
    return "u16";
  case TOK_U32:
    return "u32";
  case TOK_U64:
    return "u64";
  case TOK_U128:
    return "u128";
  case TOK_USIZE:
    return "usize";
  case TOK_F32:
    return "f32";
  case TOK_F64:
    return "f64";
  case TOK_BOOL:
    return "bool";
  case TOK_CHAR:
    return "char";
  case TOK_STR:
    return "str";
  case TOK_VOID:
    return "void";
  default:
    return "unknown";
  }
}

// Forward declarations
ASTNode *parse_expression(Parser *parser);
static TypeInfo *parse_type(Parser *parser);

static TypeInfo *parse_type(Parser *parser) {
  // Tuple type: (T1, T2, ...)
  if (check(parser, TOK_LPAREN)) {
    advance(parser);
    TypeInfo *tuple = type_info_new(TYPE_TUPLE, NULL);
    int cap = 4;
    tuple->tuple_types = malloc(sizeof(TypeInfo *) * cap);
    tuple->tuple_count = 0;

    if (!check(parser, TOK_RPAREN)) {
      do {
        if (tuple->tuple_count >= cap) {
          cap *= 2;
          tuple->tuple_types =
              realloc(tuple->tuple_types, sizeof(TypeInfo *) * cap);
        }
        tuple->tuple_types[tuple->tuple_count++] = parse_type(parser);
      } while (match(parser, TOK_COMMA));
    }
    expect(parser, TOK_RPAREN, "Expected ')' after tuple type");
    return tuple;
  }

  // dict<K, V>
  if (check(parser, TOK_DICT)) {
    advance(parser);
    expect(parser, TOK_LT, "Expected '<' after dict");
    TypeInfo *dict = type_info_new(TYPE_DICT, "dict");
    dict->key_type = parse_type(parser);
    expect(parser, TOK_COMMA, "Expected ',' in dict<K, V>");
    dict->value_type = parse_type(parser);
    expect(parser, TOK_GT, "Expected '>' after dict types");
    return dict;
  }

  // set<T>
  if (check(parser, TOK_SET)) {
    advance(parser);
    expect(parser, TOK_LT, "Expected '<' after set");
    TypeInfo *set = type_info_new(TYPE_SET, "set");
    set->element_type = parse_type(parser);
    expect(parser, TOK_GT, "Expected '>' after set type");
    return set;
  }

  // Auto type
  if (match(parser, TOK_AUTO)) {
    return type_info_new(TYPE_AUTO, "auto");
  }

  if (check(parser, TOK_IDENT) &&
      parser_has_struct(parser, parser->current.value)) {
    TypeInfo *def = parser_lookup_struct(parser, parser->current.value);
    TypeInfo *st = type_info_new(TYPE_STRUCT, parser->current.value);
    st->field_names = def->field_names;
    st->field_types = def->field_types;
    st->field_count = def->field_count;
    st->owns_fields = 0;
    st->struct_def = def;
    advance(parser);
    // Handle pointers or arrays to struct
    while (check(parser, TOK_LBRACKET) || check(parser, TOK_STAR)) {
      if (match(parser, TOK_LBRACKET)) {
        expect(parser, TOK_RBRACKET, "Expected ']' for array type");
        TypeInfo *arr = type_info_new(TYPE_ARRAY, NULL);
        arr->element_type = st;
        st = arr;
      } else if (match(parser, TOK_STAR)) {
        TypeInfo *ptr = type_info_new(TYPE_POINTER, NULL);
        ptr->element_type = st;
        st = ptr;
      }
    }
    return st;
  }

  // Primitive type
  if (!is_type_token(parser->current.type)) {
    error(parser, "Expected type");
    return type_info_new(TYPE_PRIMITIVE, "unknown");
  }

  TypeInfo *base =
      type_info_new(TYPE_PRIMITIVE, token_to_type_name(parser->current.type));
  advance(parser);

  // Array type: T[]
  while (check(parser, TOK_LBRACKET) || check(parser, TOK_STAR)) {
    if (match(parser, TOK_LBRACKET)) {
      expect(parser, TOK_RBRACKET, "Expected ']' for array type");
      TypeInfo *arr = type_info_new(TYPE_ARRAY, NULL);
      arr->element_type = base;
      base = arr;
    } else if (match(parser, TOK_STAR)) {
      TypeInfo *ptr = type_info_new(TYPE_POINTER, NULL);
      ptr->element_type = base;
      base = ptr;
    }
  }

  return base;
}

ASTNode *parse_expression(Parser *parser);

static ASTNode *parse_struct_literal(Parser *parser, const char *type_name,
                                     int line, int col) {
  ASTNode *node = make_node(NODE_STRUCT_LIT, line, col);
  node->data.struct_lit.type_name = type_name ? strdup(type_name) : NULL;
  node->data.struct_lit.type =
      type_name ? parser_lookup_struct(parser, type_name) : NULL;
  int cap = 4;
  node->data.struct_lit.field_names = malloc(sizeof(char *) * cap);
  node->data.struct_lit.field_values = malloc(sizeof(ASTNode *) * cap);
  node->data.struct_lit.field_count = 0;

  while (!check(parser, TOK_RBRACE)) {
    if (node->data.struct_lit.field_count >= cap) {
      cap *= 2;
      node->data.struct_lit.field_names =
          realloc(node->data.struct_lit.field_names, sizeof(char *) * cap);
      node->data.struct_lit.field_values =
          realloc(node->data.struct_lit.field_values, sizeof(ASTNode *) * cap);
    }
    if (!check(parser, TOK_IDENT)) {
      error(parser, "Expected field name in struct literal");
      break;
    }
    node->data.struct_lit.field_names[node->data.struct_lit.field_count] =
        strdup(parser->current.value);
    advance(parser);
    expect(parser, TOK_COLON, "Expected ':' in struct literal");
    node->data.struct_lit.field_values[node->data.struct_lit.field_count] =
        parse_expression(parser);
    node->data.struct_lit.field_count++;
    if (!match(parser, TOK_COMMA))
      break;
  }
  expect(parser, TOK_RBRACE, "Expected '}' after struct literal");
  return node;
}

ASTNode *parse_string_with_interpolation(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;
  char *str = parser->current.value;
  const char *p = str;

  // Check if it contains interpolation
  int has_interp = 0;
  while (*p) {
    if (*p == '$' && *(p + 1) == '{') {
      has_interp = 1;
      break;
    }
    p++;
  }

  if (has_interp) {
    ASTNode *interp = make_node(NODE_INTERPOLATED_STRING, line, col);
    interp->data.interpolated_string.parts = malloc(sizeof(ASTNode *) * 8);
    interp->data.interpolated_string.count = 0;
    int cap = 8;

    // Reset p to start
    p = str;
    char buffer[1024];
    int buf_idx = 0;

    // For parsing expressions inside ${...}
    // We need to setup a temporary lexer/parser on the expression string

    while (*p) {
      if (*p == '$' && *(p + 1) == '{') {
        // Push accumulated string literal part if any
        if (buf_idx > 0) {
          buffer[buf_idx] = '\0';
          ASTNode *part = make_node(NODE_STRING_LIT, line, col);
          part->data.string.value = strdup(buffer);

          if (interp->data.interpolated_string.count >= cap) {
            cap *= 2;
            interp->data.interpolated_string.parts =
                realloc(interp->data.interpolated_string.parts,
                        sizeof(ASTNode *) * cap);
          }
          interp->data.interpolated_string
              .parts[interp->data.interpolated_string.count++] = part;
          buf_idx = 0;
        }

        p += 2; // Skip '${'

        // Extract the expression until '}'
        // We need to handle nested braces logic ideally, but for now scan until
        // '}' Actually, we must handle nested braces if the expression contains
        // blocks or dicts. A simple counter approach:
        int brace_depth = 1;
        char expr_buf[1024];
        int expr_idx = 0;

        while (*p && brace_depth > 0) {
          if (*p == '{')
            brace_depth++;
          if (*p == '}')
            brace_depth--;

          if (brace_depth > 0) {
            expr_buf[expr_idx++] = *p;
            p++;
          }
        }

        if (*p == '}')
          p++; // Skip closing '}'

        expr_buf[expr_idx] = '\0';

        // Parse this expression
        Lexer *expr_lexer = lexer_init(expr_buf);
        Parser *expr_parser = parser_init(expr_lexer);
        // Inherit current file info for error reporting context?
        expr_parser->current_file =
            parser->current_file ? strdup(parser->current_file) : NULL;

        ASTNode *expr_node = parse_expression(expr_parser);

        if (expr_parser->had_error) {
          error(parser, "Invalid expression in string interpolation");
        }

        if (interp->data.interpolated_string.count >= cap) {
          cap *= 2;
          interp->data.interpolated_string.parts = realloc(
              interp->data.interpolated_string.parts, sizeof(ASTNode *) * cap);
        }
        interp->data.interpolated_string
            .parts[interp->data.interpolated_string.count++] = expr_node;

        parser_free(expr_parser);
        lexer_free(expr_lexer);

      } else {
        buffer[buf_idx++] = *p;
        p++;
      }
    }

    // Trailing string part
    if (buf_idx > 0) {
      buffer[buf_idx] = '\0';
      ASTNode *part = make_node(NODE_STRING_LIT, line, col);
      part->data.string.value = strdup(buffer);

      if (interp->data.interpolated_string.count >= cap) {
        cap *= 2;
        interp->data.interpolated_string.parts = realloc(
            interp->data.interpolated_string.parts, sizeof(ASTNode *) * cap);
      }
      interp->data.interpolated_string
          .parts[interp->data.interpolated_string.count++] = part;
    }

    advance(parser);
    return interp;
  }

  ASTNode *node = make_node(NODE_STRING_LIT, line, col);
  node->data.string.value = strdup(parser->current.value);
  advance(parser);
  return node;
}

// Expression parsing
static ASTNode *parse_primary(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;

  if (check(parser, TOK_INT_LIT)) {
    ASTNode *node = make_node(NODE_INT_LIT, line, col);
    node->data.literal.value = strdup(parser->current.value);
    advance(parser);
    return node;
  }
  if (check(parser, TOK_FLOAT_LIT)) {
    ASTNode *node = make_node(NODE_FLOAT_LIT, line, col);
    node->data.literal.value = strdup(parser->current.value);
    advance(parser);
    return node;
  }
  if (check(parser, TOK_STRING_LIT)) {
    return parse_string_with_interpolation(parser);
  }
  if (check(parser, TOK_CHAR_LIT)) {
    ASTNode *node = make_node(NODE_CHAR_LIT, line, col);
    node->data.character.value = strdup(parser->current.value);
    advance(parser);
    return node;
  }
  if (check(parser, TOK_NULL)) {
    advance(parser);
    return make_node(NODE_NULL_LIT, line, col);
  }
  if (match(parser, TOK_LBRACE)) {
    return parse_struct_literal(parser, NULL, line, col);
  }
  if (check(parser, TOK_TYPEOF)) {
    advance(parser);
    ASTNode *node = make_node(NODE_TYPEOF, line, col);
    expect(parser, TOK_LPAREN, "Expected '(' after typeof");
    node->data.typeof_expr.expr = parse_expression(parser);
    expect(parser, TOK_RPAREN, "Expected ')' after typeof expression");
    return node;
  }
  if (check(parser, TOK_SIZEOF)) {
    advance(parser);
    ASTNode *node = make_node(NODE_SIZEOF, line, col);
    expect(parser, TOK_LPAREN, "Expected '(' after sizeof");
    if (is_type_start(parser)) {
      node->data.s_of.target_type = parse_type(parser);
      node->data.s_of.expr = NULL;
    } else {
      node->data.s_of.expr = parse_expression(parser);
      node->data.s_of.target_type = NULL;
    }
    expect(parser, TOK_RPAREN, "Expected ')' after sizeof argument");
    return node;
  }
  if (check(parser, TOK_TRUE) || check(parser, TOK_FALSE)) {
    ASTNode *node = make_node(NODE_BOOL_LIT, line, col);
    node->data.boolean.value = check(parser, TOK_TRUE) ? 1 : 0;
    advance(parser);
    return node;
  }
  if (check(parser, TOK_IDENT)) {
    char *name = strdup(parser->current.value);
    advance(parser);

    // Check for alias usage: alias.func
    char *prefix = parser_resolve_alias(parser, name);
    if (prefix && match(parser, TOK_DOT)) {
      if (!check(parser, TOK_IDENT)) {
        error(parser, "Expected function name after alias");
        free(name);
        return NULL;
      }
      Token next_tok = lexer_peek(parser->lexer);
      if (next_tok.type == TOK_LPAREN) {
        char mangled[512];
        snprintf(mangled, sizeof(mangled), "%s_%s", prefix,
                 parser->current.value);
        free(name);
        name = strdup(mangled);
      } else {
        free(name);
        name = strdup(parser->current.value);
      }
      token_free(&next_tok);
      advance(parser);
    }

    if (check(parser, TOK_LBRACE)) {
      advance(parser);
      ASTNode *lit = parse_struct_literal(parser, name, line, col);
      free(name);
      return lit;
    }

    // Function call
    if (check(parser, TOK_LPAREN)) {
      advance(parser);
      ASTNode *node = make_node(NODE_CALL, line, col);
      node->data.call.name = name;
      node->data.call.args = NULL;
      node->data.call.arg_count = 0;
      if (!check(parser, TOK_RPAREN)) {
        int cap = 4;
        node->data.call.args = malloc(sizeof(ASTNode *) * cap);
        do {
          if (node->data.call.arg_count >= cap) {
            cap *= 2;
            node->data.call.args =
                realloc(node->data.call.args, sizeof(ASTNode *) * cap);
          }
          node->data.call.args[node->data.call.arg_count++] =
              parse_expression(parser);
        } while (match(parser, TOK_COMMA));
      }
      expect(parser, TOK_RPAREN, "Expected ')' after arguments");
      return node;
    }
    // Just an identifier
    ASTNode *node = make_node(NODE_IDENT, line, col);
    node->data.ident.name = name;
    return node;
  }
  // Tuple/grouped expression or tuple literal
  if (match(parser, TOK_LPAREN)) {
    ASTNode *first = parse_expression(parser);
    if (check(parser, TOK_COMMA)) {
      // Tuple literal
      ASTNode *tuple = make_node(NODE_TUPLE_LIT, line, col);
      int cap = 4;
      tuple->data.array.elements = malloc(sizeof(ASTNode *) * cap);
      tuple->data.array.elements[0] = first;
      tuple->data.array.count = 1;
      while (match(parser, TOK_COMMA)) {
        if (tuple->data.array.count >= cap) {
          cap *= 2;
          tuple->data.array.elements =
              realloc(tuple->data.array.elements, sizeof(ASTNode *) * cap);
        }
        tuple->data.array.elements[tuple->data.array.count++] =
            parse_expression(parser);
      }
      expect(parser, TOK_RPAREN, "Expected ')' after tuple");

      // Destructuring assignment
      if (check(parser, TOK_EQ)) {
        advance(parser);
        ASTNode *assign = make_node(NODE_DEST_ASSIGN, line, col);
        assign->data.dest_assign.lhs = tuple;
        assign->data.dest_assign.rhs = parse_expression(parser);
        return assign;
      }
      return tuple;
    }
    expect(parser, TOK_RPAREN, "Expected ')' after expression");
    return first;
  }
  // Array literal: [a, b, c]
  if (match(parser, TOK_LBRACKET)) {
    ASTNode *arr = make_node(NODE_ARRAY_LIT, line, col);
    int cap = 4;
    arr->data.array.elements = malloc(sizeof(ASTNode *) * cap);
    arr->data.array.count = 0;
    if (!check(parser, TOK_RBRACKET)) {
      do {
        if (arr->data.array.count >= cap) {
          cap *= 2;
          arr->data.array.elements =
              realloc(arr->data.array.elements, sizeof(ASTNode *) * cap);
        }
        arr->data.array.elements[arr->data.array.count++] =
            parse_expression(parser);
      } while (match(parser, TOK_COMMA));
    }
    expect(parser, TOK_RBRACKET, "Expected ']' after array");
    return arr;
  }

  // Match expression: match (x) { 1 => "one", _ => "other" }
  if (match(parser, TOK_MATCH)) {
    ASTNode *node = make_node(NODE_MATCH_EXPR, line, col);
    expect(parser, TOK_LPAREN, "Expected '(' after match");
    node->data.match_expr.value = parse_expression(parser);
    expect(parser, TOK_RPAREN, "Expected ')' after match value");
    expect(parser, TOK_LBRACE, "Expected '{' for match body");

    int cap = 8;
    node->data.match_expr.case_values = malloc(sizeof(ASTNode *) * cap);
    node->data.match_expr.case_bodies = malloc(sizeof(ASTNode *) * cap);
    node->data.match_expr.case_count = 0;

    while (!check(parser, TOK_RBRACE) && !check(parser, TOK_EOF)) {
      int idx = node->data.match_expr.case_count;
      if (idx >= cap) {
        cap *= 2;
        node->data.match_expr.case_values =
            realloc(node->data.match_expr.case_values, sizeof(ASTNode *) * cap);
        node->data.match_expr.case_bodies =
            realloc(node->data.match_expr.case_bodies, sizeof(ASTNode *) * cap);
      }

      // Pattern (or _ for default)
      if (match(parser, TOK_UNDERSCORE)) {
        node->data.match_expr.case_values[idx] = NULL; // NULL = wildcard
      } else {
        node->data.match_expr.case_values[idx] = parse_expression(parser);
      }

      expect(parser, TOK_ARROW, "Expected '=>' after match pattern");
      node->data.match_expr.case_bodies[idx] = parse_expression(parser);
      node->data.match_expr.case_count++;

      // Optional trailing comma
      if (!check(parser, TOK_RBRACE))
        match(parser, TOK_COMMA);
    }

    expect(parser, TOK_RBRACE, "Expected '}' after match body");
    return node;
  }

  error(parser, "Expected expression");
  return NULL;
}

static ASTNode *parse_postfix(Parser *parser) {
  ASTNode *left = parse_primary(parser);
  int cont = 1;
  while (cont) {
    if (check(parser, TOK_LBRACKET)) {
      int line = parser->current.line, col = parser->current.col;
      advance(parser);
      ASTNode *idx = parse_expression(parser);
      expect(parser, TOK_RBRACKET, "Expected ']' after index");
      ASTNode *node = make_node(NODE_INDEX, line, col);
      node->data.index.array = left;
      node->data.index.index = idx;
      left = node;
      continue;
    }
    if (match(parser, TOK_ARROW_RIGHT) || match(parser, TOK_DOT)) {
      int via_ptr = parser->previous.type == TOK_ARROW_RIGHT;
      int line = parser->previous.line, col = parser->previous.col;

      // Auto-dereference: if using '.' on a pointer, treat as '->'
      if (!via_ptr) {
        // We can't easily check type here without a symbol table or type system
        // in parser but we can set a flag and let codegen decide, or just
        // always treat '.' as potential '->' for now, let's keep it simple and
        // just allow '.' to act as '->' if needed in codegen. BUT the user code
        // specifically uses '.' on a pointer.
      }

      if (!check(parser, TOK_IDENT)) {
        error(parser, "Expected identifier after member access");
        break;
      }
      char *member = strdup(parser->current.value);
      advance(parser);
      if (check(parser, TOK_LPAREN)) {
        advance(parser);
        ASTNode *node = make_node(NODE_METHOD_CALL, line, col);
        node->data.method_call.receiver = left;
        node->data.method_call.method = member;
        node->data.method_call.args = NULL;
        node->data.method_call.arg_count = 0;
        node->data.method_call.via_pointer = via_ptr;
        if (!check(parser, TOK_RPAREN)) {
          int cap = 4;
          node->data.method_call.args = malloc(sizeof(ASTNode *) * cap);
          do {
            if (node->data.method_call.arg_count >= cap) {
              cap *= 2;
              node->data.method_call.args =
                  realloc(node->data.method_call.args, sizeof(ASTNode *) * cap);
            }
            node->data.method_call.args[node->data.method_call.arg_count++] =
                parse_expression(parser);
          } while (match(parser, TOK_COMMA));
        }
        expect(parser, TOK_RPAREN, "Expected ')' after arguments");
        left = node;
      } else {
        ASTNode *node = make_node(NODE_FIELD_ACCESS, line, col);
        node->data.field_access.object = left;
        node->data.field_access.field = member;
        node->data.field_access.via_pointer = via_ptr;
        left = node;
      }
      continue;
    }
    if (check(parser, TOK_INC) || check(parser, TOK_DEC)) {
      int line = parser->current.line, col = parser->current.col;
      char *op = strdup(parser->current.value);
      advance(parser);
      ASTNode *node = make_node(NODE_UNARY_OP, line, col);
      node->data.unary.op = op;
      node->data.unary.operand = left;
      left = node;
      continue;
    }
    cont = 0;
  }
  return left;
}

static ASTNode *parse_unary(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;
  if (check(parser, TOK_MINUS) || check(parser, TOK_NOT) ||
      check(parser, TOK_TILDE)) {
    char *op = strdup(parser->current.value);
    advance(parser);
    ASTNode *node = make_node(NODE_UNARY_OP, line, col);
    node->data.unary.op = op;
    node->data.unary.operand = parse_unary(parser);
    return node;
  }
  if (match(parser, TOK_STAR)) {
    ASTNode *node = make_node(NODE_DEREF, line, col);
    node->data.unary.op = strdup("*");
    node->data.unary.operand = parse_unary(parser);
    return node;
  }
  if (match(parser, TOK_AMPERSAND)) {
    ASTNode *node = make_node(NODE_ADDR_OF, line, col);
    node->data.unary.op = strdup("&");
    node->data.unary.operand = parse_unary(parser);
    return node;
  }

  // Cast: (type)expr
  if (check(parser, TOK_LPAREN)) {
    Token next = lexer_peek(parser->lexer);
    if (is_type_token(next.type) ||
        (next.type == TOK_IDENT && parser_has_struct(parser, next.value))) {
      advance(parser); // skip (
      TypeInfo *target = parse_type(parser);
      if (match(parser, TOK_RPAREN)) {
        ASTNode *node = make_node(NODE_CAST, line, col);
        node->data.cast.target_type = target;
        node->data.cast.expr = parse_unary(parser);
        token_free(&next);
        return node;
      }
      type_info_free(target);
      // If we matched ( and a type but no ), it's an error we can't easily
      // recover from here but let's just fall through for now as it's better
      // than manual state hacking.
    }
    token_free(&next);
  }

  return parse_postfix(parser);
}

static ASTNode *parse_multiplicative(Parser *parser) {
  ASTNode *left = parse_unary(parser);
  while (check(parser, TOK_STAR) || check(parser, TOK_SLASH) ||
         check(parser, TOK_PERCENT)) {
    int line = parser->current.line, col = parser->current.col;
    char *op = strdup(parser->current.value);
    advance(parser);
    ASTNode *node = make_node(NODE_BINARY_OP, line, col);
    node->data.binary.op = op;
    node->data.binary.left = left;
    node->data.binary.right = parse_unary(parser);
    left = node;
  }
  return left;
}

static ASTNode *parse_additive(Parser *parser) {
  ASTNode *left = parse_multiplicative(parser);
  while (check(parser, TOK_PLUS) || check(parser, TOK_MINUS)) {
    int line = parser->current.line, col = parser->current.col;
    char *op = strdup(parser->current.value);
    advance(parser);
    ASTNode *node = make_node(NODE_BINARY_OP, line, col);
    node->data.binary.op = op;
    node->data.binary.left = left;
    node->data.binary.right = parse_multiplicative(parser);
    left = node;
  }
  return left;
}

static ASTNode *parse_relational(Parser *parser) {
  ASTNode *left = parse_additive(parser);
  while (check(parser, TOK_LT) || check(parser, TOK_GT) ||
         check(parser, TOK_LTE) || check(parser, TOK_GTE)) {
    int line = parser->current.line, col = parser->current.col;
    char *op = strdup(parser->current.value);
    advance(parser);
    ASTNode *node = make_node(NODE_BINARY_OP, line, col);
    node->data.binary.op = op;
    node->data.binary.left = left;
    node->data.binary.right = parse_additive(parser);
    left = node;
  }
  return left;
}

static ASTNode *parse_equality(Parser *parser) {
  ASTNode *left = parse_relational(parser);
  while (check(parser, TOK_EQEQ) || check(parser, TOK_NEQ)) {
    int line = parser->current.line, col = parser->current.col;
    char *op = strdup(parser->current.value);
    advance(parser);
    ASTNode *node = make_node(NODE_BINARY_OP, line, col);
    node->data.binary.op = op;
    node->data.binary.left = left;
    node->data.binary.right = parse_relational(parser);
    left = node;
  }
  return left;
}

static ASTNode *parse_and(Parser *parser) {
  ASTNode *left = parse_equality(parser);
  while (check(parser, TOK_AND)) {
    int line = parser->current.line, col = parser->current.col;
    advance(parser);
    ASTNode *node = make_node(NODE_BINARY_OP, line, col);
    node->data.binary.op = strdup("&&");
    node->data.binary.left = left;
    node->data.binary.right = parse_equality(parser);
    left = node;
  }
  return left;
}

static ASTNode *parse_or(Parser *parser) {
  ASTNode *left = parse_and(parser);
  while (check(parser, TOK_OR)) {
    int line = parser->current.line, col = parser->current.col;
    advance(parser);
    ASTNode *node = make_node(NODE_BINARY_OP, line, col);
    node->data.binary.op = strdup("||");
    node->data.binary.left = left;
    node->data.binary.right = parse_and(parser);
    left = node;
  }
  return left;
}

static ASTNode *parse_ternary(Parser *parser) {
  ASTNode *cond = parse_or(parser);
  if (match(parser, TOK_QUESTION)) {
    int line = parser->previous.line, col = parser->previous.col;
    ASTNode *node = make_node(NODE_TERNARY, line, col);
    node->data.ternary.condition = cond;
    node->data.ternary.then_expr = parse_expression(parser);
    expect(parser, TOK_COLON, "Expected ':' in ternary expression");
    node->data.ternary.else_expr = parse_expression(parser);
    return node;
  }
  return cond;
}

static ASTNode *parse_assignment(Parser *parser) {
  ASTNode *left = parse_ternary(parser);
  if (match(parser, TOK_EQ) || match(parser, TOK_PLUS_ASSIGN) ||
      match(parser, TOK_MINUS_ASSIGN) || match(parser, TOK_STAR_ASSIGN) ||
      match(parser, TOK_SLASH_ASSIGN)) {
    TokenType op = parser->previous.type;
    int line = parser->previous.line, col = parser->previous.col;
    ASTNode *value = parse_expression(parser);

    if (op == TOK_EQ) {
      ASTNode *node = make_node(NODE_ASSIGN, line, col);
      node->data.assign.lhs = left;
      node->data.assign.value = value;
      return node;
    } else {
      // Desugar compound assignment: x += y -> x = x + y
      char *binary_op = NULL;
      switch (op) {
      case TOK_PLUS_ASSIGN:
        binary_op = strdup("+");
        break;
      case TOK_MINUS_ASSIGN:
        binary_op = strdup("-");
        break;
      case TOK_STAR_ASSIGN:
        binary_op = strdup("*");
        break;
      case TOK_SLASH_ASSIGN:
        binary_op = strdup("/");
        break;
      default:
        break;
      }

      ASTNode *bin = make_node(NODE_BINARY_OP, line, col);
      bin->data.binary.op = binary_op;
      bin->data.binary.left = ast_copy(left);
      bin->data.binary.right = value;

      ASTNode *node = make_node(NODE_ASSIGN, line, col);
      node->data.assign.lhs = left;
      node->data.assign.value = bin;
      return node;
    }
  }
  return left;
}

ASTNode *parse_expression(Parser *parser) { return parse_assignment(parser); }

static ASTNode *parse_statement(Parser *parser);
static ASTNode *parse_block(Parser *parser);

static ASTNode *parse_statement(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;

  if (check(parser, TOK_LBRACE)) {
    return parse_block(parser);
  }

  if (match(parser, TOK_RETURN)) {
    ASTNode *node = make_node(NODE_RETURN_STMT, line, col);
    if (!check(parser, TOK_SEMICOLON))
      node->data.ret.value = parse_expression(parser);
    else
      node->data.ret.value = NULL;
    expect(parser, TOK_SEMICOLON, "Expected ';' after return");
    return node;
  }

  // Variable declaration
  if (is_type_start(parser)) {
    TypeInfo *type = parse_type(parser);
    if (!check(parser, TOK_IDENT)) {
      error(parser, "Expected variable name");
      type_info_free(type);
      return NULL;
    }
    ASTNode *node = make_node(NODE_VAR_DECL, line, col);
    node->data.var.var_type = type;
    node->data.var.name = strdup(parser->current.value);
    advance(parser);
    if (match(parser, TOK_EQ))
      node->data.var.init = parse_expression(parser);
    else
      node->data.var.init = NULL;
    expect(parser, TOK_SEMICOLON, "Expected ';' after variable declaration");
    return node;
  }

  // If statement
  if (match(parser, TOK_IF)) {
    ASTNode *node = make_node(NODE_IF_STMT, line, col);
    expect(parser, TOK_LPAREN, "Expected '(' after if");
    node->data.if_stmt.condition = parse_expression(parser);
    expect(parser, TOK_RPAREN, "Expected ')' after condition");
    node->data.if_stmt.then_block = parse_statement(parser);
    node->data.if_stmt.else_block = NULL;
    if (match(parser, TOK_ELSE)) {
      // Check for else if
      if (check(parser, TOK_IF)) {
        node->data.if_stmt.else_block =
            parse_statement(parser); // Recursively parse else if
      } else {
        node->data.if_stmt.else_block = parse_statement(parser);
      }
    }
    return node;
  }

  // While loop
  if (match(parser, TOK_WHILE)) {
    ASTNode *node = make_node(NODE_WHILE_STMT, line, col);
    expect(parser, TOK_LPAREN, "Expected '(' after while");
    node->data.while_stmt.condition = parse_expression(parser);
    expect(parser, TOK_RPAREN, "Expected ')' after condition");
    node->data.while_stmt.body = parse_statement(parser);
    return node;
  }

  // Do-While loop
  if (match(parser, TOK_DO)) {
    ASTNode *node = make_node(NODE_DO_WHILE, line, col);
    node->data.do_while.body = parse_block(parser);
    expect(parser, TOK_WHILE, "Expected 'while' after do block");
    expect(parser, TOK_LPAREN, "Expected '(' after while");
    node->data.do_while.condition = parse_expression(parser);
    expect(parser, TOK_RPAREN, "Expected ')' after condition");
    expect(parser, TOK_SEMICOLON, "Expected ';' after do-while loop");
    return node;
  }

  // Break statement
  if (match(parser, TOK_BREAK)) {
    ASTNode *node = make_node(NODE_BREAK_STMT, line, col);
    expect(parser, TOK_SEMICOLON, "Expected ';' after break");
    return node;
  }

  // For loop: for (init; condition; update) { body }
  if (match(parser, TOK_FOR)) {
    ASTNode *node = make_node(NODE_FOR_STMT, line, col);
    expect(parser, TOK_LPAREN, "Expected '(' after for");

    // Init (var decl or expression)
    if (is_type_start(parser)) {
      TypeInfo *type = parse_type(parser);
      if (!check(parser, TOK_IDENT)) {
        error(parser, "Expected variable name");
        type_info_free(type);
        return NULL;
      }
      ASTNode *var =
          make_node(NODE_VAR_DECL, parser->current.line, parser->current.col);
      var->data.var.var_type = type;
      var->data.var.name = strdup(parser->current.value);
      advance(parser);
      if (match(parser, TOK_EQ))
        var->data.var.init = parse_expression(parser);
      else
        var->data.var.init = NULL;
      node->data.for_stmt.init = var;
    } else if (!check(parser, TOK_SEMICOLON)) {
      node->data.for_stmt.init = parse_expression(parser);
    } else {
      node->data.for_stmt.init = NULL;
    }
    expect(parser, TOK_SEMICOLON, "Expected ';' after for init");

    // Condition
    if (!check(parser, TOK_SEMICOLON))
      node->data.for_stmt.condition = parse_expression(parser);
    else
      node->data.for_stmt.condition = NULL;
    expect(parser, TOK_SEMICOLON, "Expected ';' after for condition");

    // Update
    if (!check(parser, TOK_RPAREN))
      node->data.for_stmt.update = parse_expression(parser);
    else
      node->data.for_stmt.update = NULL;
    expect(parser, TOK_RPAREN, "Expected ')' after for update");

    node->data.for_stmt.body = parse_statement(parser);
    return node;
  }

  // Expression statement
  ASTNode *expr = parse_expression(parser);
  ASTNode *node = make_node(NODE_EXPR_STMT, line, col);
  node->data.ret.value = expr;
  expect(parser, TOK_SEMICOLON, "Expected ';' after expression");
  return node;
}

static ASTNode *parse_block(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;
  expect(parser, TOK_LBRACE, "Expected '{'");
  ASTNode *node = make_node(NODE_BLOCK, line, col);
  int cap = 8;
  node->data.block.statements = malloc(sizeof(ASTNode *) * cap);
  node->data.block.count = 0;
  while (!check(parser, TOK_RBRACE) && !check(parser, TOK_EOF)) {
    if (node->data.block.count >= cap) {
      cap *= 2;
      node->data.block.statements =
          realloc(node->data.block.statements, sizeof(ASTNode *) * cap);
    }
    ASTNode *stmt = parse_statement(parser);
    if (stmt)
      node->data.block.statements[node->data.block.count++] = stmt;
  }
  expect(parser, TOK_RBRACE, "Expected '}'");
  return node;
}

static ASTNode *parse_struct_decl(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;
  expect(parser, TOK_STRUCT, "Expected 'struct'");
  if (!check(parser, TOK_IDENT)) {
    error(parser, "Expected struct name");
    return NULL;
  }
  char *name = strdup(parser->current.value);
  advance(parser);
  TypeInfo *type = type_info_new(TYPE_STRUCT, name);
  type->field_names = NULL;
  type->field_types = NULL;
  type->field_count = 0;
  type->struct_def = type;
  parser_add_struct(parser, type); // Allow self-references

  expect(parser, TOK_LBRACE, "Expected '{' after struct name");
  int cap = 4;
  type->field_names = malloc(sizeof(char *) * cap);
  type->field_types = malloc(sizeof(TypeInfo *) * cap);

  while (!check(parser, TOK_RBRACE) && !check(parser, TOK_EOF)) {
    if (type->field_count >= cap) {
      cap *= 2;
      type->field_names = realloc(type->field_names, sizeof(char *) * cap);
      type->field_types = realloc(type->field_types, sizeof(TypeInfo *) * cap);
    }
    TypeInfo *ftype = parse_type(parser);
    if (!check(parser, TOK_IDENT)) {
      error(parser, "Expected field name");
      type_info_free(ftype);
      break;
    }
    type->field_names[type->field_count] = strdup(parser->current.value);
    type->field_types[type->field_count] = ftype;
    type->field_count++;
    advance(parser);
    expect(parser, TOK_SEMICOLON, "Expected ';' after field");
  }

  expect(parser, TOK_RBRACE, "Expected '}' after struct fields");
  match(parser, TOK_SEMICOLON); // Optional trailing semicolon

  ASTNode *node = make_node(NODE_STRUCT_DECL, line, col);
  node->data.struct_decl.name = name;
  node->data.struct_decl.type = type;
  return node;
}

static ASTNode *parse_function(Parser *parser) {
  int line = parser->current.line, col = parser->current.col;
  int is_inline = 0;
  int is_local = 0;

  // Parse modifiers
  while (check(parser, TOK_INLINE) || check(parser, TOK_LOCAL)) {
    if (match(parser, TOK_INLINE))
      is_inline = 1;
    if (match(parser, TOK_LOCAL))
      is_local = 1;
  }

  if (!is_type_start(parser)) {
    error(parser, "Expected return type");
    return NULL;
  }
  TypeInfo *ret_type = parse_type(parser);
  if (!check(parser, TOK_IDENT)) {
    error(parser, "Expected function name");
    type_info_free(ret_type);
    return NULL;
  }
  char *raw_name = strdup(parser->current.value);
  ASTNode *node = make_node(NODE_FUNC_DECL, line, col);
  node->data.func.return_type = ret_type;

  node->data.func.method_of =
      parser->current_impl ? strdup(parser->current_impl) : NULL;
  node->data.func.original_name = strdup(raw_name);

  char mangled[512];
  if (parser->current_impl) {
    if (parser->current_prefix && !is_local) {
      snprintf(mangled, sizeof(mangled), "%s_%s_%s", parser->current_prefix,
               parser->current_impl, raw_name);
    } else {
      snprintf(mangled, sizeof(mangled), "%s_%s", parser->current_impl,
               raw_name);
    }
    node->data.func.name = strdup(mangled);
  } else if (parser->current_prefix && !is_local &&
             strcmp(raw_name, "main") != 0) {
    snprintf(mangled, sizeof(mangled), "%s_%s", parser->current_prefix,
             raw_name);
    node->data.func.name = strdup(mangled);
  } else {
    node->data.func.name = strdup(raw_name);
  }

  node->data.func.param_names = NULL;
  node->data.func.param_types = NULL;
  node->data.func.param_count = 0;
  node->data.func.is_inline = is_inline;
  node->data.func.is_local = is_local;
  node->data.func.source_file =
      parser->current_file ? strdup(parser->current_file) : NULL;
  advance(parser);
  free(raw_name);

  expect(parser, TOK_LPAREN, "Expected '('");

  // Parse parameters: type name, type name, ...
  if (!check(parser, TOK_RPAREN)) {
    int cap = 4;
    node->data.func.param_names = malloc(sizeof(char *) * cap);
    node->data.func.param_types = malloc(sizeof(TypeInfo *) * cap);
    do {
      if (node->data.func.param_count >= cap) {
        cap *= 2;
        node->data.func.param_names =
            realloc(node->data.func.param_names, sizeof(char *) * cap);
        node->data.func.param_types =
            realloc(node->data.func.param_types, sizeof(TypeInfo *) * cap);
      }
      TypeInfo *ptype = parse_type(parser);
      if (!check(parser, TOK_IDENT)) {
        error(parser, "Expected parameter name");
        type_info_free(ptype);
        break;
      }
      node->data.func.param_types[node->data.func.param_count] = ptype;
      node->data.func.param_names[node->data.func.param_count] =
          strdup(parser->current.value);
      node->data.func.param_count++;
      advance(parser);
    } while (match(parser, TOK_COMMA));
  }

  expect(parser, TOK_RPAREN, "Expected ')'");
  node->data.func.body = parse_block(parser);
  return node;
}

static void parse_impl_block(Parser *parser, ASTNode *program, int *cap) {
  // Current token should be the identifier after 'impl'
  if (!check(parser, TOK_IDENT)) {
    error(parser, "Expected struct name after impl");
    return;
  }
  char *owner = strdup(parser->current.value);
  if (!parser_has_struct(parser, owner)) {
    error(parser, "Unknown struct in impl block");
  }
  advance(parser);
  expect(parser, TOK_LBRACE, "Expected '{' after impl name");

  char *old_impl = parser->current_impl;
  parser->current_impl = strdup(owner);

  while (!check(parser, TOK_RBRACE) && !check(parser, TOK_EOF)) {
    if (program->data.program.count >= *cap) {
      *cap *= 2;
      program->data.program.decls =
          realloc(program->data.program.decls, sizeof(ASTNode *) * (*cap));
    }
    ASTNode *decl = parse_function(parser);
    if (decl)
      program->data.program.decls[program->data.program.count++] = decl;
  }
  expect(parser, TOK_RBRACE, "Expected '}' after impl block");

  free(parser->current_impl);
  parser->current_impl = old_impl;
  free(owner);
}

static char *read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  long length = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *buffer = malloc(length + 1);
  if (!buffer) {
    fclose(f);
    return NULL;
  }
  fread(buffer, 1, length, f);
  buffer[length] = '\0';
  fclose(f);
  return buffer;
}

ASTNode *parse(Parser *parser) {
  ASTNode *program = make_node(NODE_PROGRAM, 1, 1);
  int cap = 8;
  program->data.program.decls = malloc(sizeof(ASTNode *) * cap);
  program->data.program.count = 0;

  while (!check(parser, TOK_EOF) && !parser->had_error) {
    // Handle #include (well, keyword "include")
    if (check(parser, TOK_INCLUDE)) {
      advance(parser); // eat include

      char path[1024] = {0};
      int leading_dots = 0;
      while (check(parser, TOK_DOT)) {
        leading_dots++;
        advance(parser);
      }

      // .. -> ../ (one level up)
      if (leading_dots >= 2) {
        for (int i = 0; i < leading_dots - 1; i++) {
          strcat(path, "../");
        }
      }

      if (!check(parser, TOK_IDENT)) {
        error(parser, "Expected module path");
        continue;
      }

      strcat(path, parser->current.value);
      advance(parser);

      while (match(parser, TOK_DOT)) {
        strcat(path, "/");
        if (!check(parser, TOK_IDENT)) {
          error(parser, "Expected segment name");
          break;
        }
        strcat(path, parser->current.value);
        advance(parser);
      }

      char *alias = NULL;
      // Default alias is the last segment of the path
      char *last_seg = strrchr(path, '/');
      if (last_seg) {
        alias =
            last_seg + 1; // Point to it, don't dup yet if we might overwrite
      } else {
        alias = path;
      }
      char *final_alias = strdup(alias);

      // Check for 'as' alias
      if (match(parser, TOK_AS)) {
        if (!check(parser, TOK_IDENT)) {
          error(parser, "Expected alias name after 'as'");
        } else {
          free(final_alias);
          final_alias = strdup(parser->current.value);
          advance(parser);
        }
      }

      expect(parser, TOK_SEMICOLON, "Expected ';' after include");
      char *fname_raw = strdup(path);

      // Construct path relative to current file
      char *path_to_open = NULL;
      char base_dir[1024] = {0};

      if (parser->current_file) {
        char *last_slash = strrchr(parser->current_file, '/');
        if (last_slash) {
          size_t dir_len = last_slash - parser->current_file + 1;
          strncpy(base_dir, parser->current_file, dir_len);
          base_dir[dir_len] = '\0';
        }
      }

      char full_path[2048];
      char *target_filename = fname_raw;

      // If filename doesn't contain extension, assume .c26 unless it already
      // has one
      char filename_with_ext[1024];
      if (!strstr(target_filename, ".c26")) {
        snprintf(filename_with_ext, sizeof(filename_with_ext), "%s.c26",
                 target_filename);
        target_filename = filename_with_ext;
      }

      snprintf(full_path, sizeof(full_path), "%s%s", base_dir, target_filename);
      path_to_open = full_path;

      free(fname_raw);

      // Calculate prefix for this module
      char *prefix = canonicalize_path_to_prefix(path_to_open);
      char *ext = strstr(prefix, ".c26");
      if (ext)
        *ext = '\0';

      // Register import
      parser_add_import(parser, final_alias, prefix);
      free(final_alias);

      char *content = read_file(path_to_open);
      if (!content) {
        char msg[1024];
        snprintf(msg, sizeof(msg), "Could not open included file: %s",
                 path_to_open);
        error(parser, msg);
        free(prefix);
        continue;
      }

      // Recursively parse included file
      Lexer *lexer = lexer_init(content);
      Parser *sub_parser = parser_init(lexer);
      if (parser->current_file) {
        sub_parser->current_file = strdup(path_to_open);
      }
      sub_parser->current_prefix = prefix;

      ASTNode *sub_program = parse(sub_parser);

      if (sub_parser->had_error) {
        parser->had_error = 1;
      } else {
        // Merge decls
        for (int i = 0; i < sub_program->data.program.count; i++) {
          if (program->data.program.count >= cap) {
            cap *= 2;
            program->data.program.decls =
                realloc(program->data.program.decls, sizeof(ASTNode *) * cap);
          }
          program->data.program.decls[program->data.program.count++] =
              sub_program->data.program.decls[i];
        }
        // Merge struct definitions for downstream parsing
        for (int i = 0; i < sub_parser->struct_count; i++) {
          parser_add_struct(parser, sub_parser->struct_types[i]);
        }
      }

      // Cleanup sub-parser, but NOT the nodes we just moved
      // We free sub_program container but not its children
      free(sub_program->data.program.decls);
      free(sub_program);
      parser_free(sub_parser);
      lexer_free(lexer);
      free(content);
      continue;
    }

    if (program->data.program.count >= cap) {
      cap *= 2;
      program->data.program.decls =
          realloc(program->data.program.decls, sizeof(ASTNode *) * cap);
    }
    if (check(parser, TOK_STRUCT)) {
      ASTNode *decl = parse_struct_decl(parser);
      if (decl)
        program->data.program.decls[program->data.program.count++] = decl;
      continue;
    }
    if (check(parser, TOK_IMPL)) {
      advance(parser); // consume impl
      parse_impl_block(parser, program, &cap);
      continue;
    }
    ASTNode *decl = parse_function(parser);
    if (decl)
      program->data.program.decls[program->data.program.count++] = decl;
  }
  return program;
}

void ast_free(ASTNode *node);

TypeInfo *type_info_copy(TypeInfo *type) {
  if (!type)
    return NULL;
  TypeInfo *copy = malloc(sizeof(TypeInfo));
  memcpy(copy, type, sizeof(TypeInfo));
  if (type->name)
    copy->name = strdup(type->name);
  if (type->element_type)
    copy->element_type = type_info_copy(type->element_type);
  if (type->key_type)
    copy->key_type = type_info_copy(type->key_type);
  if (type->value_type)
    copy->value_type = type_info_copy(type->value_type);
  if (type->kind == TYPE_TUPLE && type->tuple_types) {
    copy->tuple_types = malloc(sizeof(TypeInfo *) * type->tuple_count);
    for (int i = 0; i < type->tuple_count; i++)
      copy->tuple_types[i] = type_info_copy(type->tuple_types[i]);
  }
  if (type->kind == TYPE_STRUCT && type->owns_fields) {
    copy->field_names = malloc(sizeof(char *) * type->field_count);
    copy->field_types = malloc(sizeof(TypeInfo *) * type->field_count);
    for (int i = 0; i < type->field_count; i++) {
      copy->field_names[i] = strdup(type->field_names[i]);
      copy->field_types[i] = type_info_copy(type->field_types[i]);
    }
  }
  return copy;
}

void ast_free(ASTNode *node) {
  if (!node)
    return;
  switch (node->type) {
  case NODE_PROGRAM:
    for (int i = 0; i < node->data.program.count; i++)
      ast_free(node->data.program.decls[i]);
    free(node->data.program.decls);
    break;
  case NODE_FUNC_DECL:
    type_info_free(node->data.func.return_type);
    free(node->data.func.name);
    if (node->data.func.method_of)
      free(node->data.func.method_of);
    if (node->data.func.original_name)
      free(node->data.func.original_name);
    for (int i = 0; i < node->data.func.param_count; i++) {
      type_info_free(node->data.func.param_types[i]);
      free(node->data.func.param_names[i]);
    }
    free(node->data.func.param_types);
    free(node->data.func.param_names);
    ast_free(node->data.func.body);
    break;
  case NODE_BLOCK:
    for (int i = 0; i < node->data.block.count; i++)
      ast_free(node->data.block.statements[i]);
    free(node->data.block.statements);
    break;
  case NODE_RETURN_STMT:
  case NODE_EXPR_STMT:
    ast_free(node->data.ret.value);
    break;
  case NODE_VAR_DECL:
    type_info_free(node->data.var.var_type);
    free(node->data.var.name);
    ast_free(node->data.var.init);
    break;
  case NODE_INT_LIT:
  case NODE_FLOAT_LIT:
    free(node->data.literal.value);
    break;
  case NODE_STRING_LIT:
    free(node->data.string.value);
    break;
  case NODE_NULL_LIT:
    break;
  case NODE_CHAR_LIT:
    free(node->data.character.value);
    break;
  case NODE_BOOL_LIT:
    break;
  case NODE_IDENT:
    free(node->data.ident.name);
    break;
  case NODE_BINARY_OP:
    free(node->data.binary.op);
    ast_free(node->data.binary.left);
    ast_free(node->data.binary.right);
    break;
  case NODE_UNARY_OP:
    free(node->data.unary.op);
    ast_free(node->data.unary.operand);
    break;
  case NODE_TYPEOF:
    ast_free(node->data.typeof_expr.expr);
    break;
  case NODE_DEST_ASSIGN:
    ast_free(node->data.dest_assign.lhs);
    ast_free(node->data.dest_assign.rhs);
    break;
  case NODE_CALL:
    free(node->data.call.name);
    for (int i = 0; i < node->data.call.arg_count; i++)
      ast_free(node->data.call.args[i]);
    free(node->data.call.args);
    break;
  case NODE_ARRAY_LIT:
  case NODE_TUPLE_LIT:
    for (int i = 0; i < node->data.array.count; i++)
      ast_free(node->data.array.elements[i]);
    free(node->data.array.elements);
    break;
  case NODE_INDEX:
    ast_free(node->data.index.array);
    ast_free(node->data.index.index);
    break;
  case NODE_IF_STMT:
    ast_free(node->data.if_stmt.condition);
    ast_free(node->data.if_stmt.then_block);
    ast_free(node->data.if_stmt.else_block);
    break;
  case NODE_WHILE_STMT:
    ast_free(node->data.while_stmt.condition);
    ast_free(node->data.while_stmt.body);
    break;
  case NODE_TERNARY:
    ast_free(node->data.ternary.condition);
    ast_free(node->data.ternary.then_expr);
    ast_free(node->data.ternary.else_expr);
    break;
  case NODE_ASSIGN:
    ast_free(node->data.assign.lhs);
    ast_free(node->data.assign.value);
    break;

  case NODE_FOR_STMT:
    if (node->data.for_stmt.init)
      ast_free(node->data.for_stmt.init);
    if (node->data.for_stmt.condition)
      ast_free(node->data.for_stmt.condition);
    if (node->data.for_stmt.update)
      ast_free(node->data.for_stmt.update);
    ast_free(node->data.for_stmt.body);
    break;
  case NODE_MATCH_EXPR:
    ast_free(node->data.match_expr.value);
    for (int i = 0; i < node->data.match_expr.case_count; i++) {
      if (node->data.match_expr.case_values[i])
        ast_free(node->data.match_expr.case_values[i]);
      ast_free(node->data.match_expr.case_bodies[i]);
    }
    free(node->data.match_expr.case_values);
    free(node->data.match_expr.case_bodies);
    break;
  case NODE_BREAK_STMT:
    break;
  case NODE_DO_WHILE:
    ast_free(node->data.do_while.body);
    ast_free(node->data.do_while.condition);
    break;
  case NODE_INTERPOLATED_STRING:
    for (int i = 0; i < node->data.interpolated_string.count; i++) {
      ast_free(node->data.interpolated_string.parts[i]);
    }
    free(node->data.interpolated_string.parts);
    break;
  case NODE_DEREF:
  case NODE_ADDR_OF:
    free(node->data.unary.op);
    ast_free(node->data.unary.operand);
    break;
  case NODE_CAST:
    type_info_free(node->data.cast.target_type);
    ast_free(node->data.cast.expr);
    break;
  case NODE_SIZEOF:
    if (node->data.s_of.target_type)
      type_info_free(node->data.s_of.target_type);
    if (node->data.s_of.expr)
      ast_free(node->data.s_of.expr);
    break;
  case NODE_STRUCT_DECL:
    free(node->data.struct_decl.name);
    type_info_free(node->data.struct_decl.type);
    break;
  case NODE_STRUCT_LIT:
    if (node->data.struct_lit.type_name)
      free(node->data.struct_lit.type_name);
    for (int i = 0; i < node->data.struct_lit.field_count; i++) {
      free(node->data.struct_lit.field_names[i]);
      ast_free(node->data.struct_lit.field_values[i]);
    }
    free(node->data.struct_lit.field_names);
    free(node->data.struct_lit.field_values);
    break;
  case NODE_FIELD_ACCESS:
    ast_free(node->data.field_access.object);
    free(node->data.field_access.field);
    break;
  case NODE_METHOD_CALL:
    ast_free(node->data.method_call.receiver);
    free(node->data.method_call.method);
    for (int i = 0; i < node->data.method_call.arg_count; i++)
      ast_free(node->data.method_call.args[i]);
    free(node->data.method_call.args);
    break;
  }
  free(node);
}

ASTNode *ast_copy(ASTNode *node) {
  if (!node)
    return NULL;
  ASTNode *copy = malloc(sizeof(ASTNode));
  memcpy(copy, node, sizeof(ASTNode));

  switch (node->type) {
  case NODE_PROGRAM:
    copy->data.program.decls =
        malloc(sizeof(ASTNode *) * node->data.program.count);
    for (int i = 0; i < node->data.program.count; i++)
      copy->data.program.decls[i] = ast_copy(node->data.program.decls[i]);
    break;
  case NODE_FUNC_DECL:
    copy->data.func.name = strdup(node->data.func.name);
    copy->data.func.return_type = type_info_copy(node->data.func.return_type);
    if (node->data.func.method_of)
      copy->data.func.method_of = strdup(node->data.func.method_of);
    if (node->data.func.original_name)
      copy->data.func.original_name = strdup(node->data.func.original_name);
    copy->data.func.param_names =
        malloc(sizeof(char *) * node->data.func.param_count);
    copy->data.func.param_types =
        malloc(sizeof(TypeInfo *) * node->data.func.param_count);
    for (int i = 0; i < node->data.func.param_count; i++) {
      copy->data.func.param_names[i] = strdup(node->data.func.param_names[i]);
      copy->data.func.param_types[i] =
          type_info_copy(node->data.func.param_types[i]);
    }
    copy->data.func.body = ast_copy(node->data.func.body);
    break;
  case NODE_BLOCK:
    copy->data.block.statements =
        malloc(sizeof(ASTNode *) * node->data.block.count);
    for (int i = 0; i < node->data.block.count; i++)
      copy->data.block.statements[i] = ast_copy(node->data.block.statements[i]);
    break;
  case NODE_RETURN_STMT:
  case NODE_EXPR_STMT:
    copy->data.ret.value = ast_copy(node->data.ret.value);
    break;
  case NODE_VAR_DECL:
    copy->data.var.var_type = type_info_copy(node->data.var.var_type);
    copy->data.var.name = strdup(node->data.var.name);
    copy->data.var.init = ast_copy(node->data.var.init);
    break;
  case NODE_INT_LIT:
  case NODE_FLOAT_LIT:
    copy->data.literal.value = strdup(node->data.literal.value);
    break;
  case NODE_STRING_LIT:
    copy->data.string.value = strdup(node->data.string.value);
    break;
  case NODE_CHAR_LIT:
    copy->data.character.value = strdup(node->data.character.value);
    break;
  case NODE_IDENT:
    copy->data.ident.name = strdup(node->data.ident.name);
    break;
  case NODE_BINARY_OP:
    copy->data.binary.op = strdup(node->data.binary.op);
    copy->data.binary.left = ast_copy(node->data.binary.left);
    copy->data.binary.right = ast_copy(node->data.binary.right);
    break;
  case NODE_UNARY_OP:
    copy->data.unary.op = strdup(node->data.unary.op);
    copy->data.unary.operand = ast_copy(node->data.unary.operand);
    break;
  case NODE_TYPEOF:
    copy->data.typeof_expr.expr = ast_copy(node->data.typeof_expr.expr);
    break;
  case NODE_DEST_ASSIGN:
    copy->data.dest_assign.lhs = ast_copy(node->data.dest_assign.lhs);
    copy->data.dest_assign.rhs = ast_copy(node->data.dest_assign.rhs);
    break;
  case NODE_CALL:
    copy->data.call.name = strdup(node->data.call.name);
    copy->data.call.args =
        malloc(sizeof(ASTNode *) * node->data.call.arg_count);
    for (int i = 0; i < node->data.call.arg_count; i++)
      copy->data.call.args[i] = ast_copy(node->data.call.args[i]);
    break;
  case NODE_ARRAY_LIT:
  case NODE_TUPLE_LIT:
    copy->data.array.elements =
        malloc(sizeof(ASTNode *) * node->data.array.count);
    for (int i = 0; i < node->data.array.count; i++)
      copy->data.array.elements[i] = ast_copy(node->data.array.elements[i]);
    break;
  case NODE_INDEX:
    copy->data.index.array = ast_copy(node->data.index.array);
    copy->data.index.index = ast_copy(node->data.index.index);
    break;
  case NODE_IF_STMT:
    copy->data.if_stmt.condition = ast_copy(node->data.if_stmt.condition);
    copy->data.if_stmt.then_block = ast_copy(node->data.if_stmt.then_block);
    copy->data.if_stmt.else_block = ast_copy(node->data.if_stmt.else_block);
    break;
  case NODE_WHILE_STMT:
    copy->data.while_stmt.condition = ast_copy(node->data.while_stmt.condition);
    copy->data.while_stmt.body = ast_copy(node->data.while_stmt.body);
    break;
  case NODE_TERNARY:
    copy->data.ternary.condition = ast_copy(node->data.ternary.condition);
    copy->data.ternary.then_expr = ast_copy(node->data.ternary.then_expr);
    copy->data.ternary.else_expr = ast_copy(node->data.ternary.else_expr);
    break;
  case NODE_ASSIGN:
    copy->data.assign.lhs = ast_copy(node->data.assign.lhs);
    copy->data.assign.value = ast_copy(node->data.assign.value);
    break;
  case NODE_FOR_STMT:
    copy->data.for_stmt.init = ast_copy(node->data.for_stmt.init);
    copy->data.for_stmt.condition = ast_copy(node->data.for_stmt.condition);
    copy->data.for_stmt.update = ast_copy(node->data.for_stmt.update);
    copy->data.for_stmt.body = ast_copy(node->data.for_stmt.body);
    break;
  case NODE_MATCH_EXPR:
    copy->data.match_expr.value = ast_copy(node->data.match_expr.value);
    copy->data.match_expr.case_values =
        malloc(sizeof(ASTNode *) * node->data.match_expr.case_count);
    copy->data.match_expr.case_bodies =
        malloc(sizeof(ASTNode *) * node->data.match_expr.case_count);
    for (int i = 0; i < node->data.match_expr.case_count; i++) {
      copy->data.match_expr.case_values[i] =
          ast_copy(node->data.match_expr.case_values[i]);
      copy->data.match_expr.case_bodies[i] =
          ast_copy(node->data.match_expr.case_bodies[i]);
    }
    break;
  case NODE_STRUCT_DECL:
    copy->data.struct_decl.name = strdup(node->data.struct_decl.name);
    copy->data.struct_decl.type = type_info_copy(node->data.struct_decl.type);
    break;
  case NODE_STRUCT_LIT:
    if (node->data.struct_lit.type_name)
      copy->data.struct_lit.type_name = strdup(node->data.struct_lit.type_name);
    copy->data.struct_lit.field_names =
        malloc(sizeof(char *) * node->data.struct_lit.field_count);
    copy->data.struct_lit.field_values =
        malloc(sizeof(ASTNode *) * node->data.struct_lit.field_count);
    for (int i = 0; i < node->data.struct_lit.field_count; i++) {
      copy->data.struct_lit.field_names[i] =
          strdup(node->data.struct_lit.field_names[i]);
      copy->data.struct_lit.field_values[i] =
          ast_copy(node->data.struct_lit.field_values[i]);
    }
    break;
  case NODE_FIELD_ACCESS:
    copy->data.field_access.object = ast_copy(node->data.field_access.object);
    copy->data.field_access.field = strdup(node->data.field_access.field);
    break;
  case NODE_METHOD_CALL:
    copy->data.method_call.receiver = ast_copy(node->data.method_call.receiver);
    copy->data.method_call.method = strdup(node->data.method_call.method);
    copy->data.method_call.args =
        malloc(sizeof(ASTNode *) * node->data.method_call.arg_count);
    for (int i = 0; i < node->data.method_call.arg_count; i++)
      copy->data.method_call.args[i] = ast_copy(node->data.method_call.args[i]);
    break;
  default:
    break;
  }
  return copy;
}

void ast_print(ASTNode *node, int indent) {
  if (!node)
    return;
  for (int i = 0; i < indent; i++)
    printf("  ");
  switch (node->type) {
  case NODE_PROGRAM:
    printf("Program\n");
    for (int i = 0; i < node->data.program.count; i++)
      ast_print(node->data.program.decls[i], indent + 1);
    break;
  case NODE_FUNC_DECL: {
    char *ts = type_info_to_string(node->data.func.return_type);
    if (node->data.func.method_of) {
      printf("Method: %s %s::%s()\n", ts, node->data.func.method_of,
             node->data.func.original_name);
    } else {
      printf("Function: %s %s()\n", ts, node->data.func.name);
    }
    free(ts);
    ast_print(node->data.func.body, indent + 1);
    break;
  }
  case NODE_BLOCK:
    printf("Block\n");
    for (int i = 0; i < node->data.block.count; i++)
      ast_print(node->data.block.statements[i], indent + 1);
    break;
  case NODE_RETURN_STMT:
    printf("Return\n");
    if (node->data.ret.value)
      ast_print(node->data.ret.value, indent + 1);
    break;
  case NODE_VAR_DECL: {
    char *ts = type_info_to_string(node->data.var.var_type);
    printf("VarDecl: %s %s\n", ts, node->data.var.name);
    free(ts);
    if (node->data.var.init)
      ast_print(node->data.var.init, indent + 1);
    break;
  }
  case NODE_INT_LIT:
    printf("IntLit: %s\n", node->data.literal.value);
    break;
  case NODE_FLOAT_LIT:
    printf("FloatLit: %s\n", node->data.literal.value);
    break;
  case NODE_STRING_LIT:
    printf("StringLit: \"%s\"\n", node->data.string.value);
    break;
  case NODE_NULL_LIT:
    printf("NullLit\n");
    break;
  case NODE_CHAR_LIT:
    printf("CharLit: '%s'\n", node->data.character.value);
    break;
  case NODE_BOOL_LIT:
    printf("BoolLit: %s\n", node->data.boolean.value ? "true" : "false");
    break;
  case NODE_IDENT:
    printf("Ident: %s\n", node->data.ident.name);
    break;
  case NODE_BINARY_OP:
    printf("BinaryOp: %s\n", node->data.binary.op);
    ast_print(node->data.binary.left, indent + 1);
    ast_print(node->data.binary.right, indent + 1);
    break;
  case NODE_UNARY_OP:
    printf("UnaryOp: %s\n", node->data.unary.op);
    ast_print(node->data.unary.operand, indent + 1);
    break;
  case NODE_TYPEOF:
    printf("Typeof\n");
    ast_print(node->data.typeof_expr.expr, indent + 1);
    break;
  case NODE_DEST_ASSIGN:
    printf("DestructuringAssign\n");
    ast_print(node->data.dest_assign.lhs, indent + 1);
    ast_print(node->data.dest_assign.rhs, indent + 1);
    break;
  case NODE_CALL:
    printf("Call: %s()\n", node->data.call.name);
    for (int i = 0; i < node->data.call.arg_count; i++)
      ast_print(node->data.call.args[i], indent + 1);
    break;
  case NODE_ARRAY_LIT:
    printf("ArrayLit\n");
    for (int i = 0; i < node->data.array.count; i++)
      ast_print(node->data.array.elements[i], indent + 1);
    break;
  case NODE_TUPLE_LIT:
    printf("TupleLit\n");
    for (int i = 0; i < node->data.array.count; i++)
      ast_print(node->data.array.elements[i], indent + 1);
    break;
  case NODE_INDEX:
    printf("Index\n");
    ast_print(node->data.index.array, indent + 1);
    ast_print(node->data.index.index, indent + 1);
    break;
  case NODE_EXPR_STMT:
    printf("ExprStmt\n");
    ast_print(node->data.ret.value, indent + 1);
    break;
  case NODE_IF_STMT:
    printf("IfStmt\n");
    ast_print(node->data.if_stmt.condition, indent + 1);
    printf("%*sThen\n", (indent + 1) * 2, "");
    ast_print(node->data.if_stmt.then_block, indent + 2);
    if (node->data.if_stmt.else_block) {
      printf("%*sElse\n", (indent + 1) * 2, "");
      ast_print(node->data.if_stmt.else_block, indent + 2);
    }
    break;
  case NODE_WHILE_STMT:
    printf("WhileStmt\n");
    ast_print(node->data.while_stmt.condition, indent + 1);
    ast_print(node->data.while_stmt.body, indent + 1);
    break;
  case NODE_DO_WHILE:
    printf("DoWhileStmt\n");
    ast_print(node->data.do_while.body, indent + 1);
    ast_print(node->data.do_while.condition, indent + 1);
    break;
  case NODE_TERNARY:
    printf("Ternary\n");
    ast_print(node->data.ternary.condition, indent + 1);
    ast_print(node->data.ternary.then_expr, indent + 1);
    ast_print(node->data.ternary.else_expr, indent + 1);
    break;
  case NODE_ASSIGN:
    printf("Assign\n");
    ast_print(node->data.assign.lhs, indent + 1);
    ast_print(node->data.assign.value, indent + 1);
    break;

  case NODE_FOR_STMT:
    printf("ForStmt\n");
    if (node->data.for_stmt.init) {
      printf("%*sInit\n", (indent + 1) * 2, "");
      ast_print(node->data.for_stmt.init, indent + 2);
    }
    if (node->data.for_stmt.condition) {
      printf("%*sCond\n", (indent + 1) * 2, "");
      ast_print(node->data.for_stmt.condition, indent + 2);
    }
    if (node->data.for_stmt.update) {
      printf("%*sUpdate\n", (indent + 1) * 2, "");
      ast_print(node->data.for_stmt.update, indent + 2);
    }
    ast_print(node->data.for_stmt.body, indent + 1);
    break;
  case NODE_MATCH_EXPR:
    printf("MatchExpr\n");
    ast_print(node->data.match_expr.value, indent + 1);
    for (int i = 0; i < node->data.match_expr.case_count; i++) {
      if (node->data.match_expr.case_values[i]) {
        printf("%*sPattern\n", (indent + 1) * 2, "");
        ast_print(node->data.match_expr.case_values[i], indent + 2);
      } else {
        printf("%*sDefault\n", (indent + 1) * 2, "");
      }
      printf("%*s=>\n", (indent + 1) * 2, "");
      ast_print(node->data.match_expr.case_bodies[i], indent + 2);
    }
    break;
  case NODE_BREAK_STMT:
    printf("BreakStmt\n");
    break;
  case NODE_INTERPOLATED_STRING:
    printf("InterpolatedString\n");
    for (int i = 0; i < node->data.interpolated_string.count; i++) {
      ast_print(node->data.interpolated_string.parts[i], indent + 1);
    }
    break;
  case NODE_DEREF:
    printf("Deref: %s\n", node->data.unary.op);
    ast_print(node->data.unary.operand, indent + 1);
    break;
  case NODE_ADDR_OF:
    printf("AddrOf: %s\n", node->data.unary.op);
    ast_print(node->data.unary.operand, indent + 1);
    break;
  case NODE_CAST: {
    char *ts = type_info_to_string(node->data.cast.target_type);
    printf("Cast: (%s)\n", ts);
    free(ts);
    ast_print(node->data.cast.expr, indent + 1);
    break;
  }
  case NODE_SIZEOF: {
    if (node->data.s_of.target_type) {
      char *ts = type_info_to_string(node->data.s_of.target_type);
      printf("Sizeof: (%s)\n", ts);
      free(ts);
    } else {
      printf("Sizeof:\n");
      ast_print(node->data.s_of.expr, indent + 1);
    }
    break;
  }
  case NODE_STRUCT_DECL: {
    printf("StructDecl: %s\n", node->data.struct_decl.name);
    for (int i = 0; i < node->data.struct_decl.type->field_count; i++) {
      for (int j = 0; j < indent + 1; j++)
        printf("  ");
      char *ts =
          type_info_to_string(node->data.struct_decl.type->field_types[i]);
      printf("%s %s\n", ts, node->data.struct_decl.type->field_names[i]);
      free(ts);
    }
    break;
  }
  case NODE_STRUCT_LIT:
    printf("StructLit\n");
    for (int i = 0; i < node->data.struct_lit.field_count; i++) {
      printf("%*s%s:\n", (indent + 1) * 2, "",
             node->data.struct_lit.field_names[i]);
      ast_print(node->data.struct_lit.field_values[i], indent + 2);
    }
    break;
  case NODE_FIELD_ACCESS:
    printf("FieldAccess: %s\n", node->data.field_access.field);
    ast_print(node->data.field_access.object, indent + 1);
    break;
  case NODE_METHOD_CALL:
    printf("MethodCall: %s()\n", node->data.method_call.method);
    ast_print(node->data.method_call.receiver, indent + 1);
    for (int i = 0; i < node->data.method_call.arg_count; i++)
      ast_print(node->data.method_call.args[i], indent + 1);
    break;
  }
}
