/*
 * C26 Compiler - Lexer Implementation
 */

#include "lexer.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Lexer *lexer_init(char *source) {
  Lexer *lexer = malloc(sizeof(Lexer));
  lexer->source = source;
  lexer->length = strlen(source);
  lexer->pos = 0;
  lexer->line = 1;
  lexer->col = 1;
  return lexer;
}

void lexer_free(Lexer *lexer) { free(lexer); }

void token_free(Token *token) {
  if (token->value) {
    free(token->value);
    token->value = NULL;
  }
}

static char peek(Lexer *lexer) {
  if (lexer->pos >= lexer->length)
    return '\0';
  return lexer->source[lexer->pos];
}

static char peek_next(Lexer *lexer) {
  if (lexer->pos + 1 >= lexer->length)
    return '\0';
  return lexer->source[lexer->pos + 1];
}

static char advance(Lexer *lexer) {
  char c = peek(lexer);
  lexer->pos++;
  if (c == '\n') {
    lexer->line++;
    lexer->col = 1;
  } else {
    lexer->col++;
  }
  return c;
}

static void skip_whitespace(Lexer *lexer) {
  while (1) {
    char c = peek(lexer);
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      advance(lexer);
    } else if (c == '/' && peek_next(lexer) == '/') {
      while (peek(lexer) != '\n' && peek(lexer) != '\0')
        advance(lexer);
    } else if (c == '/' && peek_next(lexer) == '*') {
      advance(lexer);
      advance(lexer);
      while (!(peek(lexer) == '*' && peek_next(lexer) == '/') &&
             peek(lexer) != '\0')
        advance(lexer);
      if (peek(lexer) != '\0') {
        advance(lexer);
        advance(lexer);
      }
    } else
      break;
  }
}

static Token make_token(TokenType type, char *value, int line, int col) {
  Token token = {type, value, line, col};
  return token;
}

static char *substring(char *source, size_t start, size_t end) {
  size_t len = end - start;
  char *str = malloc(len + 1);
  strncpy(str, source + start, len);
  str[len] = '\0';
  return str;
}

static TokenType check_keyword(char *ident) {
  // Signed integers
  if (strcmp(ident, "i8") == 0)
    return TOK_I8;
  if (strcmp(ident, "i16") == 0)
    return TOK_I16;
  if (strcmp(ident, "i32") == 0)
    return TOK_I32;
  if (strcmp(ident, "i64") == 0)
    return TOK_I64;
  if (strcmp(ident, "i128") == 0)
    return TOK_I128;
  if (strcmp(ident, "isize") == 0)
    return TOK_ISIZE;
  // Unsigned integers
  if (strcmp(ident, "u8") == 0)
    return TOK_U8;
  if (strcmp(ident, "u16") == 0)
    return TOK_U16;
  if (strcmp(ident, "u32") == 0)
    return TOK_U32;
  if (strcmp(ident, "u64") == 0)
    return TOK_U64;
  if (strcmp(ident, "u128") == 0)
    return TOK_U128;
  if (strcmp(ident, "usize") == 0)
    return TOK_USIZE;
  // Floats
  if (strcmp(ident, "f32") == 0)
    return TOK_F32;
  if (strcmp(ident, "f64") == 0)
    return TOK_F64;
  // Other primitives
  if (strcmp(ident, "bool") == 0)
    return TOK_BOOL;
  if (strcmp(ident, "char") == 0)
    return TOK_CHAR;
  if (strcmp(ident, "str") == 0)
    return TOK_STR;
  if (strcmp(ident, "void") == 0)
    return TOK_VOID;
  if (strcmp(ident, "struct") == 0)
    return TOK_STRUCT;
  if (strcmp(ident, "impl") == 0)
    return TOK_IMPL;
  if (strcmp(ident, "const") == 0)
    return TOK_CONST;
  // Generic collections
  if (strcmp(ident, "dict") == 0)
    return TOK_DICT;
  if (strcmp(ident, "set") == 0)
    return TOK_SET;
  // Control flow
  if (strcmp(ident, "return") == 0)
    return TOK_RETURN;
  if (strcmp(ident, "if") == 0)
    return TOK_IF;
  if (strcmp(ident, "else") == 0)
    return TOK_ELSE;
  if (strcmp(ident, "while") == 0)
    return TOK_WHILE;
  if (strcmp(ident, "do") == 0)
    return TOK_DO;
  if (strcmp(ident, "for") == 0)
    return TOK_FOR;
  // Function Modifiers & Directives
  if (strcmp(ident, "inline") == 0)
    return TOK_INLINE;
  if (strcmp(ident, "include") == 0)
    return TOK_INCLUDE;
  if (strcmp(ident, "local") == 0)
    return TOK_LOCAL;
  if (strcmp(ident, "as") == 0)
    return TOK_AS;
  // Booleans
  if (strcmp(ident, "true") == 0)
    return TOK_TRUE;
  if (strcmp(ident, "false") == 0)
    return TOK_FALSE;
  if (strcmp(ident, "null") == 0)
    return TOK_NULL;
  if (strcmp(ident, "typeof") == 0)
    return TOK_TYPEOF;
  if (strcmp(ident, "auto") == 0)
    return TOK_AUTO;
  if (strcmp(ident, "break") == 0)
    return TOK_BREAK;
  if (strcmp(ident, "match") == 0)
    return TOK_MATCH;
  if (strcmp(ident, "sizeof") == 0)
    return TOK_SIZEOF;
  if (strcmp(ident, "_") == 0)
    return TOK_UNDERSCORE;
  return TOK_IDENT;
}

static Token scan_identifier(Lexer *lexer) {
  int start_line = lexer->line, start_col = lexer->col;
  size_t start = lexer->pos;
  while (isalnum(peek(lexer)) || peek(lexer) == '_')
    advance(lexer);
  char *value = substring(lexer->source, start, lexer->pos);
  return make_token(check_keyword(value), value, start_line, start_col);
}

static Token scan_number(Lexer *lexer) {
  int start_line = lexer->line, start_col = lexer->col;
  size_t start = lexer->pos;
  TokenType type = TOK_INT_LIT;
  while (isdigit(peek(lexer)))
    advance(lexer);
  if (peek(lexer) == '.' && isdigit(peek_next(lexer))) {
    type = TOK_FLOAT_LIT;
    advance(lexer);
    while (isdigit(peek(lexer)))
      advance(lexer);
  }
  return make_token(type, substring(lexer->source, start, lexer->pos),
                    start_line, start_col);
}

static Token scan_string(Lexer *lexer) {
  int start_line = lexer->line, start_col = lexer->col;
  advance(lexer); // consume "

  // Pass 1: Calculate length and find end
  size_t start = lexer->pos;
  int depth = 0;

  while (lexer->pos < lexer->length) {
    char c = peek(lexer);

    if (depth == 0) {
      if (c == '"') {
        break; // End of string
      } else if (c == '\\') {
        advance(lexer); // skip escape
        if (peek(lexer) != '\0')
          advance(lexer);
      } else if (c == '$' && lexer->pos + 1 < lexer->length &&
                 lexer->source[lexer->pos + 1] == '{') {
        depth++;
        advance(lexer);
        advance(lexer);
      } else {
        advance(lexer);
      }
    } else {
      // Inside interpolation - stick to raw code scanning (ignore escapes for
      // now, just track brackets) But we MUST handle strings/chars to not get
      // confused by } inside them
      if (c == '{') {
        depth++;
        advance(lexer);
      } else if (c == '}') {
        depth--;
        advance(lexer);
      } else if (c == '"') {
        advance(lexer);
        while (peek(lexer) != '\0' && peek(lexer) != '"') {
          if (peek(lexer) == '\\')
            advance(lexer);
          advance(lexer);
        }
        if (peek(lexer) == '"')
          advance(lexer);
      } else if (c == '\'') {
        advance(lexer);
        while (peek(lexer) != '\0' && peek(lexer) != '\'') {
          if (peek(lexer) == '\\')
            advance(lexer);
          advance(lexer);
        }
        if (peek(lexer) == '\'')
          advance(lexer);
      } else {
        advance(lexer);
      }
    }
  }

  size_t end = lexer->pos;
  lexer->pos = start;

  // Pass 2: Extract value
  char *value = malloc(end - start + 1);
  int idx = 0;
  depth = 0; // Reset depth for second pass

  while (lexer->pos < end) {
    if (depth > 0) {
      // Inside interpolation: Copy RAW characters
      char c = peek(lexer);

      // Track nesting for mode switching, but inside strings/chars just copy
      // blindly We need to mirror the logic of Pass 1 to stay in sync
      if (c == '{') {
        depth++;
        value[idx++] = c;
        advance(lexer);
      } else if (c == '}') {
        depth--;
        value[idx++] = c;
        advance(lexer);
      } else if (c == '"') {
        value[idx++] = c;
        advance(lexer);
        while (lexer->pos < end && peek(lexer) != '"') {
          value[idx++] = peek(lexer);
          advance(lexer);
        }
        if (lexer->pos < end && peek(lexer) == '"') {
          value[idx++] = peek(lexer);
          advance(lexer);
        }
      } else if (c == '\'') {
        value[idx++] = c;
        advance(lexer);
        while (lexer->pos < end && peek(lexer) != '\'') {
          value[idx++] = peek(lexer);
          advance(lexer);
        }
        if (lexer->pos < end && peek(lexer) == '\'') {
          value[idx++] = peek(lexer);
          advance(lexer);
        }
      } else {
        value[idx++] = c;
        advance(lexer);
      }
    } else {
      // Outside interpolation: Handle Unescaping
      char c = peek(lexer);
      if (c == '$' && lexer->pos + 1 < end &&
          lexer->source[lexer->pos + 1] == '{') {
        depth++;
        value[idx++] = '$';
        value[idx++] = '{';
        advance(lexer);
        advance(lexer);
      } else if (c == '\\') {
        advance(lexer);
        // Only unescape if we are NOT at the boundary of a ${
        // Actually, normal escapes
        char esc = peek(lexer);
        switch (esc) {
        case 'n':
          value[idx++] = '\n';
          break;
        case 't':
          value[idx++] = '\t';
          break;
        case 'r':
          value[idx++] = '\r';
          break;
        case '\\':
          value[idx++] = '\\';
          break;
        case '"':
          value[idx++] = '"';
          break;
        case '\'':
          value[idx++] = '\'';
          break;
        case '0':
          value[idx++] = '\0';
          break;
        default:
          value[idx++] = esc;
          break;
        }
        advance(lexer);
      } else {
        value[idx++] = c;
        advance(lexer);
      }
    }
  }
  value[idx] = '\0';

  if (peek(lexer) == '"')
    advance(lexer);

  return make_token(TOK_STRING_LIT, value, start_line, start_col);
}

static Token scan_char(Lexer *lexer) {
  int start_line = lexer->line, start_col = lexer->col;
  advance(lexer); // consume '
  size_t start = lexer->pos;
  if (peek(lexer) == '\\')
    advance(lexer); // escape
  advance(lexer);   // the char
  char *value = substring(lexer->source, start, lexer->pos);
  if (peek(lexer) == '\'')
    advance(lexer);
  return make_token(TOK_CHAR_LIT, value, start_line, start_col);
}

Token lexer_next(Lexer *lexer) {
  skip_whitespace(lexer);
  if (lexer->pos >= lexer->length)
    return make_token(TOK_EOF, NULL, lexer->line, lexer->col);

  int sl = lexer->line, sc = lexer->col;
  char c = peek(lexer);

  if (isalpha(c) || c == '_')
    return scan_identifier(lexer);
  if (isdigit(c))
    return scan_number(lexer);
  if (c == '"')
    return scan_string(lexer);
  if (c == '\'')
    return scan_char(lexer);

  advance(lexer);
  switch (c) {
  case '(':
    return make_token(TOK_LPAREN, strdup("("), sl, sc);
  case ')':
    return make_token(TOK_RPAREN, strdup(")"), sl, sc);
  case '{':
    return make_token(TOK_LBRACE, strdup("{"), sl, sc);
  case '}':
    return make_token(TOK_RBRACE, strdup("}"), sl, sc);
  case '[':
    return make_token(TOK_LBRACKET, strdup("["), sl, sc);
  case ']':
    return make_token(TOK_RBRACKET, strdup("]"), sl, sc);
  case ';':
    return make_token(TOK_SEMICOLON, strdup(";"), sl, sc);
  case ',':
    return make_token(TOK_COMMA, strdup(","), sl, sc);
  case '.':
    if (peek(lexer) == '.' && peek_next(lexer) == '.') {
      advance(lexer);
      advance(lexer);
      return make_token(TOK_ELLIPSIS, strdup("..."), sl, sc);
    }
    return make_token(TOK_DOT, strdup("."), sl, sc);
  case ':':
    return make_token(TOK_COLON, strdup(":"), sl, sc);
  case '+':
    if (peek(lexer) == '+') {
      advance(lexer);
      return make_token(TOK_INC, strdup("++"), sl, sc);
    }
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_PLUS_ASSIGN, strdup("+="), sl, sc);
    }
    return make_token(TOK_PLUS, strdup("+"), sl, sc);
  case '-':
    if (peek(lexer) == '-') {
      advance(lexer);
      return make_token(TOK_DEC, strdup("--"), sl, sc);
    }
    if (peek(lexer) == '>') {
      advance(lexer);
      return make_token(TOK_ARROW_RIGHT, strdup("->"), sl, sc);
    }
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_MINUS_ASSIGN, strdup("-="), sl, sc);
    }
    return make_token(TOK_MINUS, strdup("-"), sl, sc);
  case '*':
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_STAR_ASSIGN, strdup("*="), sl, sc);
    }
    return make_token(TOK_STAR, strdup("*"), sl, sc);
  case '/':
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_SLASH_ASSIGN, strdup("/="), sl, sc);
    }
    return make_token(TOK_SLASH, strdup("/"), sl, sc);
  case '%':
    return make_token(TOK_PERCENT, strdup("%"), sl, sc);
  case '~':
    return make_token(TOK_TILDE, strdup("~"), sl, sc);
  case '^':
    return make_token(TOK_CARET, strdup("^"), sl, sc);
  case '?':
    return make_token(TOK_QUESTION, strdup("?"), sl, sc);
  case '=':
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_EQEQ, strdup("=="), sl, sc);
    }
    if (peek(lexer) == '>') {
      advance(lexer);
      return make_token(TOK_ARROW, strdup("=>"), sl, sc);
    }
    return make_token(TOK_EQ, strdup("="), sl, sc);
  case '!':
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_NEQ, strdup("!="), sl, sc);
    }
    return make_token(TOK_NOT, strdup("!"), sl, sc);
  case '<':
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_LTE, strdup("<="), sl, sc);
    }
    return make_token(TOK_LT, strdup("<"), sl, sc);
  case '>':
    if (peek(lexer) == '=') {
      advance(lexer);
      return make_token(TOK_GTE, strdup(">="), sl, sc);
    }
    return make_token(TOK_GT, strdup(">"), sl, sc);
  case '&':
    if (peek(lexer) == '&') {
      advance(lexer);
      return make_token(TOK_AND, strdup("&&"), sl, sc);
    }
    return make_token(TOK_AMPERSAND, strdup("&"), sl, sc);
  case '|':
    if (peek(lexer) == '|') {
      advance(lexer);
      return make_token(TOK_OR, strdup("||"), sl, sc);
    }
    return make_token(TOK_PIPE, strdup("|"), sl, sc);
  }
  char *err = malloc(2);
  err[0] = c;
  err[1] = '\0';
  return make_token(TOK_ERROR, err, sl, sc);
}

Token lexer_peek(Lexer *lexer) {
  size_t old_pos = lexer->pos;
  int old_line = lexer->line;
  int old_col = lexer->col;
  Token tok = lexer_next(lexer);
  lexer->pos = old_pos;
  lexer->line = old_line;
  lexer->col = old_col;
  return tok;
}

const char *token_type_name(TokenType type) {
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
  case TOK_STRUCT:
    return "struct";
  case TOK_IMPL:
    return "impl";
  case TOK_DICT:
    return "dict";
  case TOK_SET:
    return "set";
  case TOK_RETURN:
    return "return";
  case TOK_IF:
    return "if";
  case TOK_ELSE:
    return "else";
  case TOK_WHILE:
    return "while";
  case TOK_FOR:
    return "for";
  case TOK_TRUE:
    return "true";
  case TOK_FALSE:
    return "false";
  case TOK_SIZEOF:
    return "sizeof";
  case TOK_INT_LIT:
    return "INT_LIT";
  case TOK_FLOAT_LIT:
    return "FLOAT_LIT";
  case TOK_STRING_LIT:
    return "STRING_LIT";
  case TOK_CHAR_LIT:
    return "CHAR_LIT";
  case TOK_IDENT:
    return "IDENT";
  case TOK_PLUS:
    return "+";
  case TOK_MINUS:
    return "-";
  case TOK_STAR:
    return "*";
  case TOK_SLASH:
    return "/";
  case TOK_PERCENT:
    return "%";
  case TOK_EQ:
    return "=";
  case TOK_EQEQ:
    return "==";
  case TOK_NEQ:
    return "!=";
  case TOK_LT:
    return "<";
  case TOK_GT:
    return ">";
  case TOK_LTE:
    return "<=";
  case TOK_GTE:
    return ">=";
  case TOK_AND:
    return "&&";
  case TOK_OR:
    return "||";
  case TOK_NOT:
    return "!";
  case TOK_AMPERSAND:
    return "&";
  case TOK_PIPE:
    return "|";
  case TOK_CARET:
    return "^";
  case TOK_TILDE:
    return "~";
  case TOK_LPAREN:
    return "(";
  case TOK_RPAREN:
    return ")";
  case TOK_LBRACE:
    return "{";
  case TOK_RBRACE:
    return "}";
  case TOK_LBRACKET:
    return "[";
  case TOK_RBRACKET:
    return "]";
  case TOK_SEMICOLON:
    return ";";
  case TOK_COMMA:
    return ",";
  case TOK_DOT:
    return ".";
  case TOK_COLON:
    return ":";
  case TOK_ARROW_RIGHT:
    return "->";
  case TOK_EOF:
    return "EOF";
  case TOK_ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}
