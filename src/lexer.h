/*
 * C26 Compiler - Lexer
 * Tokenizes .c26 source files
 */

#ifndef LEXER_H
#define LEXER_H

#include <stddef.h>

typedef enum {
  // Primitive Type Keywords - Signed Integers
  TOK_I8,
  TOK_I16,
  TOK_I32,
  TOK_I64,
  TOK_I128,
  TOK_ISIZE,
  // Unsigned Integers
  TOK_U8,
  TOK_U16,
  TOK_U32,
  TOK_U64,
  TOK_U128,
  TOK_USIZE,
  // Floating Point
  TOK_F32,
  TOK_F64,
  // Other Primitives
  TOK_BOOL,
  TOK_CHAR,
  TOK_STR,
  TOK_VOID,
  TOK_STRUCT,
  TOK_IMPL,
  TOK_CONST,
  // Function Modifiers & Directives
  TOK_INLINE,
  TOK_INCLUDE,
  TOK_LOCAL,
  // Generic Collection Types
  TOK_DICT,
  TOK_SET,
  TOK_AS,

  // Control Flow Keywords
  TOK_RETURN,
  TOK_IF,
  TOK_ELSE,
  TOK_WHILE,
  TOK_DO,
  TOK_FOR,
  TOK_TRUE,
  TOK_FALSE,
  TOK_NULL,
  TOK_TYPEOF,
  TOK_AUTO,
  TOK_BREAK,
  TOK_MATCH,
  TOK_ARROW,      // =>
  TOK_UNDERSCORE, // _ for default match
  TOK_ELLIPSIS,   // ... for array destructuring

  // Literals
  TOK_INT_LIT,
  TOK_FLOAT_LIT,
  TOK_STRING_LIT,
  TOK_CHAR_LIT,

  // Identifiers
  TOK_IDENT,

  // Operators
  TOK_INC, // ++
  TOK_DEC, // --
  TOK_PLUS,
  TOK_MINUS,
  TOK_STAR,
  TOK_SLASH,
  TOK_PERCENT,
  TOK_PLUS_ASSIGN,
  TOK_MINUS_ASSIGN,
  TOK_STAR_ASSIGN,
  TOK_SLASH_ASSIGN,
  TOK_EQ,
  TOK_EQEQ,
  TOK_NEQ,
  TOK_LT,
  TOK_GT,
  TOK_LTE,
  TOK_GTE,
  TOK_AND,
  TOK_OR,
  TOK_NOT,
  TOK_AMPERSAND,
  TOK_PIPE,
  TOK_CARET,
  TOK_TILDE,
  TOK_QUESTION,

  // Punctuation
  TOK_LPAREN,
  TOK_RPAREN,
  TOK_LBRACE,
  TOK_RBRACE,
  TOK_LBRACKET,
  TOK_RBRACKET,
  TOK_SEMICOLON,
  TOK_COMMA,
  TOK_DOT,
  TOK_COLON,
  TOK_ARROW_RIGHT,

  TOK_SIZEOF,

  // Special
  TOK_EOF,
  TOK_ERROR
} TokenType;

typedef struct {
  TokenType type;
  char *value;
  int line;
  int col;
} Token;

typedef struct {
  char *source;
  size_t length;
  size_t pos;
  int line;
  int col;
} Lexer;

Lexer *lexer_init(char *source);
void lexer_free(Lexer *lexer);
Token lexer_next(Lexer *lexer);
void token_free(Token *token);
const char *token_type_name(TokenType type);
Token lexer_peek(Lexer *lexer);

#endif // LEXER_H
