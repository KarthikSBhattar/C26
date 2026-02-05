/*
 * C26 Compiler - Main Entry Point
 * Usage: c26c <input.c26> [-o output]
 */

#include "codegen.h"
#include "lexer.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
  FILE *file = fopen(path, "r");
  if (!file) {
    fprintf(stderr, "Error: Could not open file '%s'\n", path);
    return NULL;
  }
  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *buffer = malloc(length + 1);
  if (!buffer) {
    fclose(file);
    return NULL;
  }
  size_t bytes_read = fread(buffer, 1, length, file);
  buffer[bytes_read] = '\0';
  fclose(file);
  return buffer;
}

static char *get_basename(const char *path) {
  const char *base = strrchr(path, '/');
  if (base)
    base++;
  else
    base = path;
  char *name = strdup(base);
  char *dot = strrchr(name, '.');
  if (dot)
    *dot = '\0';
  return name;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("C26 Compiler - C for the 21st Century (2026)\n");
    printf("Usage: c26c <input.c26> [-o output] [--emit-ir] [--ast]\n");
    return 1;
  }

  const char *input_file = NULL;
  const char *output_file = NULL;
  int emit_ir = 0;
  int show_ast = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--ast") == 0)
      show_ast = 1;
    else if (strcmp(argv[i], "--emit-ir") == 0)
      emit_ir = 1;
    else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
      output_file = argv[++i];
    else if (argv[i][0] != '-')
      input_file = argv[i];
  }

  if (!input_file) {
    fprintf(stderr, "No input file\n");
    return 1;
  }

  char *source = read_file(input_file);
  if (!source)
    return 1;

  // Parse
  Lexer *lexer = lexer_init(source);
  Parser *parser = parser_init(lexer);
  parser->current_file = strdup(input_file);
  ASTNode *ast = parse(parser);

  if (parser->had_error) {
    fprintf(stderr, "Compilation failed\n");
    ast_free(ast);
    parser_free(parser);
    lexer_free(lexer);
    free(source);
    return 1;
  }

  if (show_ast) {
    ast_print(ast, 0);
    ast_free(ast);
    parser_free(parser);
    lexer_free(lexer);
    free(source);
    return 0;
  }

  // Generate code
  char *module_name = get_basename(input_file);
  CodeGen *codegen = codegen_init(module_name);
  codegen_generate(codegen, ast);

  if (emit_ir) {
    if (output_file) {
      codegen_write_ir(codegen, output_file);
      printf("Wrote IR to: %s\n", output_file);
    } else {
      codegen_dump_ir(codegen);
    }
  } else {
    // Compile to object file, then link
    char obj_file[256];
    char *out = output_file ? strdup(output_file) : module_name;
    snprintf(obj_file, sizeof(obj_file), "%s.o", out);

    if (codegen_compile_object(codegen, obj_file) == 0) {
      // Link with system linker
      char link_cmd[512];
      snprintf(link_cmd, sizeof(link_cmd),
               "ld %s -o %s -lSystem -L/opt/homebrew/opt/bdw-gc/lib -lgc "
               "-syslibroot `xcrun --sdk macosx "
               "--show-sdk-path` -e _main -arch arm64",
               obj_file, out);
      int result = system(link_cmd);

      if (result == 0) {
        printf("Compiled: %s\n", out);
        remove(obj_file); // Clean up object file
      } else {
        fprintf(stderr, "Linking failed\n");
      }
    }

    if (output_file)
      free(out);
  }

  free(module_name);
  codegen_free(codegen);
  ast_free(ast);
  parser_free(parser);
  lexer_free(lexer);
  free(source);

  return 0;
}
