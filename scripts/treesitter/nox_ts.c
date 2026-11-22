// nox_ts.c -- the guest side of nox's tree-sitter boundary (ADR 0006).
//
// One module per grammar: the official tree-sitter runtime, one or more
// languages, and these exports. The host calls nox_parse once per file and
// reads the whole tree back as a flat array of records: no per-node call
// crosses the boundary (ADR 0006, rule 2).
//
// Record layout, one per node in pre-order, NOX_RECORD_WORDS little-endian
// uint32 words:
//
//   0 symbol   the node's symbol (an alias's, when the grammar aliases it);
//              its name is nox_symbol_name(lang, symbol)
//   1 field    the field this node fills in its parent, 0 for none; its name
//              is nox_field_name(lang, field)
//   2 start    first byte of the node in the source
//   3 end      one past its last byte
//   4 parent   the parent's record index; the root's is 0xFFFFFFFF
//   5 flags    NOX_NAMED | NOX_MISSING | NOX_EXTRA | NOX_ERROR | NOX_HAS_ERROR
//
// Pre-order means a node's children follow it, in source order, and a
// record's parent always comes earlier in the array.
//
// The module imports nothing a parse needs: no clock, no file, no network.
// The tree-sitter timeout and logging, the only runtime features that would,
// are never set.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tree_sitter/api.h>

#define NOX_ABI 1
#define NOX_RECORD_WORDS 6

#define NOX_NAMED 1u
#define NOX_MISSING 2u
#define NOX_EXTRA 4u
#define NOX_ERROR 8u
#define NOX_HAS_ERROR 16u

// NOX_LANGUAGES expands X(name, function) once per language in this module;
// the build defines it (for example X("typescript", tree_sitter_typescript)
// X("tsx", tree_sitter_tsx)).
#define X(name, fn) const TSLanguage *fn(void);
NOX_LANGUAGES
#undef X

static const char *const lang_names[] = {
#define X(name, fn) name,
    NOX_LANGUAGES
#undef X
};

static const TSLanguage *(*const lang_fns[])(void) = {
#define X(name, fn) fn,
    NOX_LANGUAGES
#undef X
};

#define LANG_COUNT (sizeof(lang_names) / sizeof(lang_names[0]))

static uint32_t *records;
static uint32_t record_cap; // in records

#define EXPORT(name) __attribute__((export_name(#name)))

EXPORT(nox_abi) uint32_t nox_abi(void) { return NOX_ABI; }
EXPORT(nox_record_words) uint32_t nox_record_words(void) { return NOX_RECORD_WORDS; }

EXPORT(nox_alloc) void *nox_alloc(uint32_t size) { return malloc(size); }
EXPORT(nox_free) void nox_free(void *p) { free(p); }

EXPORT(nox_lang_count) uint32_t nox_lang_count(void) { return LANG_COUNT; }

EXPORT(nox_lang_name) const char *nox_lang_name(uint32_t lang) {
  return lang < LANG_COUNT ? lang_names[lang] : 0;
}

static const TSLanguage *language(uint32_t lang) {
  return lang < LANG_COUNT ? lang_fns[lang]() : 0;
}

EXPORT(nox_symbol_count) uint32_t nox_symbol_count(uint32_t lang) {
  const TSLanguage *l = language(lang);
  return l ? ts_language_symbol_count(l) : 0;
}

EXPORT(nox_symbol_name) const char *nox_symbol_name(uint32_t lang, uint32_t symbol) {
  const TSLanguage *l = language(lang);
  return l && symbol < ts_language_symbol_count(l) ? ts_language_symbol_name(l, (TSSymbol)symbol) : 0;
}

EXPORT(nox_symbol_named) uint32_t nox_symbol_named(uint32_t lang, uint32_t symbol) {
  const TSLanguage *l = language(lang);
  return l && symbol < ts_language_symbol_count(l) &&
         ts_language_symbol_type(l, (TSSymbol)symbol) == TSSymbolTypeRegular;
}

EXPORT(nox_field_count) uint32_t nox_field_count(uint32_t lang) {
  const TSLanguage *l = language(lang);
  return l ? ts_language_field_count(l) : 0;
}

EXPORT(nox_field_name) const char *nox_field_name(uint32_t lang, uint32_t field) {
  const TSLanguage *l = language(lang);
  return l && field >= 1 && field <= ts_language_field_count(l) ? ts_language_field_name_for_id(l, (TSFieldId)field) : 0;
}

// nox_result is the record array of the last successful nox_parse.
EXPORT(nox_result) uint32_t *nox_result(void) { return records; }

static int grow(uint32_t need) {
  if (need <= record_cap) {
    return 1;
  }
  uint32_t cap = record_cap ? record_cap : 1024;
  while (cap < need) {
    if (cap > UINT32_MAX / 2) {
      return 0;
    }
    cap *= 2;
  }
  uint32_t *r = realloc(records, (size_t)cap * NOX_RECORD_WORDS * sizeof(uint32_t));
  if (!r) {
    return 0;
  }
  records = r;
  record_cap = cap;
  return 1;
}

// Errors nox_parse returns, as negative counts.
#define NOX_E_LANGUAGE -1 // no such language, or the runtime rejects its ABI
#define NOX_E_PARSE -2    // the parser returned no tree
#define NOX_E_MEMORY -3   // the record array could not grow

// nox_parse parses len bytes at src as language lang and returns the number
// of records written to nox_result(), or a negative NOX_E_* code.
EXPORT(nox_parse) int32_t nox_parse(uint32_t lang, const char *src, uint32_t len) {
  const TSLanguage *l = language(lang);
  if (!l) {
    return NOX_E_LANGUAGE;
  }
  TSParser *parser = ts_parser_new();
  if (!ts_parser_set_language(parser, l)) {
    ts_parser_delete(parser);
    return NOX_E_LANGUAGE;
  }
  TSTree *tree = ts_parser_parse_string(parser, 0, src, len);
  ts_parser_delete(parser);
  if (!tree) {
    return NOX_E_PARSE;
  }

  TSTreeCursor cursor = ts_tree_cursor_new(ts_tree_root_node(tree));
  // stack[d] is the record index of the node at depth d on the current path.
  uint32_t stack_cap = 256, depth = 0, n = 0;
  uint32_t *stack = malloc(stack_cap * sizeof(uint32_t));
  int32_t result = stack ? 0 : NOX_E_MEMORY;

  while (result == 0) {
    if (!grow(n + 1)) {
      result = NOX_E_MEMORY;
      break;
    }
    TSNode node = ts_tree_cursor_current_node(&cursor);
    uint32_t *r = records + (size_t)n * NOX_RECORD_WORDS;
    uint32_t flags = 0;
    if (ts_node_is_named(node)) flags |= NOX_NAMED;
    if (ts_node_is_missing(node)) flags |= NOX_MISSING;
    if (ts_node_is_extra(node)) flags |= NOX_EXTRA;
    if (ts_node_is_error(node)) flags |= NOX_ERROR;
    if (ts_node_has_error(node)) flags |= NOX_HAS_ERROR;
    r[0] = ts_node_symbol(node);
    r[1] = ts_tree_cursor_current_field_id(&cursor);
    r[2] = ts_node_start_byte(node);
    r[3] = ts_node_end_byte(node);
    r[4] = depth ? stack[depth - 1] : 0xFFFFFFFFu;
    r[5] = flags;

    if (ts_tree_cursor_goto_first_child(&cursor)) {
      if (depth + 1 >= stack_cap) {
        uint32_t *s = realloc(stack, stack_cap * 2 * sizeof(uint32_t));
        if (!s) {
          result = NOX_E_MEMORY;
          break;
        }
        stack = s;
        stack_cap *= 2;
      }
      stack[depth++] = n++;
      continue;
    }
    n++;
    // No child: the next sibling, or up until an ancestor has one.
    for (;;) {
      if (ts_tree_cursor_goto_next_sibling(&cursor)) {
        break;
      }
      if (!ts_tree_cursor_goto_parent(&cursor)) {
        result = 1; // back at the root: done
        break;
      }
      depth--;
    }
  }

  free(stack);
  ts_tree_cursor_delete(&cursor);
  ts_tree_delete(tree);
  return result < 0 ? result : (int32_t)n;
}
