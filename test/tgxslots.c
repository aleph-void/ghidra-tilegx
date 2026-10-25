/* Decode every 8-byte bundle of a raw little-endian file with GNU libopcodes' TILE-Gx decoder
 * (parse_insn_tilegx) and print every slot, padding nops included:
 *   tgxslots <file> [-l <address-list> -b <base-vma>]
 * Output: "<offset-hex> <slot> ; <slot> [; <slot>]" where a slot is "<mnemonic> <op>, <op>" in
 * objdump's operand syntax, or "<invalid>". With -l, <file> is an image loaded at <base-vma> and
 * one bundle is decoded at each listed address (hex, first field of each line).
 * Build: see run-tests.sh (links binutils' libopcodes.a/libbfd.a; test-only, not distributed). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opcode/tilegx.h"

static void slot(const struct tilegx_decoded_instruction *d) {
  const struct tilegx_opcode *op = d->opcode;
  if (op == NULL || op->name == NULL) { printf("<invalid>"); return; }
  printf("%s", op->name);
  for (int j = 0; j < op->num_operands; j++) {
    long long num = d->operand_values[j];
    printf(j ? ", " : " ");
    switch (d->operands[j]->type) {
    case TILEGX_OP_TYPE_REGISTER: printf("%s", tilegx_register_names[(int) num]); break;
    case TILEGX_OP_TYPE_SPR: {
      const char *n = get_tilegx_spr_name((int) num);
      if (n) printf("%s", n); else printf("%d", (int) num);
      break;
    }
    case TILEGX_OP_TYPE_IMMEDIATE: printf("%d", (int) num); break;
    case TILEGX_OP_TYPE_ADDRESS: printf("0x%llx", (unsigned long long) num); break;
    default: printf("?");
    }
  }
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: tgxslots <file> [-l list -b base]\n"); return 2; }
  const char *lst = NULL; unsigned long long base = 0;
  for (int i = 2; i + 1 < argc; i += 2) {
    if (!strcmp(argv[i], "-l")) lst = argv[i + 1];
    else if (!strcmp(argv[i], "-b")) base = strtoull(argv[i + 1], NULL, 16);
  }
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror(argv[1]); return 2; }
  fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
  unsigned char *data = malloc(sz);
  if (fread(data, 1, sz, f) != (size_t) sz) return 2;
  fclose(f);
  FILE *lf = lst ? fopen(lst, "r") : NULL;
  char line[1024];
  for (long off = 0;; off += 8) {
    unsigned long long vma = off;
    if (lf) {
      if (!fgets(line, sizeof line, lf)) break;
      vma = strtoull(line, NULL, 16);
      off = (long) (vma - base);
      if (off < 0 || off + 8 > sz) continue;
    } else if (off + 8 > sz) break;
    unsigned long long w = 0;
    for (int b = 7; b >= 0; b--) w = (w << 8) | data[off + b];
    struct tilegx_decoded_instruction d[TILEGX_MAX_INSTRUCTIONS_PER_BUNDLE];
    int n = parse_insn_tilegx(w, vma, d);
    printf("%08llx ", vma);
    for (int i = 0; i < n; i++) { if (i) printf(" ; "); slot(&d[i]); }
    printf("\n");
  }
  return 0;
}
