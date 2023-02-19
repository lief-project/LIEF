#include <stdio.h>
#include <stdlib.h>

#include "libadd.h"

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <a> <b>\n", argv[0]);
    exit(-1);
  }

  int res = add(atoi(argv[1]), atoi(argv[2]));
  printf("From myLIb, a + b = %d\n", res);
  return 0;
}

