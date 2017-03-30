#include <stdlib.h>
#include <stdio.h>
#include "libadd.h"

int add(int a, int b) {
  printf("%d + %d = %d\n", a, b, a+b);
  return a + b;
}

