#include "legacy.h"
void release(void *value) {
  if (value != NULL) {
    free(value);
  }
}
