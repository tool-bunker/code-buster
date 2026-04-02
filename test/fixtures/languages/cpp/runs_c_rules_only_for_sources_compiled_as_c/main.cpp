#include "widget.hpp"
#include "../shared/api.h"
void release(void *value) {
  free(value);
}
