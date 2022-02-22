#include "bre_utils.h"

int64_t bre_atoi(const char *str, size_t len) {
  while (len > 0 && *str > '\0' && *str <= ' ') {
    str++;
    len--;
  }
  if (len == 0) {
    return 0;
  }
  int sign = 1;
  int64_t num = 0;
  if (*str == '-') {
    str++;
    len--;
    sign = -1;
  } else if (*str == '+') {
    str++;
    len--;
  }
  while (len > 0 && *str != '\0') {
    if ((*str < '0') || (*str > '9')) {
      break;
    }
    num = num * 10 + *str - '0';
    str++;
    len--;
  }
  return num * sign;
}
