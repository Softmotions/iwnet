#pragma once

#include "brssl.h"

#define ZGO(label__, val__)           \
  ({ __typeof__(val__) v__ = (val__); \
    if (!v__) goto label__;           \
    v__; })


#define ZRET(ret__, val__)            \
  ({ __typeof__(val__) v__ = (val__); \
    if (!v__) return ret__;           \
    v__; })
