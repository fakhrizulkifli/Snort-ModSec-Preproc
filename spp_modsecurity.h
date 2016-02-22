#ifndef SPP_MODSECURITY_H
#define SPP_MODSECURITY_H

#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#define MAX_PORTS 65536
extern DynamicPreprocessorData _dpd;

/* NOTE: Snort can't strip ssl */
#define MODSECURITY_PORT 80

/* Preprocessor configuration */
typedef struct _modsecurity_config
{
    int ports;
} modsecurity_config_t;

#define MODSECURITY_SUCCESS 1
#define MODSECURITY_FAILURE (-1)

#endif
