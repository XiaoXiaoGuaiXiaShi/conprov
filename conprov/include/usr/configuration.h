#ifndef _CONFIGURATION_H_   
#define _CONFIGURATION_H_

typedef struct
{
    char log_path[1024];
} configuration;

void read_config(void);

#endif
