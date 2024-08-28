#include <syslog.h>
#include <time.h>
#include <ini.h>

#include "usr/configuration.h"

#define CONFIG_PATH "./conprov.ini"

configuration __config;

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)

/* call back for configuation */
static int handler(void *user, const char *section, const char *name,
                   const char *value)
{
    configuration *pconfig = (configuration *)user;

    time_t now;
    struct tm *local;

    if (MATCH("log", "path"))
    {
        time(&now);
        local = localtime(&now);
        snprintf(pconfig->log_path, 1024,
                 "%sconprov-%02d_%02d-%02d-%02d.log",
                 value,
                 local->tm_mday,
                 local->tm_hour,
                 local->tm_min,
                 local->tm_sec);
    }
    else
    {
        return 0; /* unknown section/name error */
    }
    return 1;
}

void read_config(void)
{
    memset(&__config, 0, sizeof(configuration));
    if (ini_parse(CONFIG_PATH, handler, &__config) < 0)
    {
        syslog(LOG_ERR, "ConProv: Can't load configuration: %s.", CONFIG_PATH);
        exit(-1);
    }
}