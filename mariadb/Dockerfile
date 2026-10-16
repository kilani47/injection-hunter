# mariadb/Dockerfile, custom MariaDB image with the http_get UDF compiled in.
#
# Build context: repository root (docker-compose.yml sets context: .).
# That lets COPY reach udf/http_get.c without any ../.. gymnastics.
#
# What this adds over the stock mariadb:11 image:
#   - gcc + MariaDB dev headers to compile the UDF at build time
#   - curl, which the UDF's popen() call uses at runtime
#   - /usr/lib/mysql/plugin/http_get.so (the compiled UDF binary)
#
# The UDF binary is a standalone .so; once gcc and the dev headers have done
# their job they aren't needed at runtime.  curl IS needed at runtime (the
# UDF shells out to it), so it stays.
FROM mariadb:11

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libmariadbd-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY udf/http_get.c /tmp/http_get.c

RUN gcc -shared -fPIC -nostartfiles \
        -I/usr/include/mariadb \
        -o /usr/lib/mysql/plugin/http_get.so \
        /tmp/http_get.c \
    && rm /tmp/http_get.c
