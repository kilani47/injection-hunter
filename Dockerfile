# The Seiyaku Arc — Flask portal image.
# Note: system build deps below cover python-ldap (libldap2-dev/libsasl2-dev)
# and lxml (libxml2-dev/libxslt1-dev) even though no challenge route uses
# them yet in this scaffold task — later phases add the routes, not the
# image plumbing, so this Dockerfile shouldn't need touching again for that.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libldap2-dev \
        libsasl2-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "app.py"]
