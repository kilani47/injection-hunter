# The Seiyaku Arc, Flask portal image.
# Note: system build deps below cover python-ldap (libldap2-dev/libsasl2-dev)
# and lxml (libxml2-dev/libxslt1-dev) even though no challenge route uses
# them yet in this scaffold task; later phases add the routes, not the
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

# Task 5.4 "The King's Sealed Archives": a real file, outside the app's own
# source tree, readable only by an XXE external-entity file-read reaching
# outside the document the app itself ever intended to parse, never by any
# in-app route directly. Mirrors the notes' file:///etc/passwd example, but
# with a path the app controls so the flag content is deterministic.
#
# Deliberately placed under a real OS account's home directory rather than
# an app-specific path like /opt/<name>: /etc/passwd lists every account on
# the box and the home directory each one resolves to, so a file read that
# already proved itself against /etc/passwd tells a reader exactly where to
# look next, with no app layout or container-tooling knowledge assumed.
RUN useradd -r -m -d /home/king -s /usr/sbin/nologin king && \
    printf 'SEIYAKU{external_entity_unsealed}\n' > /home/king/flag.txt && \
    chmod 444 /home/king/flag.txt

# Task 5.5 "The Silent Courier": flag file for OOB XXE exfil. No trailing
# newline: the exfil chain embeds file content directly into a URI query
# parameter, and a trailing newline would appear as %0A in the capture.
RUN mkdir -p /opt/king && \
    printf 'SEIYAKU{entity_phoned_home}' > /opt/king/dispatch.txt && \
    chmod 444 /opt/king/dispatch.txt

# Task F.2 "Chairman Election Infiltration": the Document Import faction's
# fragment of the Chairman seat's key, sealed outside the app's own source
# tree exactly like /opt/king/flag.txt above, reachable only via a genuine
# XXE external-entity file read against the Document Import route.
RUN mkdir -p /opt/omnigrid && \
    printf 'CHAIR-D0CX7Q-9a3f\n' > /opt/omnigrid/fragment.txt && \
    chmod 444 /opt/omnigrid/fragment.txt

EXPOSE 8000

CMD ["python", "app.py"]
