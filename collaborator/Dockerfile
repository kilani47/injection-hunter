# The Seiyaku Arc, OOB collaborator service.
# Stdlib only (see collaborator.py), no requirements.txt needed here.
FROM python:3.12-slim

WORKDIR /app
COPY collaborator.py .

# HTTP capture + /captures API on 80/tcp, DNS capture on 53/udp. Both are
# privileged (<1024) ports, which is why this runs as root (the image's
# default) rather than dropping to an unprivileged user; acceptable for a
# lab-only service that never leaves the internal compose network.
EXPOSE 80/tcp
EXPOSE 53/udp

CMD ["python3", "collaborator.py"]
