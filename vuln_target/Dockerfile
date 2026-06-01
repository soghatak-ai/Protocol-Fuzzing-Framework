FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y gcc make iproute2 iputils-ping tcpdump ttyd && \
    rm -rf /var/lib/apt/lists/*

COPY vuln_ids.c /opt/vuln_ids.c

# Compile WITHOUT stack protections to make vulns exploitable
RUN gcc -o /opt/vuln_ids /opt/vuln_ids.c -lpthread \
    -fno-stack-protector \
    -z execstack \
    -D_FORTIFY_SOURCE=0 \
    -no-pie \
    -Wno-format-security

EXPOSE 53/udp 5353/tcp 21/tcp 7683

# Run once — no auto-restart. User must manually restart via web terminal.
# stdbuf disables output buffering so logs appear immediately before a crash.
CMD bash -c "stdbuf -oL /opt/vuln_ids > /var/log/vuln_ids.log 2>&1 & ttyd -p 7683 bash"
