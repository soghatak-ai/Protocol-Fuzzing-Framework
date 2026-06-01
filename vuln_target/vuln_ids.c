/*
 * vuln_ids.c — Intentionally Vulnerable IDS / Network Service
 *
 * A deliberately buggy network service that:
 *   - Listens on UDP 53 (DNS) and TCP 21 (FTP)
 *   - Parses incoming packets like a simplified IDS
 *   - Contains REAL exploitable vulnerabilities for fuzzer testing
 *
 * VULNERABILITIES PLANTED:
 *   1. Stack buffer overflow in DNS label parsing (no length check)
 *   2. Heap buffer overflow in DNS TXT record handling
 *   3. Integer overflow in EDNS OPT record size calculation
 *   4. Out-of-bounds array read in DNS qtype lookup
 *   5. Format string bug in FTP USER command logging
 *   6. Stack buffer overflow in FTP CWD command
 *   7. Use-after-free in FTP data channel handling
 *   8. Null pointer dereference on malformed DNS compression pointer
 *   9. Off-by-one in FTP SITE command parsing
 *  10. Integer underflow in DNS message length validation
 *
 * Compile: gcc -o vuln_ids vuln_ids.c -lpthread
 * Run:     ./vuln_ids
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNS_PORT      53
#define DNS_TCP_PORT  5353
#define FTP_PORT      21
#define MAX_PKT_SIZE  4096
#define LOG_BUF_SIZE  256

/* ─── Globals ─────────────────────────────────────────────────────── */
volatile int running = 1;
int packets_processed = 0;
int alerts_triggered = 0;

/* Simulated "rule" table for IDS matching */
const char *rule_names[] = {
    "ALLOW",  "DROP",  "ALERT",  "LOG",
    "BLOCK",  "PASS",  "REJECT", "MONITOR"
};
#define NUM_RULES 8

/* ─── VULN #4: OOB array read ────────────────────────────────────── */
const char *qtype_names[] = {
    "A", "NS", "CNAME", "SOA", "MX", "TXT", "AAAA", "SRV"
};
#define NUM_QTYPES 8

const char *lookup_qtype(uint16_t qtype) {
    /* BUG: No bounds check — qtype from network can be anything 0-65535 */
    return qtype_names[qtype];
}

/* ─── DNS Parsing (UDP 53) ───────────────────────────────────────── */

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* VULN #1: Stack buffer overflow in DNS label parsing */
int parse_dns_name(const uint8_t *pkt, int offset, int pkt_len, char *out_name) {
    int pos = offset;
    int name_pos = 0;
    char label_buf[64];  /* BUG: label can be up to 63 bytes, but we don't check total name length */

    while (pos < pkt_len) {
        uint8_t label_len = pkt[pos];
        if (label_len == 0) {
            pos++;
            break;
        }

        /* VULN #8: Null deref on compression pointer — if pointer target is invalid */
        if ((label_len & 0xC0) == 0xC0) {
            uint16_t ptr_offset = ((label_len & 0x3F) << 8) | pkt[pos + 1];
            /* BUG: No validation of ptr_offset — can point anywhere, even past pkt_len */
            if (ptr_offset >= pkt_len) {
                /* Intentionally dereference NULL-ish memory for crash */
                const char *bad_ptr = NULL;
                out_name[name_pos] = *bad_ptr;  /* CRASH: null deref */
            }
            parse_dns_name(pkt, ptr_offset, pkt_len, out_name + name_pos);
            pos += 2;
            return pos;
        }

        pos++;
        /* BUG: No check that label_len + name_pos < out_name buffer size */
        memcpy(label_buf, &pkt[pos], label_len);
        memcpy(out_name + name_pos, label_buf, label_len);
        name_pos += label_len;
        out_name[name_pos++] = '.';
        pos += label_len;
    }

    if (name_pos > 0) name_pos--;
    out_name[name_pos] = '\0';
    return pos;
}

/* VULN #2: Heap buffer overflow in TXT record handling */
void process_txt_record(const uint8_t *rdata, uint16_t rdlength) {
    /* BUG: Allocates based on first byte (txt_len) but copies rdlength bytes */
    uint8_t txt_len = rdata[0];
    char *txt_buf = (char *)malloc(txt_len + 1);
    if (!txt_buf) return;

    /* BUG: Copies rdlength bytes into txt_len-sized buffer → heap overflow */
    memcpy(txt_buf, rdata + 1, rdlength - 1);
    txt_buf[txt_len] = '\0';

    printf("[IDS] TXT record: %s\n", txt_buf);
    free(txt_buf);
}

/* VULN #3: Integer overflow in EDNS OPT record */
void process_edns_opt(const uint8_t *rdata, uint16_t rdlength) {
    if (rdlength < 4) return;

    uint16_t opt_code = (rdata[0] << 8) | rdata[1];
    uint16_t opt_len  = (rdata[2] << 8) | rdata[3];

    /* BUG: opt_len + 4 can overflow uint16_t if opt_len is near 0xFFFF */
    uint16_t total_size = opt_len + 4;
    char *opt_buf = (char *)malloc(total_size);  /* allocates tiny buffer on overflow */
    if (!opt_buf) return;

    /* Copies real data into potentially tiny buffer */
    if (rdlength > 4) {
        memcpy(opt_buf, rdata + 4, rdlength - 4);  /* overflow if total_size wrapped */
    }

    printf("[IDS] EDNS OPT code=%d len=%d\n", opt_code, opt_len);
    free(opt_buf);
}

/* VULN #10: Integer underflow in DNS message length */
void process_dns_packet(const uint8_t *pkt, int pkt_len) {
    packets_processed++;

    /* BUG: If pkt_len < sizeof(dns_header), subtraction underflows */
    int payload_len = pkt_len - sizeof(struct dns_header);
    if (payload_len == 0) return;  /* BUG: Should check payload_len < 0, not == 0 */

    struct dns_header *hdr = (struct dns_header *)pkt;
    uint16_t qdcount = ntohs(hdr->qdcount);
    uint16_t ancount = ntohs(hdr->ancount);
    uint16_t arcount = ntohs(hdr->arcount);

    printf("[IDS] DNS id=0x%04x qd=%d an=%d ar=%d (%d bytes)\n",
           ntohs(hdr->id), qdcount, ancount, arcount, pkt_len);

    /* Parse question section */
    int offset = sizeof(struct dns_header);
    for (int i = 0; i < qdcount && offset < pkt_len; i++) {
        char qname[256];  /* VULN #1 target: stack overflow if name > 256 bytes */
        offset = parse_dns_name(pkt, offset, pkt_len, qname);

        if (offset + 4 > pkt_len) break;
        uint16_t qtype  = (pkt[offset] << 8) | pkt[offset + 1];
        uint16_t qclass = (pkt[offset + 2] << 8) | pkt[offset + 3];
        offset += 4;

        /* VULN #4: OOB read if qtype >= NUM_QTYPES */
        printf("[IDS] Query: %s type=%s class=%d\n", qname, lookup_qtype(qtype), qclass);
    }

    /* Parse answer/additional sections for TXT and OPT records */
    int total_rr = ancount + arcount;
    for (int i = 0; i < total_rr && offset < pkt_len; i++) {
        char rr_name[256];
        offset = parse_dns_name(pkt, offset, pkt_len, rr_name);

        if (offset + 10 > pkt_len) break;
        uint16_t rr_type = (pkt[offset] << 8) | pkt[offset + 1];
        offset += 8;  /* skip type, class, ttl */
        uint16_t rdlength = (pkt[offset] << 8) | pkt[offset + 1];
        offset += 2;

        if (offset + rdlength > pkt_len) break;

        if (rr_type == 16) {        /* TXT */
            process_txt_record(pkt + offset, rdlength);
        } else if (rr_type == 41) { /* OPT / EDNS */
            process_edns_opt(pkt + offset, rdlength);
        }

        offset += rdlength;
    }

    /* Simulated IDS rule matching */
    uint8_t rule_idx = pkt[sizeof(struct dns_header)] % (NUM_RULES + 4);
    /* BUG: rule_idx can be >= NUM_RULES due to +4, causing OOB read */
    if (rule_idx < NUM_RULES + 4) {
        printf("[IDS] Matched rule: %s\n", rule_names[rule_idx]);
        if (rule_idx == 2) {
            alerts_triggered++;
            printf("[ALERT] Suspicious DNS query detected! (alert #%d)\n", alerts_triggered);
        }
    }
}

/* ─── FTP Parsing (TCP 21) ───────────────────────────────────────── */

struct ftp_session {
    int sock;
    char username[64];
    char cwd[512];
    int authenticated;
    char *data_buf;  /* for VULN #7: use-after-free */
    int data_buf_size;
};

/* VULN #5: Format string vulnerability in USER command */
void handle_ftp_user(struct ftp_session *sess, const char *arg) {
    char log_msg[LOG_BUF_SIZE];

    /* BUG: User-controlled arg used directly as format string */
    snprintf(log_msg, sizeof(log_msg), arg);
    printf("[IDS-FTP] Login attempt: %s\n", log_msg);

    strncpy(sess->username, arg, sizeof(sess->username) - 1);
    sess->username[sizeof(sess->username) - 1] = '\0';

    const char *resp = "331 Username OK, need password.\r\n";
    send(sess->sock, resp, strlen(resp), 0);
}

/* VULN #6: Stack buffer overflow in CWD command */
void handle_ftp_cwd(struct ftp_session *sess, const char *arg) {
    char path_buf[128];

    /* BUG: No length check — arg can be thousands of bytes */
    strcpy(path_buf, arg);

    /* Simulate directory traversal check (buggy) */
    if (strstr(path_buf, "..") != NULL) {
        printf("[ALERT] Directory traversal attempt: %s\n", path_buf);
        alerts_triggered++;
        const char *resp = "550 Permission denied.\r\n";
        send(sess->sock, resp, strlen(resp), 0);
        return;
    }

    snprintf(sess->cwd, sizeof(sess->cwd), "%s/%s", sess->cwd, path_buf);
    printf("[IDS-FTP] CWD: %s\n", sess->cwd);

    const char *resp = "250 Directory changed.\r\n";
    send(sess->sock, resp, strlen(resp), 0);
}

/* VULN #7: Use-after-free in data channel */
void handle_ftp_retr(struct ftp_session *sess, const char *arg) {
    /* Allocate data buffer */
    sess->data_buf = (char *)malloc(1024);
    if (!sess->data_buf) return;
    sess->data_buf_size = 1024;
    snprintf(sess->data_buf, 1024, "Contents of %s\n", arg);

    /* Simulate transfer */
    printf("[IDS-FTP] RETR %s (%d bytes)\n", arg, sess->data_buf_size);

    /* BUG: Free the buffer... */
    free(sess->data_buf);
    /* ...but don't NULL the pointer. Next access is use-after-free */
}

void handle_ftp_abor(struct ftp_session *sess) {
    /* VULN #7 trigger: accesses freed data_buf */
    if (sess->data_buf) {
        printf("[IDS-FTP] Aborting transfer, buffer contents: %.20s\n", sess->data_buf);
        /* BUG: data_buf was freed in handle_ftp_retr → use-after-free */
        sess->data_buf_size = 0;
    }
    const char *resp = "226 Abort OK.\r\n";
    send(sess->sock, resp, strlen(resp), 0);
}

/* VULN #9: Off-by-one in SITE command */
void handle_ftp_site(struct ftp_session *sess, const char *arg) {
    char site_cmd[64];
    int len = strlen(arg);

    /* BUG: Off-by-one — should be len < sizeof(site_cmd), not <= */
    if (len <= sizeof(site_cmd)) {
        memcpy(site_cmd, arg, len);
        site_cmd[len] = '\0';  /* writes one byte past buffer if len == 64 */
    }

    printf("[IDS-FTP] SITE command: %s\n", site_cmd);
    const char *resp = "200 SITE command OK.\r\n";
    send(sess->sock, resp, strlen(resp), 0);
}

void handle_ftp_pass(struct ftp_session *sess, const char *arg) {
    sess->authenticated = 1;
    printf("[IDS-FTP] PASS accepted for user: %s\n", sess->username);
    const char *resp = "230 Login successful.\r\n";
    send(sess->sock, resp, strlen(resp), 0);
}

void handle_ftp_client(int client_sock) {
    struct ftp_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.sock = client_sock;
    strcpy(sess.cwd, "/");

    const char *banner = "220 VulnIDS FTP Service Ready.\r\n";
    send(client_sock, banner, strlen(banner), 0);

    char buf[MAX_PKT_SIZE];
    while (running) {
        int n = recv(client_sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        packets_processed++;

        /* Strip trailing \r\n */
        for (int i = n - 1; i >= 0 && (buf[i] == '\r' || buf[i] == '\n'); i--)
            buf[i] = '\0';

        /* Parse FTP command */
        char *cmd = buf;
        char *arg = strchr(buf, ' ');
        if (arg) {
            *arg = '\0';
            arg++;
        } else {
            arg = "";
        }

        /* Convert command to uppercase */
        for (char *p = cmd; *p; p++) {
            if (*p >= 'a' && *p <= 'z') *p -= 32;
        }

        if (strcmp(cmd, "USER") == 0)       handle_ftp_user(&sess, arg);
        else if (strcmp(cmd, "PASS") == 0)  handle_ftp_pass(&sess, arg);
        else if (strcmp(cmd, "CWD") == 0)   handle_ftp_cwd(&sess, arg);
        else if (strcmp(cmd, "RETR") == 0)  handle_ftp_retr(&sess, arg);
        else if (strcmp(cmd, "ABOR") == 0)  handle_ftp_abor(&sess);
        else if (strcmp(cmd, "SITE") == 0)  handle_ftp_site(&sess, arg);
        else if (strcmp(cmd, "QUIT") == 0)  { break; }
        else {
            const char *resp = "502 Command not implemented.\r\n";
            send(client_sock, resp, strlen(resp), 0);
        }
    }

    close(client_sock);
    printf("[IDS-FTP] Client disconnected.\n");
}

/* ─── DNS Server Thread ──────────────────────────────────────────── */
void *dns_server_thread(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("DNS socket"); return NULL; }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DNS_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("DNS bind");
        close(sock);
        return NULL;
    }

    printf("[*] DNS listener started on UDP :%d\n", DNS_PORT);

    uint8_t pkt[MAX_PKT_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len;

    while (running) {
        client_len = sizeof(client_addr);
        int n = recvfrom(sock, pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&client_addr, &client_len);
        if (n <= 0) continue;

        printf("[*] DNS packet from %s:%d (%d bytes)\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), n);

        process_dns_packet(pkt, n);

        /* Send a minimal DNS response (NXDOMAIN) */
        if (n >= 12) {
            pkt[2] = 0x81;  /* flags: response, recursion available */
            pkt[3] = 0x83;  /* NXDOMAIN */
            sendto(sock, pkt, n, 0,
                   (struct sockaddr *)&client_addr, client_len);
        }
    }

    close(sock);
    return NULL;
}

/* ─── DNS-over-TCP Server Thread ─────────────────────────────────── */
void handle_dns_tcp_client(int client_sock) {
    uint8_t buf[MAX_PKT_SIZE];
    while (running) {
        /* DNS-over-TCP: 2-byte length prefix, then DNS message */
        uint8_t len_buf[2];
        int n = recv(client_sock, len_buf, 2, MSG_WAITALL);
        if (n <= 0) break;

        uint16_t msg_len = (len_buf[0] << 8) | len_buf[1];
        if (msg_len > sizeof(buf)) msg_len = sizeof(buf);

        n = recv(client_sock, buf, msg_len, MSG_WAITALL);
        if (n <= 0) break;

        printf("[*] DNS-TCP packet (%d bytes)\n", n);
        process_dns_packet(buf, n);

        /* Send response */
        if (n >= 12) {
            buf[2] = 0x81;
            buf[3] = 0x83;
            uint8_t resp_len[2] = { (n >> 8) & 0xFF, n & 0xFF };
            send(client_sock, resp_len, 2, 0);
            send(client_sock, buf, n, 0);
        }
    }
    close(client_sock);
}

void *dns_tcp_server_thread(void *arg) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("DNS-TCP socket"); return NULL; }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DNS_TCP_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("DNS-TCP bind");
        close(sock);
        return NULL;
    }

    listen(sock, 10);
    printf("[*] DNS-TCP listener started on TCP :%d\n", DNS_TCP_PORT);

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr *)&client_addr, &client_len);
        if (client < 0) continue;

        printf("[*] DNS-TCP connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        pthread_t tid;
        pthread_create(&tid, NULL, (void *(*)(void *))handle_dns_tcp_client, (void *)(long)client);
        pthread_detach(tid);
    }

    close(sock);
    return NULL;
}

/* ─── FTP Server Thread ──────────────────────────────────────────── */
void *ftp_server_thread(void *arg) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("FTP socket"); return NULL; }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(FTP_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("FTP bind");
        close(sock);
        return NULL;
    }

    listen(sock, 10);
    printf("[*] FTP listener started on TCP :%d\n", FTP_PORT);

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr *)&client_addr, &client_len);
        if (client < 0) continue;

        printf("[*] FTP connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        /* Handle each client in a new thread */
        pthread_t tid;
        int *csock = malloc(sizeof(int));
        *csock = client;
        pthread_create(&tid, NULL, (void *(*)(void *))handle_ftp_client, (void *)(long)client);
        pthread_detach(tid);
    }

    close(sock);
    return NULL;
}

/* ─── Signal Handler ─────────────────────────────────────────────── */
void sighandler(int sig) {
    printf("\n[*] Caught signal %d, shutting down...\n", sig);
    running = 0;
}

/* ─── Main ───────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    /* Disable output buffering so logs appear before crashes */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  VulnIDS — Intentionally Vulnerable IDS     ║\n");
    printf("║  DNS (UDP 53 / TCP 5353) + FTP (TCP 21)     ║\n");
    printf("║  10 planted vulnerabilities                 ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    pthread_t dns_tid, dns_tcp_tid, ftp_tid;
    pthread_create(&dns_tid, NULL, dns_server_thread, NULL);
    pthread_create(&dns_tcp_tid, NULL, dns_tcp_server_thread, NULL);
    pthread_create(&ftp_tid, NULL, ftp_server_thread, NULL);

    /* Stats loop */
    while (running) {
        sleep(10);
        printf("[STATS] Packets: %d | Alerts: %d\n", packets_processed, alerts_triggered);
    }

    printf("[*] VulnIDS shutting down. Total packets: %d, alerts: %d\n",
           packets_processed, alerts_triggered);
    return 0;
}
