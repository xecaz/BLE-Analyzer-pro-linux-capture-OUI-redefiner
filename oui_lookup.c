/*
 * oui_lookup.c — BLE OUI & Manufacturer Lookup Tool
 *
 * Single-file C tool for enriching BLE capture CSVs with manufacturer info.
 * Uses IEEE OUI database and Bluetooth SIG Company IDs.
 *
 * Build: gcc -O2 -o oui_lookup oui_lookup.c
 * Usage: ./oui_lookup --update
 *        ./oui_lookup --mac AA:BB:CC:DD:EE:FF
 *        ./oui_lookup <file.csv> [-o enriched.csv]
 *        ./oui_lookup --summary <file.csv>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t g_interrupted = 0;

static void sigint_handler(int sig)
{
    (void)sig;
    g_interrupted = 1;
}

/* ---------- constants ---------- */

#define DB_MAGIC   0x4F554944u  /* "OUID" */
#define DB_VERSION 2
#define NAME_LEN   64
#define MAX_LINE   8192
#define MAX_COLS   64

#define OUI_JSON_URL "https://maclookup.app/downloads/json-database/get-db"
#define CID_YAML_URL "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml"

/* ---------- data structures ---------- */

#pragma pack(push, 1)

struct db_header {
    uint32_t magic;
    uint32_t version;
    uint32_t oui_count;
    uint32_t cid_count;
};

struct oui_entry {
    uint8_t  prefix[3];   /* OUI bytes, big-endian */
    char     name[NAME_LEN];
};

struct cid_entry {
    uint16_t company_id;  /* little-endian as per BLE spec */
    char     name[NAME_LEN];
};

#pragma pack(pop)

struct database {
    uint32_t          oui_count;
    uint32_t          cid_count;
    struct oui_entry *ouis;
    struct cid_entry *cids;
};

/* ---------- utility ---------- */

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_byte(const char *s)
{
    int hi = hex_digit(s[0]);
    int lo = hex_digit(s[1]);
    if (hi < 0 || lo < 0) return -1;
    return (hi << 4) | lo;
}

/* Parse hex string into byte array, return number of bytes parsed */
static int parse_hex(const char *hex, uint8_t *out, int maxlen)
{
    int n = 0;
    while (hex[0] && hex[1] && n < maxlen) {
        int b = hex_byte(hex);
        if (b < 0) break;
        out[n++] = (uint8_t)b;
        hex += 2;
    }
    return n;
}

/* Parse MAC address "AA:BB:CC:DD:EE:FF" into 6 bytes */
static int parse_mac(const char *s, uint8_t mac[6])
{
    for (int i = 0; i < 6; i++) {
        int b = hex_byte(s);
        if (b < 0) return -1;
        mac[i] = (uint8_t)b;
        s += 2;
        if (i < 5) {
            if (*s != ':') return -1;
            s++;
        }
    }
    return 0;
}

static const char *get_db_path(void)
{
    static char path[1024];
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(path, sizeof(path), "%s/.oui_lookup.db", home);
    return path;
}

static char *get_tmp_path(const char *suffix)
{
    static char path[1024];
    snprintf(path, sizeof(path), "/tmp/oui_lookup_%s_%d", suffix, getpid());
    return path;
}

/* ---------- CSV field parser ---------- */

/*
 * Parse next CSV field from *p, advance *p past delimiter.
 * Handles quoted fields with escaped quotes ("").
 * Returns pointer to field content in buf (null-terminated).
 */
static char *csv_next_field(const char **p, char *buf, int bufsize)
{
    const char *s = *p;
    char *out = buf;
    char *end = buf + bufsize - 1;

    if (*s == '"') {
        s++;
        while (*s && out < end) {
            if (*s == '"') {
                if (s[1] == '"') {
                    *out++ = '"';
                    s += 2;
                } else {
                    s++; /* closing quote */
                    break;
                }
            } else {
                *out++ = *s++;
            }
        }
        if (*s == ',') s++;
    } else {
        while (*s && *s != ',' && *s != '\n' && *s != '\r' && out < end)
            *out++ = *s++;
        if (*s == ',') s++;
    }
    *out = '\0';
    *p = s;
    return buf;
}

/* Split a CSV line into fields, return count */
static int csv_split(const char *line, char fields[][256], int maxfields)
{
    int n = 0;
    const char *p = line;
    while (*p && *p != '\n' && *p != '\r' && n < maxfields) {
        csv_next_field(&p, fields[n], 256);
        n++;
    }
    return n;
}

/* ---------- database I/O ---------- */

static int db_load(struct database *db)
{
    const char *path = get_db_path();
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    struct db_header hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) goto fail;
    if (hdr.magic != DB_MAGIC || hdr.version != DB_VERSION) {
        fprintf(stderr, "DB version mismatch, please run --update\n");
        goto fail;
    }

    db->oui_count = hdr.oui_count;
    db->cid_count = hdr.cid_count;

    db->ouis = calloc(hdr.oui_count, sizeof(struct oui_entry));
    db->cids = calloc(hdr.cid_count, sizeof(struct cid_entry));
    if (!db->ouis || !db->cids) goto fail;

    if (fread(db->ouis, sizeof(struct oui_entry), hdr.oui_count, f) != hdr.oui_count) goto fail;
    if (fread(db->cids, sizeof(struct cid_entry), hdr.cid_count, f) != hdr.cid_count) goto fail;

    fclose(f);
    return 0;

fail:
    fclose(f);
    free(db->ouis); db->ouis = NULL;
    free(db->cids); db->cids = NULL;
    return -1;
}

static int db_save(const struct database *db)
{
    const char *path = get_db_path();
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Cannot write DB to %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct db_header hdr = {
        .magic = DB_MAGIC,
        .version = DB_VERSION,
        .oui_count = db->oui_count,
        .cid_count = db->cid_count,
    };

    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(db->ouis, sizeof(struct oui_entry), db->oui_count, f);
    fwrite(db->cids, sizeof(struct cid_entry), db->cid_count, f);
    fclose(f);
    return 0;
}

static void db_free(struct database *db)
{
    free(db->ouis); db->ouis = NULL;
    free(db->cids); db->cids = NULL;
    db->oui_count = db->cid_count = 0;
}

/* ---------- binary search lookups ---------- */

static int oui_cmp(const void *a, const void *b)
{
    const struct oui_entry *ea = a, *eb = b;
    return memcmp(ea->prefix, eb->prefix, 3);
}

static int cid_cmp(const void *a, const void *b)
{
    const struct cid_entry *ea = a, *eb = b;
    if (ea->company_id < eb->company_id) return -1;
    if (ea->company_id > eb->company_id) return  1;
    return 0;
}

static const char *db_lookup_oui(const struct database *db, const uint8_t mac[6])
{
    struct oui_entry key;
    memcpy(key.prefix, mac, 3);
    struct oui_entry *found = bsearch(&key, db->ouis, db->oui_count,
                                       sizeof(struct oui_entry), oui_cmp);
    return found ? found->name : NULL;
}

static const char *db_lookup_cid(const struct database *db, uint16_t cid)
{
    struct cid_entry key = { .company_id = cid };
    struct cid_entry *found = bsearch(&key, db->cids, db->cid_count,
                                       sizeof(struct cid_entry), cid_cmp);
    return found ? found->name : NULL;
}

/* ---------- update: parse OUI JSON (maclookup.app format) ---------- */

/*
 * Format: [{"macPrefix":"AA:BB:CC","vendorName":"...","private":false,...}, ...]
 * We extract macPrefix and vendorName from each object.
 */
static int parse_oui_json(const char *path, struct oui_entry **out, uint32_t *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = malloc(sz + 1);
    if (!data) { fclose(f); return -1; }
    fread(data, 1, sz, f);
    data[sz] = '\0';
    fclose(f);

    int cap = 40000;
    int n = 0;
    struct oui_entry *entries = calloc(cap, sizeof(struct oui_entry));
    if (!entries) { free(data); return -1; }

    const char *p = data;
    while ((p = strchr(p, '{')) != NULL) {
        const char *obj_end = strchr(p, '}');
        if (!obj_end) break;

        char mac_prefix[20] = {0};
        char vendor[NAME_LEN] = {0};

        /* Find "macPrefix" */
        const char *mp = strstr(p, "\"macPrefix\"");
        if (mp && mp < obj_end) {
            mp += 11;
            while (mp < obj_end && (*mp == ' ' || *mp == ':' || *mp == '\t')) mp++;
            if (*mp == '"') {
                mp++;
                int i = 0;
                while (mp < obj_end && *mp != '"' && i < 19)
                    mac_prefix[i++] = *mp++;
                mac_prefix[i] = '\0';
            }
        }

        /* Find "vendorName" */
        const char *vp = strstr(p, "\"vendorName\"");
        if (vp && vp < obj_end) {
            vp += 12;
            while (vp < obj_end && (*vp == ' ' || *vp == ':' || *vp == '\t')) vp++;
            if (*vp == '"') {
                vp++;
                int i = 0;
                while (vp < obj_end && *vp != '"' && i < NAME_LEN - 1) {
                    if (*vp == '\\' && vp[1]) { vp++; vendor[i++] = *vp; }
                    else vendor[i++] = *vp;
                    vp++;
                }
                vendor[i] = '\0';
            }
        }

        if (mac_prefix[0] && vendor[0]) {
            /* Parse "AA:BB:CC" into 3 bytes */
            uint8_t prefix[3];
            int ok = 1;
            const char *s = mac_prefix;
            for (int i = 0; i < 3 && ok; i++) {
                int b = hex_byte(s);
                if (b < 0) { ok = 0; break; }
                prefix[i] = (uint8_t)b;
                s += 2;
                if (i < 2) { if (*s == ':') s++; else ok = 0; }
            }

            if (ok) {
                if (n >= cap) {
                    cap *= 2;
                    entries = realloc(entries, cap * sizeof(struct oui_entry));
                    if (!entries) { free(data); return -1; }
                }
                memcpy(entries[n].prefix, prefix, 3);
                strncpy(entries[n].name, vendor, NAME_LEN - 1);
                entries[n].name[NAME_LEN - 1] = '\0';
                n++;
            }
        }

        p = obj_end + 1;
    }

    free(data);
    qsort(entries, n, sizeof(struct oui_entry), oui_cmp);

    *out = entries;
    *count = n;
    fprintf(stderr, "Parsed %d OUI entries\n", n);
    return 0;
}

/* ---------- update: parse BT SIG Company IDs YAML ---------- */

/*
 * YAML format:
 *   company_identifiers:
 *     - value: 0x004C
 *       name: 'Apple, Inc.'
 *     - value: 0x0006
 *       name: 'Microsoft'
 *
 * Simple line-by-line parser: look for "- value:" and "name:" lines.
 */
static int parse_cid_yaml(const char *path, struct cid_entry **out, uint32_t *count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }

    int cap = 6000;
    int n = 0;
    struct cid_entry *entries = calloc(cap, sizeof(struct cid_entry));
    if (!entries) { fclose(f); return -1; }

    char line[MAX_LINE];
    int cur_value = -1;

    while (fgets(line, sizeof(line), f)) {
        /* Trim trailing whitespace */
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
            line[--len] = '\0';

        /* Look for "- value: 0xHHHH" or "  value: 0xHHHH" */
        const char *vp = strstr(line, "value:");
        if (vp) {
            vp += 6;
            while (*vp == ' ' || *vp == '\t') vp++;
            cur_value = (int)strtol(vp, NULL, 0);
            continue;
        }

        /* Look for "name: '...'" or "name: \"...\"" */
        const char *np = strstr(line, "name:");
        if (np && cur_value >= 0) {
            np += 5;
            while (*np == ' ' || *np == '\t') np++;

            char name[NAME_LEN] = {0};
            int i = 0;

            if (*np == '\'' || *np == '"') {
                char quote = *np++;
                while (*np && *np != quote && i < NAME_LEN - 1) {
                    /* Handle escaped quotes ('') in YAML */
                    if (*np == quote && np[1] == quote) {
                        name[i++] = quote;
                        np += 2;
                    } else {
                        name[i++] = *np++;
                    }
                }
            } else {
                /* Unquoted value */
                while (*np && i < NAME_LEN - 1)
                    name[i++] = *np++;
            }
            name[i] = '\0';

            if (name[0]) {
                if (n >= cap) {
                    cap *= 2;
                    entries = realloc(entries, cap * sizeof(struct cid_entry));
                    if (!entries) { fclose(f); return -1; }
                }
                entries[n].company_id = (uint16_t)cur_value;
                strncpy(entries[n].name, name, NAME_LEN - 1);
                entries[n].name[NAME_LEN - 1] = '\0';
                n++;
            }
            cur_value = -1;
        }
    }

    fclose(f);
    qsort(entries, n, sizeof(struct cid_entry), cid_cmp);

    *out = entries;
    *count = n;
    fprintf(stderr, "Parsed %d Company ID entries\n", n);
    return 0;
}

/* ---------- update command ---------- */

static int download(const char *url, const char *dest)
{
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "curl -sL '%s' -o '%s'", url, dest);
    fprintf(stderr, "Downloading %s ...\n", url);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "Download failed (exit %d). Is curl installed?\n", rc);
        return -1;
    }

    struct stat st;
    if (stat(dest, &st) != 0 || st.st_size == 0) {
        fprintf(stderr, "Downloaded file is empty\n");
        return -1;
    }
    fprintf(stderr, "  -> %ld bytes\n", (long)st.st_size);
    return 0;
}

static int cmd_update(void)
{
    char *oui_tmp = strdup(get_tmp_path("oui.json"));
    char *cid_tmp = strdup(get_tmp_path("cid.yaml"));

    int rc = -1;
    struct database db = {0};

    if (download(OUI_JSON_URL, oui_tmp) != 0) goto done;
    if (download(CID_YAML_URL, cid_tmp) != 0) goto done;

    if (parse_oui_json(oui_tmp, &db.ouis, &db.oui_count) != 0) goto done;
    if (parse_cid_yaml(cid_tmp, &db.cids, &db.cid_count) != 0) goto done;

    if (db_save(&db) != 0) goto done;

    fprintf(stderr, "Database saved to %s (%u OUIs, %u CIDs)\n",
            get_db_path(), db.oui_count, db.cid_count);
    rc = 0;

done:
    unlink(oui_tmp);
    unlink(cid_tmp);
    free(oui_tmp);
    free(cid_tmp);
    db_free(&db);
    return rc;
}

/* ---------- BLE PDU / AD parsing ---------- */

/*
 * Extract company ID from BLE advertising PDU hex.
 * PDU format: header(2 bytes) + address(6 bytes) + AD structures
 * AD structure: length(1) + type(1) + data(length-1)
 * Type 0xFF = Manufacturer Specific Data, first 2 bytes = Company ID (LE)
 *
 * Returns company ID or -1 if not found.
 */
static int extract_company_id(const char *pdu_hex)
{
    uint8_t pdu[256];
    int pdu_len = parse_hex(pdu_hex, pdu, sizeof(pdu));

    /* Need at least header(2) + address(6) + one AD(3) = 11 bytes */
    if (pdu_len < 11) return -1;

    int ad_start = 8; /* skip 2-byte header + 6-byte address */
    int pos = ad_start;

    while (pos < pdu_len) {
        int ad_len = pdu[pos];
        if (ad_len == 0 || pos + 1 + ad_len > pdu_len) break;

        int ad_type = pdu[pos + 1];
        if (ad_type == 0xFF && ad_len >= 3) {
            /* Company ID is little-endian 16-bit */
            uint16_t cid = pdu[pos + 2] | (pdu[pos + 3] << 8);
            return cid;
        }

        pos += 1 + ad_len;
    }

    return -1;
}

/*
 * Determine address type from PDU header.
 * TxAdd = bit 6 of first PDU byte. 1 = random, 0 = public.
 */
static int is_random_address(const char *pdu_hex)
{
    if (strlen(pdu_hex) < 2) return -1;
    int b = hex_byte(pdu_hex);
    if (b < 0) return -1;
    return (b >> 6) & 1;
}

/* Extract company ID from raw PDU bytes (for pcap path) */
static int extract_company_id_bytes(const uint8_t *pdu, int pdu_len)
{
    if (pdu_len < 11) return -1;
    int pos = 8;
    while (pos < pdu_len) {
        int ad_len = pdu[pos];
        if (ad_len == 0 || pos + 1 + ad_len > pdu_len) break;
        if (pdu[pos + 1] == 0xFF && ad_len >= 3) {
            return pdu[pos + 2] | (pdu[pos + 3] << 8);
        }
        pos += 1 + ad_len;
    }
    return -1;
}

/* Convert raw bytes to compact hex string */
static void bytes_to_hex(const uint8_t *data, int len, char *out, int outsize)
{
    int i;
    for (i = 0; i < len && i * 2 + 2 < outsize; i++) {
        out[i * 2]     = "0123456789abcdef"[data[i] >> 4];
        out[i * 2 + 1] = "0123456789abcdef"[data[i] & 0xf];
    }
    out[i * 2] = '\0';
}

static const char *pdu_type_name(int type_nibble)
{
    static const char *names[] = {
        "ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
        "SCAN_RSP", "CONNECT_IND", "ADV_SCAN_IND", "ADV_EXT_IND"
    };
    if (type_nibble >= 0 && type_nibble < 8) return names[type_nibble];
    return "UNKNOWN";
}

/*
 * Parse a WCH sniffer text line. Extract MAC address and PDU hex.
 * Returns 0 on success, -1 if line doesn't contain a parseable packet.
 *
 * Format:
 * [    33344834 us] ch37  ADV_NONCONN_IND  rssi  -68 dBm  AA 8E89BED6  E9:E7:8B:69:F8:49  PDU[16]: 42 0e ...
 * SCAN_REQ lines may have: scanner_addr→target_addr — use first address.
 */
static int parse_sniffer_line(const char *line, char mac_out[18], char *pdu_hex_out, int pdu_hex_size)
{
    mac_out[0] = '\0';
    pdu_hex_out[0] = '\0';

    /* Find first MAC address (XX:XX:XX:XX:XX:XX pattern) */
    const char *p = line;
    const char *mac_start = NULL;
    while (*p) {
        if (hex_digit(p[0]) >= 0 && hex_digit(p[1]) >= 0 && p[2] == ':' &&
            hex_digit(p[3]) >= 0 && hex_digit(p[4]) >= 0 && p[5] == ':' &&
            hex_digit(p[6]) >= 0 && hex_digit(p[7]) >= 0 && p[8] == ':' &&
            hex_digit(p[9]) >= 0 && hex_digit(p[10]) >= 0 && p[11] == ':' &&
            hex_digit(p[12]) >= 0 && hex_digit(p[13]) >= 0 && p[14] == ':' &&
            hex_digit(p[15]) >= 0 && hex_digit(p[16]) >= 0) {
            mac_start = p;
            break;
        }
        p++;
    }
    if (!mac_start) return -1;

    memcpy(mac_out, mac_start, 17);
    mac_out[17] = '\0';

    /* Find PDU hex after "PDU[N]:" */
    const char *pdu_marker = strstr(line, "PDU[");
    if (!pdu_marker) return -1;

    /* Skip past "PDU[N]:" */
    const char *colon = strchr(pdu_marker, ':');
    if (!colon) return -1;
    colon++; /* skip ':' */

    /* Parse space-separated hex bytes into compact hex string */
    int out_pos = 0;
    while (*colon && out_pos + 2 < pdu_hex_size) {
        while (*colon == ' ') colon++;
        if (*colon == '\0' || *colon == '\n' || *colon == '\r') break;
        /* Handle truncation marker "..." */
        if (colon[0] == '.' && colon[1] == '.' && colon[2] == '.') break;
        int hi = hex_digit(colon[0]);
        int lo = hex_digit(colon[1]);
        if (hi < 0 || lo < 0) break;
        pdu_hex_out[out_pos++] = "0123456789abcdef"[hi];
        pdu_hex_out[out_pos++] = "0123456789abcdef"[lo];
        colon += 2;
    }
    pdu_hex_out[out_pos] = '\0';

    return (out_pos >= 4) ? 0 : -1; /* need at least 2 PDU bytes */
}

/* ---------- CSV escape for output ---------- */

static void csv_write_field(FILE *f, const char *s)
{
    int needs_quote = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n') {
            needs_quote = 1;
            break;
        }
    }
    if (needs_quote) {
        fputc('"', f);
        for (const char *p = s; *p; p++) {
            if (*p == '"') fputc('"', f);
            fputc(*p, f);
        }
        fputc('"', f);
    } else {
        fputs(s, f);
    }
}

/* ---------- CSV processing ---------- */

static int find_column(char fields[][256], int nf, const char *name)
{
    for (int i = 0; i < nf; i++)
        if (strcasecmp(fields[i], name) == 0)
            return i;
    return -1;
}

static int cmd_process_csv(const char *input_path, const char *output_path)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    FILE *fin = fopen(input_path, "r");
    if (!fin) {
        fprintf(stderr, "Cannot open %s: %s\n", input_path, strerror(errno));
        db_free(&db);
        return -1;
    }

    FILE *fout = stdout;
    if (output_path) {
        fout = fopen(output_path, "w");
        if (!fout) {
            fprintf(stderr, "Cannot open %s for writing: %s\n", output_path, strerror(errno));
            fclose(fin);
            db_free(&db);
            return -1;
        }
    }

    char line[MAX_LINE];

    /* Read header */
    if (!fgets(line, sizeof(line), fin)) {
        fprintf(stderr, "Empty input file\n");
        goto done;
    }

    char header_fields[MAX_COLS][256];
    int ncols = csv_split(line, header_fields, MAX_COLS);

    int col_address = find_column(header_fields, ncols, "address");
    int col_pdu_hex = find_column(header_fields, ncols, "pdu_hex");

    if (col_address < 0) {
        fprintf(stderr, "No 'address' column found\n");
        goto done;
    }

    /* Write header + new columns */
    /* Trim trailing newline from original line */
    int len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
        line[--len] = '\0';
    fprintf(fout, "%s,address_type,oui_manufacturer,ble_company\n", line);

    /* Process rows */
    int row = 0;
    while (fgets(line, sizeof(line), fin)) {
        row++;

        /* Trim trailing newline */
        len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if (len == 0) continue;

        char fields[MAX_COLS][256];
        int nf = csv_split(line, fields, MAX_COLS);

        const char *address = (col_address < nf) ? fields[col_address] : "";
        const char *pdu_hex = (col_pdu_hex >= 0 && col_pdu_hex < nf) ? fields[col_pdu_hex] : "";

        /* Determine address type */
        const char *addr_type = "";
        int random = -1;
        if (col_pdu_hex >= 0 && pdu_hex[0]) {
            random = is_random_address(pdu_hex);
            addr_type = (random == 1) ? "random" : (random == 0) ? "public" : "";
        }

        /* OUI lookup (meaningful for public addresses) */
        uint8_t mac[6];
        const char *oui_name = "";
        if (parse_mac(address, mac) == 0) {
            if (random != 1) {  /* public or unknown */
                const char *found = db_lookup_oui(&db, mac);
                if (found) oui_name = found;
            }
        }

        /* BLE Company ID from advertising data */
        const char *cid_name = "";
        if (pdu_hex[0]) {
            int cid = extract_company_id(pdu_hex);
            if (cid >= 0) {
                const char *found = db_lookup_cid(&db, (uint16_t)cid);
                if (found) cid_name = found;
            }
        }

        /* Write original line + new fields */
        /* Re-output original fields to preserve formatting */
        for (int i = 0; i < nf; i++) {
            if (i > 0) fputc(',', fout);
            csv_write_field(fout, fields[i]);
        }
        /* Pad missing columns if input row was short */
        for (int i = nf; i < ncols; i++)
            fputc(',', fout);

        fputc(',', fout); csv_write_field(fout, addr_type);
        fputc(',', fout); csv_write_field(fout, oui_name);
        fputc(',', fout); csv_write_field(fout, cid_name);
        fputc('\n', fout);
    }

    fprintf(stderr, "Processed %d rows\n", row);

done:
    if (fout != stdout) fclose(fout);
    fclose(fin);
    db_free(&db);
    return 0;
}

/* ---------- MAC lookup ---------- */

static int cmd_mac_lookup(const char *mac_str)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    uint8_t mac[6];
    if (parse_mac(mac_str, mac) != 0) {
        fprintf(stderr, "Invalid MAC address: %s\n", mac_str);
        db_free(&db);
        return -1;
    }

    printf("MAC: %s\n", mac_str);

    /* Check if likely random (heuristic) */
    int top2 = (mac[0] >> 6) & 3;
    if (top2 == 3) printf("Address type: likely static random (MSB=11)\n");
    else if (top2 == 1) printf("Address type: likely resolvable private (MSB=01)\n");
    else printf("Address type: possibly public\n");

    const char *oui = db_lookup_oui(&db, mac);
    if (oui)
        printf("OUI manufacturer: %s\n", oui);
    else
        printf("OUI manufacturer: (not found)\n");

    db_free(&db);
    return 0;
}

/* ---------- summary mode ---------- */

struct summary_entry {
    char name[NAME_LEN];
    int  count;
};

#define HASH_SIZE 32768

struct summary_addr {
    char address[18];
    char oui_name[NAME_LEN];
    char cid_name[NAME_LEN];
    int  is_random;
    int  used;
};

struct summary_state {
    struct summary_addr *addr_table;
    int total_packets;
    int unique_addrs;
};

static int summary_init(struct summary_state *st)
{
    st->addr_table = calloc(HASH_SIZE, sizeof(struct summary_addr));
    st->total_packets = 0;
    st->unique_addrs = 0;
    return st->addr_table ? 0 : -1;
}

static void summary_add(struct summary_state *st, const struct database *db,
                         const char *address, const char *pdu_hex)
{
    st->total_packets++;

    unsigned h = 0;
    for (const char *p = address; *p; p++)
        h = h * 31 + (unsigned)*p;
    h %= HASH_SIZE;

    for (int i = 0; i < HASH_SIZE; i++) {
        int idx = (h + i) % HASH_SIZE;
        if (!st->addr_table[idx].used) {
            st->addr_table[idx].used = 1;
            strncpy(st->addr_table[idx].address, address, 17);
            st->addr_table[idx].address[17] = '\0';
            st->unique_addrs++;

            int random = (pdu_hex && pdu_hex[0]) ? is_random_address(pdu_hex) : -1;
            st->addr_table[idx].is_random = random;

            uint8_t mac[6];
            if (parse_mac(address, mac) == 0 && random != 1) {
                const char *name = db_lookup_oui(db, mac);
                if (name) strncpy(st->addr_table[idx].oui_name, name, NAME_LEN - 1);
            }

            if (pdu_hex && pdu_hex[0]) {
                int cid = extract_company_id(pdu_hex);
                if (cid >= 0) {
                    const char *name = db_lookup_cid(db, (uint16_t)cid);
                    if (name) strncpy(st->addr_table[idx].cid_name, name, NAME_LEN - 1);
                }
            }
            break;
        }
        if (strcmp(st->addr_table[idx].address, address) == 0) {
            if (!st->addr_table[idx].cid_name[0] && pdu_hex && pdu_hex[0]) {
                int cid = extract_company_id(pdu_hex);
                if (cid >= 0) {
                    const char *name = db_lookup_cid(db, (uint16_t)cid);
                    if (name) strncpy(st->addr_table[idx].cid_name, name, NAME_LEN - 1);
                }
            }
            break;
        }
    }
}

static void summary_print(const struct summary_state *st)
{
    int sum_cap = 256;
    struct summary_entry *oui_sums = calloc(sum_cap, sizeof(struct summary_entry));
    struct summary_entry *cid_sums = calloc(sum_cap, sizeof(struct summary_entry));
    int oui_sum_n = 0, cid_sum_n = 0;
    int random_count = 0, public_count = 0;

    for (int i = 0; i < HASH_SIZE; i++) {
        if (!st->addr_table[i].used) continue;

        if (st->addr_table[i].is_random == 1) random_count++;
        else public_count++;

        const char *oname = st->addr_table[i].oui_name[0] ? st->addr_table[i].oui_name : "(unknown)";
        if (st->addr_table[i].is_random != 1 || st->addr_table[i].oui_name[0]) {
            int found = 0;
            for (int j = 0; j < oui_sum_n; j++) {
                if (strcmp(oui_sums[j].name, oname) == 0) {
                    oui_sums[j].count++;
                    found = 1;
                    break;
                }
            }
            if (!found && oui_sum_n < sum_cap) {
                strncpy(oui_sums[oui_sum_n].name, oname, NAME_LEN - 1);
                oui_sums[oui_sum_n].count = 1;
                oui_sum_n++;
            }
        }

        if (st->addr_table[i].cid_name[0]) {
            int found = 0;
            for (int j = 0; j < cid_sum_n; j++) {
                if (strcmp(cid_sums[j].name, st->addr_table[i].cid_name) == 0) {
                    cid_sums[j].count++;
                    found = 1;
                    break;
                }
            }
            if (!found && cid_sum_n < sum_cap) {
                strncpy(cid_sums[cid_sum_n].name, st->addr_table[i].cid_name, NAME_LEN - 1);
                cid_sums[cid_sum_n].count = 1;
                cid_sum_n++;
            }
        }
    }

    for (int i = 0; i < oui_sum_n - 1; i++)
        for (int j = i + 1; j < oui_sum_n; j++)
            if (oui_sums[j].count > oui_sums[i].count) {
                struct summary_entry tmp = oui_sums[i];
                oui_sums[i] = oui_sums[j];
                oui_sums[j] = tmp;
            }
    for (int i = 0; i < cid_sum_n - 1; i++)
        for (int j = i + 1; j < cid_sum_n; j++)
            if (cid_sums[j].count > cid_sums[i].count) {
                struct summary_entry tmp = cid_sums[i];
                cid_sums[i] = cid_sums[j];
                cid_sums[j] = tmp;
            }

    printf("=== BLE Capture Summary ===\n");
    printf("Total packets:     %d\n", st->total_packets);
    printf("Unique addresses:  %d\n", st->unique_addrs);
    printf("  Public:          %d\n", public_count);
    printf("  Random:          %d\n", random_count);
    printf("\n");

    printf("--- By OUI Manufacturer (public addresses) ---\n");
    printf("%-40s  %s\n", "Manufacturer", "Devices");
    printf("%-40s  %s\n", "----------------------------------------", "-------");
    for (int i = 0; i < oui_sum_n; i++)
        printf("%-40s  %d\n", oui_sums[i].name, oui_sums[i].count);
    printf("\n");

    printf("--- By BLE Company ID (from advertising data) ---\n");
    printf("%-40s  %s\n", "Company", "Devices");
    printf("%-40s  %s\n", "----------------------------------------", "-------");
    for (int i = 0; i < cid_sum_n; i++)
        printf("%-40s  %d\n", cid_sums[i].name, cid_sums[i].count);
    printf("\n");

    free(oui_sums);
    free(cid_sums);
}

static void summary_free(struct summary_state *st)
{
    free(st->addr_table);
    st->addr_table = NULL;
}

static int cmd_summary(const char *input_path)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    FILE *fin = fopen(input_path, "r");
    if (!fin) {
        fprintf(stderr, "Cannot open %s: %s\n", input_path, strerror(errno));
        db_free(&db);
        return -1;
    }

    char line[MAX_LINE];

    if (!fgets(line, sizeof(line), fin)) {
        fprintf(stderr, "Empty file\n");
        fclose(fin);
        db_free(&db);
        return -1;
    }

    char header_fields[MAX_COLS][256];
    int ncols = csv_split(line, header_fields, MAX_COLS);
    int col_address = find_column(header_fields, ncols, "address");
    int col_pdu_hex = find_column(header_fields, ncols, "pdu_hex");

    if (col_address < 0) {
        fprintf(stderr, "No 'address' column found\n");
        fclose(fin);
        db_free(&db);
        return -1;
    }

    struct summary_state st;
    if (summary_init(&st) != 0) { fclose(fin); db_free(&db); return -1; }

    while (fgets(line, sizeof(line), fin)) {
        char fields[MAX_COLS][256];
        int nf = csv_split(line, fields, MAX_COLS);
        if (col_address >= nf) continue;

        const char *address = fields[col_address];
        const char *pdu_hex = (col_pdu_hex >= 0 && col_pdu_hex < nf) ? fields[col_pdu_hex] : "";
        summary_add(&st, &db, address, pdu_hex);
    }

    fclose(fin);
    summary_print(&st);
    summary_free(&st);
    db_free(&db);
    return 0;
}

/* ---------- text stdin processing ---------- */

static int cmd_process_text(FILE *fin)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    char line[MAX_LINE];
    while (!g_interrupted && fgets(line, sizeof(line), fin)) {
        /* Trim trailing newline */
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        char mac_str[18];
        char pdu_hex[1024];

        if (parse_sniffer_line(line, mac_str, pdu_hex, sizeof(pdu_hex)) != 0) {
            /* Pass through unparseable lines unchanged */
            if (printf("%s\n", line) < 0) break;
            fflush(stdout);
            continue;
        }

        /* Determine address type */
        int random = is_random_address(pdu_hex);
        const char *addr_type = (random == 1) ? "random" : (random == 0) ? "public" : "";

        /* OUI lookup */
        uint8_t mac[6];
        const char *oui_name = "";
        if (parse_mac(mac_str, mac) == 0 && random != 1) {
            const char *found = db_lookup_oui(&db, mac);
            if (found) oui_name = found;
        }

        /* Company ID lookup */
        const char *cid_name = "";
        if (pdu_hex[0]) {
            int cid = extract_company_id(pdu_hex);
            if (cid >= 0) {
                const char *found = db_lookup_cid(&db, (uint16_t)cid);
                if (found) cid_name = found;
            }
        }

        if (printf("%s  | %s | %s | %s\n", line, addr_type, oui_name, cid_name) < 0)
            break;
        fflush(stdout);
    }

    db_free(&db);
    return 0;
}

static int cmd_summary_text(FILE *fin)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    struct summary_state st;
    if (summary_init(&st) != 0) { db_free(&db); return -1; }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fin)) {
        char mac_str[18];
        char pdu_hex[1024];
        if (parse_sniffer_line(line, mac_str, pdu_hex, sizeof(pdu_hex)) == 0)
            summary_add(&st, &db, mac_str, pdu_hex);
    }

    summary_print(&st);
    summary_free(&st);
    db_free(&db);
    return 0;
}

/* ---------- pcap processing ---------- */

#define PCAP_MAGIC      0xA1B2C3D4u
#define DLT_BLE_LL_PHDR 256

struct pcap_global_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

static int cmd_process_pcap(const char *path, const char *output_path)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    FILE *fin = fopen(path, "rb");
    if (!fin) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        db_free(&db);
        return -1;
    }

    struct pcap_global_header ghdr;
    if (fread(&ghdr, sizeof(ghdr), 1, fin) != 1) {
        fprintf(stderr, "Failed to read pcap header\n");
        fclose(fin); db_free(&db); return -1;
    }
    if (ghdr.magic != PCAP_MAGIC) {
        fprintf(stderr, "Not a pcap file (bad magic 0x%08x)\n", ghdr.magic);
        fclose(fin); db_free(&db); return -1;
    }
    if (ghdr.network != DLT_BLE_LL_PHDR) {
        fprintf(stderr, "Unsupported link type %u (expected %d for BLE LL with PHDR)\n",
                ghdr.network, DLT_BLE_LL_PHDR);
        fclose(fin); db_free(&db); return -1;
    }

    FILE *fout = stdout;
    if (output_path) {
        fout = fopen(output_path, "w");
        if (!fout) {
            fprintf(stderr, "Cannot open %s for writing: %s\n", output_path, strerror(errno));
            fclose(fin); db_free(&db); return -1;
        }
    }

    fprintf(fout, "timestamp_us,channel,pdu_type,address,rssi_dbm,pdu_hex,address_type,oui_manufacturer,ble_company\n");

    int row = 0;
    struct pcap_packet_header phdr;
    uint8_t pkt_buf[65536];

    while (fread(&phdr, sizeof(phdr), 1, fin) == 1) {
        if (phdr.incl_len > sizeof(pkt_buf)) {
            fseek(fin, phdr.incl_len, SEEK_CUR);
            continue;
        }
        if (fread(pkt_buf, 1, phdr.incl_len, fin) != phdr.incl_len)
            break;

        /* Packet layout: pseudo-header(10) + access_addr(4) + PDU + CRC(3) */
        if (phdr.incl_len < 17) continue; /* minimum: 10+4+3 */

        int channel = pkt_buf[0];
        int rssi = (int8_t)pkt_buf[1];

        /* PDU starts at byte 14, ends 3 bytes before packet end */
        int pdu_offset = 14;
        int pdu_len = (int)phdr.incl_len - pdu_offset - 3;
        if (pdu_len < 2) continue;

        const uint8_t *pdu = pkt_buf + pdu_offset;

        /* Address type from TxAdd bit */
        int random = (pdu[0] >> 6) & 1;
        const char *addr_type = random ? "random" : "public";

        /* PDU type nibble */
        int pdu_type_val = pdu[0] & 0x0F;
        const char *pdu_type_str = pdu_type_name(pdu_type_val);

        /* Extract MAC from PDU bytes 2..7 (reversed byte order) */
        char mac_str[18] = "";
        if (pdu_len >= 8) {
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     pdu[7], pdu[6], pdu[5], pdu[4], pdu[3], pdu[2]);
        }

        /* OUI lookup */
        uint8_t mac[6];
        const char *oui_name = "";
        if (mac_str[0] && parse_mac(mac_str, mac) == 0 && !random) {
            const char *found = db_lookup_oui(&db, mac);
            if (found) oui_name = found;
        }

        /* Company ID from AD structures */
        const char *cid_name = "";
        int cid = extract_company_id_bytes(pdu, pdu_len);
        if (cid >= 0) {
            const char *found = db_lookup_cid(&db, (uint16_t)cid);
            if (found) cid_name = found;
        }

        /* PDU hex string */
        char pdu_hex_str[1024];
        bytes_to_hex(pdu, pdu_len, pdu_hex_str, sizeof(pdu_hex_str));

        /* Timestamp in microseconds */
        uint64_t ts_us = (uint64_t)phdr.ts_sec * 1000000ULL + phdr.ts_usec;

        fprintf(fout, "%llu,%d,", (unsigned long long)ts_us, channel);
        csv_write_field(fout, pdu_type_str);
        fputc(',', fout);
        csv_write_field(fout, mac_str);
        fprintf(fout, ",%d,", rssi);
        csv_write_field(fout, pdu_hex_str);
        fputc(',', fout);
        csv_write_field(fout, addr_type);
        fputc(',', fout);
        csv_write_field(fout, oui_name);
        fputc(',', fout);
        csv_write_field(fout, cid_name);
        fputc('\n', fout);
        row++;
    }

    fprintf(stderr, "Processed %d packets from pcap\n", row);

    if (fout != stdout) fclose(fout);
    fclose(fin);
    db_free(&db);
    return 0;
}

static int cmd_summary_pcap(const char *path)
{
    struct database db = {0};
    if (db_load(&db) != 0) {
        fprintf(stderr, "Cannot load database. Run --update first.\n");
        return -1;
    }

    FILE *fin = fopen(path, "rb");
    if (!fin) {
        fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
        db_free(&db);
        return -1;
    }

    struct pcap_global_header ghdr;
    if (fread(&ghdr, sizeof(ghdr), 1, fin) != 1 ||
        ghdr.magic != PCAP_MAGIC || ghdr.network != DLT_BLE_LL_PHDR) {
        fprintf(stderr, "Invalid or unsupported pcap file\n");
        fclose(fin); db_free(&db); return -1;
    }

    struct summary_state st;
    if (summary_init(&st) != 0) { fclose(fin); db_free(&db); return -1; }

    struct pcap_packet_header phdr;
    uint8_t pkt_buf[65536];

    while (fread(&phdr, sizeof(phdr), 1, fin) == 1) {
        if (phdr.incl_len > sizeof(pkt_buf)) {
            fseek(fin, phdr.incl_len, SEEK_CUR);
            continue;
        }
        if (fread(pkt_buf, 1, phdr.incl_len, fin) != phdr.incl_len)
            break;

        if (phdr.incl_len < 17) continue;

        int pdu_offset = 14;
        int pdu_len = (int)phdr.incl_len - pdu_offset - 3;
        if (pdu_len < 2) continue;

        const uint8_t *pdu = pkt_buf + pdu_offset;

        char mac_str[18] = "";
        if (pdu_len >= 8) {
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     pdu[7], pdu[6], pdu[5], pdu[4], pdu[3], pdu[2]);
        }

        char pdu_hex_str[1024];
        bytes_to_hex(pdu, pdu_len, pdu_hex_str, sizeof(pdu_hex_str));

        summary_add(&st, &db, mac_str, pdu_hex_str);
    }

    fclose(fin);
    summary_print(&st);
    summary_free(&st);
    db_free(&db);
    return 0;
}

/* ---------- main ---------- */

static int cmd_import(const char *oui_path, const char *cid_path)
{
    struct database db = {0};
    int rc = -1;

    if (parse_oui_json(oui_path, &db.ouis, &db.oui_count) != 0) goto done;
    if (parse_cid_yaml(cid_path, &db.cids, &db.cid_count) != 0) goto done;
    if (db_save(&db) != 0) goto done;

    fprintf(stderr, "Database saved to %s (%u OUIs, %u CIDs)\n",
            get_db_path(), db.oui_count, db.cid_count);
    rc = 0;

done:
    db_free(&db);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --update                          Download and rebuild local DB\n"
        "  %s --import <oui.csv> <cid.json>     Build DB from local files\n"
        "  %s --mac AA:BB:CC:DD:EE:FF           Look up a single MAC address\n"
        "  %s <file.csv> [-o out.csv]            Enrich CSV with manufacturer info\n"
        "  %s --summary <file.csv>               Print per-manufacturer device counts\n"
        "  %s -                                  Enrich sniffer text from stdin\n"
        "  %s --summary -                        Summary from sniffer text on stdin\n"
        "  %s --pcap <file.pcap> [-o out.csv]    Process pcap file to enriched CSV\n"
        "  %s --summary --pcap <file.pcap>       Summary from pcap file\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--update") == 0)
        return cmd_update();

    if (strcmp(argv[1], "--import") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s --import <oui.csv> <cid.json>\n", argv[0]);
            return 1;
        }
        return cmd_import(argv[2], argv[3]);
    }

    if (strcmp(argv[1], "--mac") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --mac AA:BB:CC:DD:EE:FF\n", argv[0]);
            return 1;
        }
        return cmd_mac_lookup(argv[2]);
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage(argv[0]);
        return 0;
    }

    /* Parse flags */
    int summary_mode = 0;
    int pcap_mode = 0;
    const char *pcap_path = NULL;
    const char *output = NULL;
    const char *input = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--summary") == 0) {
            summary_mode = 1;
        } else if (strcmp(argv[i], "--pcap") == 0 && i + 1 < argc) {
            pcap_mode = 1;
            pcap_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (!input) {
            input = argv[i];
        }
    }

    /* Dispatch based on mode combinations */
    if (pcap_mode) {
        if (summary_mode)
            return cmd_summary_pcap(pcap_path);
        return cmd_process_pcap(pcap_path, output);
    }

    if (input && strcmp(input, "-") == 0) {
        if (summary_mode)
            return cmd_summary_text(stdin);
        return cmd_process_text(stdin);
    }

    if (summary_mode) {
        if (!input) {
            fprintf(stderr, "Usage: %s --summary <file.csv>\n", argv[0]);
            return 1;
        }
        return cmd_summary(input);
    }

    if (input)
        return cmd_process_csv(input, output);

    usage(argv[0]);
    return 1;
}
