/******************************************************************************
 * BoAT Attestor (C version)
 * Attests current memory and CPU usage to HashAnchor via x402 pay-per-use.
 * Uses BoAT v4 SDK for x402 payment signing.
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>

/* BoAT v4 SDK */
#include "boat.h"
#include "boat_key.h"
#include "boat_pay.h"
#include "boat_pal.h"

/* --- Configuration --- */
#define HASHANCHOR_URL       "https://hashanchor.xid.network"
#define SUBMIT_ENDPOINT      HASHANCHOR_URL "/v1/device/submit-signed"
#define VERIFY_ENDPOINT      HASHANCHOR_URL "/v1/verify"

#define DEVICE_KEY_FILE      ".boat-attest-device.json"
#define WALLET_KEY_FILE      ".boat-attest-wallet.json"
#define WALLET_KEY_ENV       "BOAT_WALLET_KEY"
#define API_KEY_ENV          "HASHANCHOR_API_KEY"

/* --- SHA-256 from OpenSSL --- */
#include <openssl/sha.h>
#include <openssl/evp.h>

/* --- Ed25519 from trezor-crypto (bundled with BoAT4) --- */
#include "ed25519-donna/ed25519.h"

/* --- Forward declarations --- */
static int get_device_id(char *out, size_t cap);
static int get_system_stats(cJSON **stats_out);
static void sha256_hex(const char *data, size_t len, char *out_hex);
static int load_or_create_device_key(uint8_t sk[64], uint8_t pk[32], bool *activated);
static void mark_device_activated(void);
static int load_or_create_wallet(BoatKey **key_out);
static int submit_signed(const char *data_json, const char *device_id,
                         const uint8_t sk[64], const uint8_t pk[32],
                         bool is_activated, BoatKey *wallet_key,
                         const char *api_key);

/* --- Curl helper for HTTP --- */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
    /* Response headers we care about */
    char payment_response[4096];
} HttpResponse;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    HttpResponse *resp = (HttpResponse *)userdata;
    size_t total = size * nmemb;
    if (resp->len + total >= resp->cap) {
        size_t newcap = (resp->cap + total) * 2;
        char *tmp = realloc(resp->data, newcap);
        if (!tmp) return 0;
        resp->data = tmp;
        resp->cap = newcap;
    }
    memcpy(resp->data + resp->len, ptr, total);
    resp->len += total;
    resp->data[resp->len] = '\0';
    return total;
}

static size_t curl_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    HttpResponse *resp = (HttpResponse *)userdata;
    size_t total = size * nitems;
    /* Look for PAYMENT-RESPONSE or payment-response header */
    if (total > 18 && (strncasecmp(buffer, "payment-response:", 17) == 0 ||
                       strncasecmp(buffer, "PAYMENT-RESPONSE:", 17) == 0)) {
        const char *val = buffer + 17;
        while (*val == ' ') val++;
        size_t vlen = total - (val - buffer);
        while (vlen > 0 && (val[vlen-1] == '\r' || val[vlen-1] == '\n')) vlen--;
        if (vlen < sizeof(resp->payment_response)) {
            memcpy(resp->payment_response, val, vlen);
            resp->payment_response[vlen] = '\0';
        }
    }
    return total;
}

static HttpResponse *http_response_new(void)
{
    HttpResponse *r = calloc(1, sizeof(HttpResponse));
    r->cap = 4096;
    r->data = malloc(r->cap);
    r->data[0] = '\0';
    return r;
}

static void http_response_free(HttpResponse *r)
{
    if (r) { free(r->data); free(r); }
}


/* --- HTTP POST helper using curl directly --- */
static int http_post(const char *url, const char *body, const char *extra_headers[],
                     int num_extra_headers, HttpResponse *resp, long *http_code)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    for (int i = 0; i < num_extra_headers; i++) {
        headers = curl_slist_append(headers, extra_headers[i]);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "  curl error: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0;
}

/* --- Base64 encode/decode --- */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap)
{
    size_t out_len = 4 * ((in_len + 2) / 3);
    if (out_len + 1 > out_cap) return 0;
    size_t i, j;
    for (i = 0, j = 0; i < in_len;) {
        uint32_t a = i < in_len ? in[i++] : 0;
        uint32_t b = i < in_len ? in[i++] : 0;
        uint32_t c = i < in_len ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = b64_table[(triple >> 6) & 0x3F];
        out[j++] = b64_table[triple & 0x3F];
    }
    size_t mod = in_len % 3;
    if (mod == 1) { out[j - 1] = '='; out[j - 2] = '='; }
    else if (mod == 2) { out[j - 1] = '='; }
    out[j] = '\0';
    return j;
}

static size_t base64_decode(const char *in, uint8_t *out, size_t out_cap)
{
    static const uint8_t d[] = {
        62,255,255,255,63,52,53,54,55,56,57,58,59,60,61,255,
        255,255,0,255,255,255,0,1,2,3,4,5,6,7,8,9,
        10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
        255,255,255,255,255,255,26,27,28,29,30,31,32,33,34,35,
        36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51
    };
    size_t in_len = strlen(in);
    if (in_len % 4 != 0) return 0;
    size_t out_len = in_len / 4 * 3;
    if (in[in_len - 1] == '=') out_len--;
    if (in[in_len - 2] == '=') out_len--;
    if (out_len > out_cap) return 0;
    for (size_t i = 0, j = 0; i < in_len;) {
        uint32_t a = in[i] == '=' ? 0 : d[(uint8_t)in[i] - 43]; i++;
        uint32_t b = in[i] == '=' ? 0 : d[(uint8_t)in[i] - 43]; i++;
        uint32_t c = in[i] == '=' ? 0 : d[(uint8_t)in[i] - 43]; i++;
        uint32_t e = in[i] == '=' ? 0 : d[(uint8_t)in[i] - 43]; i++;
        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | e;
        if (j < out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) out[j++] = triple & 0xFF;
    }
    return out_len;
}

/* --- Hex utilities --- */
static void bin_to_hex(const uint8_t *bin, size_t len, char *hex, bool prefix)
{
    int off = 0;
    if (prefix) { hex[0] = '0'; hex[1] = 'x'; off = 2; }
    for (size_t i = 0; i < len; i++)
        sprintf(hex + off + i * 2, "%02x", bin[i]);
    hex[off + len * 2] = '\0';
}

static int hex_to_bin(const char *hex, uint8_t *bin, size_t cap)
{
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    size_t len = strlen(hex) / 2;
    if (len > cap) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + i * 2, "%2x", &val);
        bin[i] = (uint8_t)val;
    }
    return (int)len;
}


/* --- Get device ID from eth0 MAC --- */
static int get_device_id(char *out, size_t cap)
{
    FILE *f = fopen("/sys/class/net/eth0/address", "r");
    if (!f) {
        fprintf(stderr, "Error: cannot read eth0 MAC address\n");
        return -1;
    }
    char mac[32];
    if (!fgets(mac, sizeof(mac), f)) { fclose(f); return -1; }
    fclose(f);

    /* Remove colons and trailing newline */
    char mac_hex[16];
    int j = 0;
    for (int i = 0; mac[i] && j < 12; i++) {
        if (mac[i] != ':' && mac[i] != '\n' && mac[i] != '\r')
            mac_hex[j++] = mac[i];
    }
    mac_hex[j] = '\0';

    snprintf(out, cap, "BoatAttestor-VF2-%s", mac_hex);
    return 0;
}

/* --- Collect system stats --- */
static int get_system_stats(cJSON **stats_out)
{
    cJSON *stats = cJSON_CreateObject();
    cJSON_AddNumberToObject(stats, "timestamp", (double)time(NULL));

    /* Memory from /proc/meminfo */
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        long total_kb = 0, available_kb = 0;
        while (fgets(line, sizeof(line), f)) {
            long val;
            if (sscanf(line, "MemTotal: %ld kB", &val) == 1) total_kb = val;
            else if (sscanf(line, "MemAvailable: %ld kB", &val) == 1) available_kb = val;
        }
        fclose(f);
        cJSON *mem = cJSON_CreateObject();
        cJSON_AddNumberToObject(mem, "available_kb", available_kb);
        cJSON_AddNumberToObject(mem, "total_kb", total_kb);
        cJSON_AddNumberToObject(mem, "used_kb", total_kb - available_kb);
        cJSON_AddItemToObject(stats, "memory", mem);
    }

    /* CPU from /proc/stat */
    f = fopen("/proc/stat", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            long vals[8] = {0};
            sscanf(line, "cpu %ld %ld %ld %ld %ld %ld %ld %ld",
                   &vals[0], &vals[1], &vals[2], &vals[3],
                   &vals[4], &vals[5], &vals[6], &vals[7]);
            long total = 0;
            for (int i = 0; i < 8; i++) total += vals[i];
            long idle = vals[3] + vals[4];
            cJSON *cpu = cJSON_CreateObject();
            cJSON_AddNumberToObject(cpu, "busy_ticks", (double)(total - idle));
            cJSON_AddNumberToObject(cpu, "idle", (double)vals[3]);
            cJSON_AddNumberToObject(cpu, "iowait", (double)vals[4]);
            cJSON_AddNumberToObject(cpu, "nice", (double)vals[1]);
            cJSON_AddNumberToObject(cpu, "system", (double)vals[2]);
            cJSON_AddNumberToObject(cpu, "total_ticks", (double)total);
            cJSON_AddNumberToObject(cpu, "user", (double)vals[0]);
            cJSON_AddItemToObject(stats, "cpu", cpu);
        }
        fclose(f);
    }

    /* Load average from /proc/loadavg */
    f = fopen("/proc/loadavg", "r");
    if (f) {
        float l1, l5, l15;
        if (fscanf(f, "%f %f %f", &l1, &l5, &l15) == 3) {
            cJSON *la = cJSON_CreateObject();
            cJSON_AddNumberToObject(la, "15min", l15);
            cJSON_AddNumberToObject(la, "1min", l1);
            cJSON_AddNumberToObject(la, "5min", l5);
            cJSON_AddItemToObject(stats, "loadavg", la);
        }
        fclose(f);
    }

    *stats_out = stats;
    return 0;
}

/* --- SHA-256 hash to 0x-prefixed hex --- */
static void sha256_hex(const char *data, size_t len, char *out_hex)
{
    uint8_t hash[32];
    SHA256((const unsigned char *)data, len, hash);
    out_hex[0] = '0';
    out_hex[1] = 'x';
    for (int i = 0; i < 32; i++)
        sprintf(out_hex + 2 + i * 2, "%02x", hash[i]);
    out_hex[66] = '\0';
}


/* --- Device key management (Ed25519) --- */
static char *get_home_path(const char *filename, char *buf, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home) home = "/root";
    snprintf(buf, cap, "%s/%s", home, filename);
    return buf;
}

static int load_or_create_device_key(uint8_t sk[64], uint8_t pk[32], bool *activated)
{
    char path[512];
    get_home_path(DEVICE_KEY_FILE, path, sizeof(path));

    *activated = false;

    FILE *f = fopen(path, "r");
    if (f) {
        /* Load existing key */
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *json_str = malloc(fsize + 1);
        fread(json_str, 1, fsize, f);
        json_str[fsize] = '\0';
        fclose(f);

        cJSON *root = cJSON_Parse(json_str);
        free(json_str);
        if (!root) {
            fprintf(stderr, "Error: cannot parse %s\n", path);
            return -1;
        }

        cJSON *priv = cJSON_GetObjectItem(root, "private_key");
        cJSON *pub = cJSON_GetObjectItem(root, "public_key");
        cJSON *act = cJSON_GetObjectItem(root, "activated");

        if (!priv || !pub || !cJSON_IsString(priv) || !cJSON_IsString(pub)) {
            cJSON_Delete(root);
            return -1;
        }

        /* Ed25519 private key is 32 bytes seed; we store seed in sk[0..31] and derive */
        uint8_t seed[32];
        hex_to_bin(priv->valuestring, seed, 32);
        hex_to_bin(pub->valuestring, pk, 32);

        /* Reconstruct the 64-byte expanded secret key from seed */
        ed25519_publickey(seed, pk);
        /* For ed25519-donna: sk = seed(32) || pk(32) */
        memcpy(sk, seed, 32);
        memcpy(sk + 32, pk, 32);

        if (act && cJSON_IsBool(act)) *activated = cJSON_IsTrue(act);

        char pk_hex[65];
        bin_to_hex(pk, 32, pk_hex, false);
        printf("  Device key loaded: %s\n", pk_hex);

        cJSON_Delete(root);
        return 0;
    }

    /* Create new key */
    uint8_t seed[32];
    FILE *rng = fopen("/dev/urandom", "r");
    if (!rng || fread(seed, 1, 32, rng) != 32) {
        if (rng) fclose(rng);
        fprintf(stderr, "Error: cannot read /dev/urandom\n");
        return -1;
    }
    fclose(rng);

    ed25519_publickey(seed, pk);
    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);

    /* Save to file */
    char sk_hex[65], pk_hex[65];
    bin_to_hex(seed, 32, sk_hex, false);
    bin_to_hex(pk, 32, pk_hex, false);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "private_key", sk_hex);
    cJSON_AddStringToObject(root, "public_key", pk_hex);
    cJSON_AddBoolToObject(root, "activated", false);

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Error: cannot write %s\n", path);
        free(json_str);
        return -1;
    }
    fputs(json_str, f);
    fclose(f);
    chmod(path, 0600);
    free(json_str);

    printf("  New device key created: %s\n", pk_hex);
    return 0;
}

static void mark_device_activated(void)
{
    char path[512];
    get_home_path(DEVICE_KEY_FILE, path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *json_str = malloc(fsize + 1);
    fread(json_str, 1, fsize, f);
    json_str[fsize] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) return;

    cJSON_ReplaceItemInObject(root, "activated", cJSON_CreateBool(true));
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    f = fopen(path, "w");
    if (f) { fputs(out, f); fclose(f); }
    free(out);
}


/* --- Wallet key management (Secp256k1 via BoAT4) --- */
static int load_or_create_wallet(BoatKey **key_out)
{
    *key_out = NULL;

    /* Priority 1: Environment variable */
    const char *env_key = getenv(WALLET_KEY_ENV);
    if (env_key && env_key[0]) {
        *key_out = boat_key_import_string(BOAT_KEY_TYPE_SECP256K1, env_key);
        if (*key_out) {
            BoatKeyInfo info;
            boat_key_get_info(*key_out, &info);
            char addr[43];
            boat_address_to_string(&info, addr, sizeof(addr));
            printf("  Wallet loaded from env: %s\n", addr);
            return 0;
        }
        fprintf(stderr, "  Warning: BOAT_WALLET_KEY set but invalid\n");
    }

    /* Priority 2: Existing file */
    char path[512];
    get_home_path(WALLET_KEY_FILE, path, sizeof(path));

    FILE *f = fopen(path, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *json_str = malloc(fsize + 1);
        fread(json_str, 1, fsize, f);
        json_str[fsize] = '\0';
        fclose(f);

        cJSON *root = cJSON_Parse(json_str);
        free(json_str);
        if (root) {
            cJSON *priv = cJSON_GetObjectItem(root, "private_key");
            if (priv && cJSON_IsString(priv)) {
                *key_out = boat_key_import_string(BOAT_KEY_TYPE_SECP256K1, priv->valuestring);
                if (*key_out) {
                    BoatKeyInfo info;
                    boat_key_get_info(*key_out, &info);
                    char addr[43];
                    boat_address_to_string(&info, addr, sizeof(addr));
                    printf("  Wallet loaded from file: %s\n", addr);
                    cJSON_Delete(root);
                    return 0;
                }
            }
            cJSON_Delete(root);
        }
    }

    /* Priority 3: Create new wallet */
    *key_out = boat_key_generate(BOAT_KEY_TYPE_SECP256K1);
    if (!*key_out) {
        fprintf(stderr, "Error: failed to generate wallet key\n");
        return -1;
    }

    BoatKeyInfo info;
    boat_key_get_info(*key_out, &info);
    char addr[43];
    boat_address_to_string(&info, addr, sizeof(addr));

    /* Export private key hex for saving */
    /* We need to get the raw private key bytes - use boat_key internal or re-derive */
    /* For now, save the address; the key is in memory */
    /* Actually we need to save the private key. Let's use the BoAT storage mechanism
       and also write a JSON file for compatibility with the Python version. */

    /* Get raw private key via sign-and-recover approach is complex.
       Instead, we generate raw bytes and import them. */
    /* Re-approach: generate 32 random bytes, import as raw key, save those bytes */
    boat_key_free(*key_out);

    uint8_t raw_key[32];
    FILE *rng = fopen("/dev/urandom", "r");
    if (!rng || fread(raw_key, 1, 32, rng) != 32) {
        if (rng) fclose(rng);
        return -1;
    }
    fclose(rng);

    *key_out = boat_key_import_raw(BOAT_KEY_TYPE_SECP256K1, raw_key, 32);
    if (!*key_out) {
        fprintf(stderr, "Error: failed to import generated wallet key\n");
        return -1;
    }

    boat_key_get_info(*key_out, &info);
    boat_address_to_string(&info, addr, sizeof(addr));

    /* Save as JSON compatible with Python version */
    char priv_hex[67];
    bin_to_hex(raw_key, 32, priv_hex, true);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "private_key", priv_hex);
    cJSON_AddStringToObject(root, "address", addr);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Error: cannot write %s\n", path);
        free(json_str);
        return -1;
    }
    fputs(json_str, f);
    fclose(f);
    chmod(path, 0600);
    free(json_str);

    /* Clear sensitive data from stack */
    memset(raw_key, 0, 32);

    printf("  New wallet created: %s\n", addr);
    printf("  IMPORTANT: Fund this wallet with USDC and deposit into Gateway.\n");
    return 0;
}


/* --- Submit signed attestation to HashAnchor --- */
static int submit_signed(const char *data_json, const char *device_id,
                         const uint8_t sk[64], const uint8_t pk[32],
                         bool is_activated, BoatKey *wallet_key,
                         const char *api_key)
{
    /* Hash the data */
    char content_hash[68];
    sha256_hex(data_json, strlen(data_json), content_hash);

    /* Sign hash with Ed25519 device key */
    uint8_t hash_bytes[32];
    hex_to_bin(content_hash + 2, hash_bytes, 32);

    uint8_t device_sig[64];
    ed25519_sign(hash_bytes, 32, sk, pk, device_sig);

    char sig_hex[129];
    bin_to_hex(device_sig, 64, sig_hex, false);

    char pk_hex[65];
    bin_to_hex(pk, 32, pk_hex, false);

    /* Build request body */
    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "deviceId", device_id);
    cJSON_AddStringToObject(body, "hash", content_hash);
    cJSON_AddStringToObject(body, "signature", sig_hex);
    cJSON_AddStringToObject(body, "algorithm", "ed25519");

    if (!is_activated) {
        cJSON_AddStringToObject(body, "publicKey", pk_hex);
        printf("  First submission - including publicKey for activation\n");
    }

    char *body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    printf("  Data hash: %s\n", content_hash);
    printf("  Device signature: %.32s...\n", sig_hex);

    if (api_key && api_key[0]) {
        /* API key mode */
        printf("  Submitting with API key...\n");
        char auth_hdr[512];
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", api_key);
        const char *headers[] = { auth_hdr };

        HttpResponse *resp = http_response_new();
        long http_code = 0;
        int rc = http_post(SUBMIT_ENDPOINT, body_str, headers, 1, resp, &http_code);
        free(body_str);

        if (rc != 0) {
            http_response_free(resp);
            return -1;
        }

        if (http_code >= 200 && http_code <= 202) {
            cJSON *result = cJSON_Parse(resp->data);
            const char *hash = content_hash;
            if (result) {
                cJSON *h = cJSON_GetObjectItem(result, "hash");
                if (h && cJSON_IsString(h)) hash = h->valuestring;
                printf("  Accepted! Hash: %s\n", hash);
                cJSON_Delete(result);
            }
            if (!is_activated) {
                mark_device_activated();
                printf("  Device activated!\n");
            }
            http_response_free(resp);
            return 0;
        } else {
            printf("  Failed: %ld\n", http_code);
            printf("  Response: %s\n", resp->data);
            http_response_free(resp);
            return -1;
        }
    }

    /* x402 mode */
    printf("  Sending initial request...\n");
    HttpResponse *resp = http_response_new();
    long http_code = 0;
    int rc = http_post(SUBMIT_ENDPOINT, body_str, NULL, 0, resp, &http_code);

    if (rc != 0) {
        free(body_str);
        http_response_free(resp);
        return -1;
    }

    if (http_code >= 200 && http_code <= 202) {
        printf("  Accepted without payment\n");
        cJSON *result = cJSON_Parse(resp->data);
        if (result) {
            cJSON *h = cJSON_GetObjectItem(result, "hash");
            if (h && cJSON_IsString(h))
                printf("  Hash: %s\n", h->valuestring);
            cJSON_Delete(result);
        }
        free(body_str);
        http_response_free(resp);
        return 0;
    }

    if (http_code != 402) {
        printf("  Unexpected status: %ld\n", http_code);
        printf("  Response: %s\n", resp->data);
        free(body_str);
        http_response_free(resp);
        return -1;
    }

    /* Parse 402 payment requirements */
    printf("  Got 402 Payment Required\n");

    /* The 402 response body contains payment requirements as JSON.
     * Use BoAT4 x402 API to handle the payment flow. */
    /* We need to parse the 402 response ourselves and use boat_x402_make_payment */
    cJSON *pay_root = cJSON_Parse(resp->data);
    http_response_free(resp);

    if (!pay_root) {
        printf("  Error: cannot parse 402 response\n");
        free(body_str);
        return -1;
    }

    cJSON *accepts = cJSON_GetObjectItem(pay_root, "accepts");
    if (!accepts || !cJSON_IsArray(accepts) || cJSON_GetArraySize(accepts) == 0) {
        printf("  No payment options available\n");
        cJSON_Delete(pay_root);
        free(body_str);
        return -1;
    }

    cJSON *accept = cJSON_GetArrayItem(accepts, 0);


    /* Fill BoatX402PaymentReq from parsed JSON */
    BoatX402PaymentReq pay_req;
    memset(&pay_req, 0, sizeof(pay_req));

    cJSON *ver = cJSON_GetObjectItem(pay_root, "x402Version");
    pay_req.x402_version = (ver && cJSON_IsNumber(ver)) ? ver->valueint : 1;

    cJSON *j_scheme = cJSON_GetObjectItem(accept, "scheme");
    if (j_scheme && cJSON_IsString(j_scheme))
        strncpy(pay_req.scheme, j_scheme->valuestring, sizeof(pay_req.scheme) - 1);

    cJSON *j_network = cJSON_GetObjectItem(accept, "network");
    if (j_network && cJSON_IsString(j_network)) {
        strncpy(pay_req.network, j_network->valuestring, sizeof(pay_req.network) - 1);
        printf("  Network: %s", pay_req.network);
    }

    cJSON *j_amount = cJSON_GetObjectItem(accept, "maxAmountRequired");
    if (!j_amount) j_amount = cJSON_GetObjectItem(accept, "amount");
    if (j_amount && cJSON_IsString(j_amount))
        strncpy(pay_req.amount_str, j_amount->valuestring, sizeof(pay_req.amount_str) - 1);
    else if (j_amount && cJSON_IsNumber(j_amount))
        snprintf(pay_req.amount_str, sizeof(pay_req.amount_str), "%lld", (long long)j_amount->valuedouble);
    printf(", Amount: %s\n", pay_req.amount_str);

    cJSON *j_payTo = cJSON_GetObjectItem(accept, "payTo");
    if (j_payTo && cJSON_IsString(j_payTo)) {
        size_t dummy;
        boat_hex_to_bin(j_payTo->valuestring, pay_req.pay_to, 20, &dummy);
        strncpy(pay_req.pay_to_hex, j_payTo->valuestring, sizeof(pay_req.pay_to_hex) - 1);
    }

    cJSON *j_asset = cJSON_GetObjectItem(accept, "asset");
    if (j_asset && cJSON_IsString(j_asset)) {
        size_t dummy;
        boat_hex_to_bin(j_asset->valuestring, pay_req.asset, 20, &dummy);
        strncpy(pay_req.asset_hex, j_asset->valuestring, sizeof(pay_req.asset_hex) - 1);
    }

    cJSON *j_timeout = cJSON_GetObjectItem(accept, "maxTimeoutSeconds");
    if (j_timeout) pay_req.max_timeout = (uint32_t)j_timeout->valueint;

    strncpy(pay_req.resource_url, SUBMIT_ENDPOINT, sizeof(pay_req.resource_url) - 1);

    /* Extra fields for EIP-712 domain */
    cJSON *j_extra = cJSON_GetObjectItem(accept, "extra");
    if (j_extra) {
        cJSON *ename = cJSON_GetObjectItem(j_extra, "name");
        if (ename && cJSON_IsString(ename))
            strncpy(pay_req.asset_name, ename->valuestring, sizeof(pay_req.asset_name) - 1);
        cJSON *eversion = cJSON_GetObjectItem(j_extra, "version");
        if (eversion && cJSON_IsString(eversion))
            strncpy(pay_req.asset_version, eversion->valuestring, sizeof(pay_req.asset_version) - 1);
        cJSON *econtract = cJSON_GetObjectItem(j_extra, "verifyingContract");
        if (econtract && cJSON_IsString(econtract)) {
            size_t dummy;
            if (boat_hex_to_bin(econtract->valuestring, pay_req.verifying_contract, 20, &dummy) == BOAT_SUCCESS
                && dummy == 20) {
                pay_req.has_verifying_contract = true;
            }
        }
    }

    cJSON_Delete(pay_root);

    /* Parse chain_id from network string (e.g. "eip155:84532" or "eip155:5042002") */
    uint64_t chain_id = 0;
    const char *colon = strchr(pay_req.network, ':');
    if (colon) chain_id = (uint64_t)strtoull(colon + 1, NULL, 10);

    BoatEvmChainConfig chain_cfg = { .chain_id = chain_id, .rpc_url = "", .eip1559 = false };

    /* Sign payment using BoAT4 */
    printf("  Signing x402 payment...\n");
    char *payment_b64 = NULL;
    BoatResult br = boat_x402_make_payment(&pay_req, wallet_key, &chain_cfg, &payment_b64);
    if (br != BOAT_SUCCESS) {
        printf("  Error: x402 payment signing failed (%d)\n", br);
        free(body_str);
        return -1;
    }

    /* Retry with payment signature */
    printf("  Retrying with payment signature...\n");
    char pay_hdr[8192];
    snprintf(pay_hdr, sizeof(pay_hdr), "PAYMENT-SIGNATURE: %s", payment_b64);

    const char *headers2[] = { pay_hdr };
    HttpResponse *resp2 = http_response_new();
    long http_code2 = 0;
    rc = http_post(SUBMIT_ENDPOINT, body_str, headers2, 1, resp2, &http_code2);
    free(body_str);
    boat_free(payment_b64);

    if (rc != 0) {
        http_response_free(resp2);
        return -1;
    }

    /* Check PAYMENT-RESPONSE header */
    if (resp2->payment_response[0]) {
        uint8_t decoded[4096];
        size_t dlen = base64_decode(resp2->payment_response, decoded, sizeof(decoded));
        if (dlen > 0) {
            decoded[dlen] = '\0';
            cJSON *pr = cJSON_Parse((const char *)decoded);
            if (pr) {
                cJSON *success = cJSON_GetObjectItem(pr, "success");
                cJSON *tx = cJSON_GetObjectItem(pr, "transaction");
                printf("  Payment: success=%s, tx=%s\n",
                       (success && cJSON_IsTrue(success)) ? "true" : "false",
                       (tx && cJSON_IsString(tx)) ? tx->valuestring : "N/A");
                cJSON_Delete(pr);
            }
        }
    }

    if (http_code2 >= 200 && http_code2 <= 202) {
        cJSON *result = cJSON_Parse(resp2->data);
        if (result) {
            cJSON *h = cJSON_GetObjectItem(result, "hash");
            printf("  Accepted! Hash: %s\n",
                   (h && cJSON_IsString(h)) ? h->valuestring : content_hash);
            cJSON_Delete(result);
        }
        if (!is_activated) {
            mark_device_activated();
            printf("  Device activated!\n");
        }
        http_response_free(resp2);
        return 0;
    } else {
        printf("  Failed: %ld\n", http_code2);
        printf("  Response: %s\n", resp2->data);
        http_response_free(resp2);
        return -1;
    }
}


/* --- Main --- */
int main(int argc, char *argv[])
{
    bool dry_run = false;
    const char *api_key = getenv(API_KEY_ENV);

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = true;
        } else if (strcmp(argv[i], "--api-key") == 0 && i + 1 < argc) {
            api_key = argv[++i];
        } else if (strncmp(argv[i], "--api-key=", 10) == 0) {
            api_key = argv[i] + 10;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: boat-attest-c [--dry-run] [--api-key KEY]\n");
            printf("  --dry-run    Collect and hash metrics without submitting\n");
            printf("  --api-key    Use API key auth instead of x402\n");
            printf("               (or set HASHANCHOR_API_KEY env var)\n");
            return 0;
        }
    }

    /* Initialize BoAT4 PAL (sets up curl-based HTTP ops) */
    boat_pal_linux_init();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    printf("==================================================\n");
    printf("BoAT Attestor (C) - System Metrics Attestation\n");
    printf("==================================================\n");

    /* Device ID */
    char device_id[128];
    if (get_device_id(device_id, sizeof(device_id)) != 0) {
        fprintf(stderr, "Error: cannot determine device ID\n");
        return 1;
    }
    printf("\nDevice ID: %s\n", device_id);

    /* Load device signing key */
    printf("\n[1/4] Loading device key...\n");
    uint8_t sk[64], pk[32];
    bool is_activated = false;
    if (load_or_create_device_key(sk, pk, &is_activated) != 0) {
        fprintf(stderr, "Error: cannot load/create device key\n");
        return 1;
    }
    printf("  Status: %s\n", is_activated ? "active" : "pending (will activate on first submit)");

    /* Collect system stats */
    printf("\n[2/4] Collecting system metrics...\n");
    cJSON *stats = NULL;
    if (get_system_stats(&stats) != 0) {
        fprintf(stderr, "Error: cannot collect system stats\n");
        return 1;
    }

    /* Print sorted JSON (cJSON sorts by insertion order, we inserted in sorted order) */
    char *data_json = cJSON_PrintUnformatted(stats);

    char content_hash[68];
    sha256_hex(data_json, strlen(data_json), content_hash);

    cJSON *mem = cJSON_GetObjectItem(stats, "memory");
    if (mem) {
        double total = cJSON_GetObjectItem(mem, "total_kb")->valuedouble;
        double used = cJSON_GetObjectItem(mem, "used_kb")->valuedouble;
        double pct = total > 0 ? (used / total * 100.0) : 0;
        printf("  Memory: %.0fKB / %.0fKB (%.1f%% used)\n", used, total, pct);
    }
    cJSON *la = cJSON_GetObjectItem(stats, "loadavg");
    if (la) {
        printf("  Load avg: %.2f, %.2f, %.2f\n",
               cJSON_GetObjectItem(la, "1min")->valuedouble,
               cJSON_GetObjectItem(la, "5min")->valuedouble,
               cJSON_GetObjectItem(la, "15min")->valuedouble);
    }
    cJSON *cpu = cJSON_GetObjectItem(stats, "cpu");
    if (cpu) {
        printf("  CPU ticks: %.0f busy / %.0f total\n",
               cJSON_GetObjectItem(cpu, "busy_ticks")->valuedouble,
               cJSON_GetObjectItem(cpu, "total_ticks")->valuedouble);
    }
    printf("  Data hash: %s\n", content_hash);

    cJSON_Delete(stats);

    if (dry_run) {
        printf("\n[dry-run] Skipping submit. Data that would be attested:\n");
        printf("  %s\n", data_json);
        free(data_json);
        return 0;
    }

    BoatKey *wallet_key = NULL;
    if (api_key && api_key[0]) {
        printf("\n[3/4] Using API key authentication...\n");
    } else {
        printf("\n[3/4] Loading wallet...\n");
        if (load_or_create_wallet(&wallet_key) != 0) {
            fprintf(stderr, "Error: cannot load/create wallet\n");
            free(data_json);
            return 1;
        }
    }

    /* Submit */
    printf("\n[4/4] Submitting to HashAnchor...\n");
    int result = submit_signed(data_json, device_id, sk, pk, is_activated,
                               wallet_key, api_key);
    free(data_json);

    if (wallet_key) boat_key_free(wallet_key);

    if (result == 0) {
        printf("\nAttestation complete!\n");
        printf("  Verify at: %s/%s\n", VERIFY_ENDPOINT, content_hash);
        return 0;
    } else {
        printf("\nAttestation failed.\n");
        return 1;
    }
}
