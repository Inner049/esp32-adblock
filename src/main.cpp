// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Commercial version: WiFi setup wizard, factory reset, configurable DNS,
// DNS benchmark, tri-language UI (UK/RU/EN).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include <Arduino.h>
#include <ArduinoOTA.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <Update.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <esp_wifi.h>
#include <lwip/dns.h>
#include <sntp.h>
#include <time.h>

// ---- remote management defaults ----
#define FW_VERSION 128
#define DEFAULT_FIREBASE_URL                                                   \
  "https://esp-adblock-default-rtdb.europe-west1.firebasedatabase.app/"
#define FIREBASE_SECRET "gXBgqzEGZEvLC1ARnoMKxCHpEQoPVAx5cPXg9PUy"
#define DEFAULT_BLOCKLIST_URL                                                  \
  "https://inner049.github.io/esp32-adblock/blocklist.bin"
#define DEFAULT_FW_UPDATE_URL "https://inner049.github.io/esp32-adblock/ota/"

// ---- hardware ----
static const int BOOT_PIN = 9; // GPIO 9 — BOOT button on SuperMini
static const int LED_PIN = 8;  // GPIO 8 — built-in LED (active LOW)

// ---- config ----
static const uint16_t DNS_PORT = 53;
static const char *BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// ---- mode ----
enum DeviceMode { MODE_SETUP, MODE_MAIN };
DeviceMode deviceMode = MODE_SETUP;
bool servicesStarted = false;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
Preferences prefs;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint32_t last_fw_ts = 0;
uint32_t last_list_ts = 0;
bool pendingFwTsSave = false;
bool licenseActive = true;
uint8_t buf[1200];
SemaphoreHandle_t blocklistMutex;

static void sendUdpPacket(WiFiUDP &udp) {
  int retries = 5;
  while (retries > 0) {
    if (udp.endPacket() == 1) return;
    retries--;
    if (retries > 0) delay(2);
  }
  Serial.println("[DNS] ERROR: endPacket() failed after retries (ENOMEM)");
}

uint64_t *sparseIndex = nullptr;
size_t sparseCount = 0;

static void buildSparseIndex() {
  if (sparseIndex) {
    free(sparseIndex);
    sparseIndex = nullptr;
  }
  if (numHashes == 0)
    return;

  sparseCount = numHashes / 128;
  if (numHashes % 128 != 0)
    sparseCount++;

  sparseIndex = (uint64_t *)malloc(sparseCount * sizeof(uint64_t));
  if (!sparseIndex) {
    Serial.println("Sparse index malloc failed!");
    return;
  }

  uint8_t b[HASH_BYTES];
  for (size_t i = 0; i < sparseCount; i++) {
    blocklist.seek(i * 128 * HASH_BYTES);
    blocklist.read(b, HASH_BYTES);
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) {
      v |= (uint64_t)b[k] << (8 * k);
    }
    sparseIndex[i] = v;
  }
  Serial.printf("Sparse index built: %u entries (%.1f KB)\n", sparseCount,
                (float)(sparseCount * 8) / 1024.0);
}

IPAddress upstreamDNS(9, 9, 9, 9); // configurable, saved in /dns.cfg
uint32_t dnsTimeoutMs = 700;       // configurable, saved in /dns.cfg
String currentLang = "en";         // uk | ru | en, saved in /lang.cfg

#define MAX_PENDING 256
struct PendingReq {
  uint16_t upstreamTid;
  uint16_t clientTid;
  IPAddress clientIp;
  uint16_t clientPort;
  uint32_t timestamp;
  uint64_t domain_hash;
  uint16_t qtype;
  bool active;
};
PendingReq pendingReqs[MAX_PENDING];
uint16_t nextUpstreamTid = 1;

#define DNS_CACHE_SIZE 128
struct DnsCacheEntry {
  uint64_t hash;
  uint16_t qtype;
  uint32_t expire_ts;
  uint8_t pkt[128];
  int pkt_len;
  bool active;
};
DnsCacheEntry dnsCache[DNS_CACHE_SIZE];
int next_cache_slot = 0;

#define QLOG_SIZE 50
struct QueryLog {
  uint32_t ts;
  char dom[64];
  uint32_t ip;
  uint8_t status; // 0=Allowed, 1=Blocked, 2=Whitelisted, 3=Cached
};
QueryLog qLog[QLOG_SIZE];
int qLogIdx = 0;
static void logQuery(const char *domain, uint32_t ip, uint8_t status) {
  int i = qLogIdx;
  qLogIdx = (qLogIdx + 1) % QLOG_SIZE;
  qLog[i].ts = millis() / 1000;
  if (qLog[i].ts == 0) qLog[i].ts = 1; // ensure not 0
  strncpy(qLog[i].dom, domain, 63);
  qLog[i].dom[63] = 0;
  qLog[i].ip = ip;
  qLog[i].status = status;
}

String cfgSSID, cfgPass; // loaded from /wifi.cfg

struct Dev {
  uint32_t ip;
  uint8_t mac[6];
  uint32_t blocked, allowed, lastSeen;
  bool banned;
  String label;
};
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS];
int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM];
uint64_t customHash[MAX_CUSTOM];
int numCustom = 0;

String allowDom[MAX_CUSTOM];
uint64_t allowHash[MAX_CUSTOM];
int numAllow = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN];
int numBanned = 0;

// remote blocklist auto-update
String updateUrl = DEFAULT_BLOCKLIST_URL;
uint32_t updateIntervalH = 24;
uint32_t lastCheckMs = 0;
uint32_t lastTelemetryMs = 0;
uint32_t lastCmdCheckMs = 0;
uint32_t lastFwCheckMs = 0;
String updateStatus = "never";

// cloud telemetry
String firebaseDbUrl = DEFAULT_FIREBASE_URL;

// pull OTA
String fwUpdateUrl = DEFAULT_FW_UPDATE_URL;

// external IP
String extIP = "";

// Action status for UI
String actionStatus = "Booted";

static void fetchExternalIP() {
  if (WiFi.status() != WL_CONNECTED)
    return;
  HTTPClient http;
  http.setTimeout(3000);
  if (http.begin("http://api.ipify.org")) {
    int code = http.GET();
    if (code == 200) {
      extIP = http.getString();
      extIP.trim();
    }
    http.end();
  }
}

static void pushTelemetry() {
  if (firebaseDbUrl.length() == 0)
    return;
  String url = firebaseDbUrl;
  if (!url.endsWith("/"))
    url += "/";
  String mac = WiFi.macAddress();
  mac.replace(":", "");
  url += "devices/" + mac + ".json";
  if (String(FIREBASE_SECRET).length() > 0)
    url += "?auth=" + String(FIREBASE_SECRET);

  if (extIP == "") {
    fetchExternalIP();
  }

  String payload =
      "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"ext_ip\":\"" + extIP +
      "\",\"uptime\":" + String(millis() / 1000) +
      ",\"blocked\":" + String(totalBlocked) +
      ",\"allowed\":" + String(totalAllowed) +
      ",\"domains\":" + String(numHashes) +
      ",\"heap\":" + String(ESP.getFreeHeap()) + ",\"fw_version\":\"" +
      String(FW_VERSION) + "\"," + "\"last_fw_ts\":" + String(last_fw_ts) +
      "," + "\"last_list_ts\":" + String(last_list_ts) + "," +
      "\"status_msg\":\"" + actionStatus + "\"" +
      ",\"lastSeen\": { \".sv\": \"timestamp\" }}";

  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  if (firebaseDbUrl.startsWith("https"))
    http.begin(client, url);
  else
    http.begin(url);

  http.addHeader("Content-Type", "application/json");
  http.PATCH(payload);
  http.end();
}

// ========== hashing / matching ==========
static uint64_t fnv40(const char *s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint8_t)s[i];
    h *= 0x100000001b3ULL;
  }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  if (!blocklist || numHashes == 0)
    return false;

  uint32_t start_idx = 0;
  uint32_t end_idx = numHashes - 1;

  if (sparseIndex && sparseCount > 0) {
    if (h < sparseIndex[0])
      return false;

    int32_t L_s = 0;
    int32_t R_s = sparseCount - 1;
    uint32_t best_block = 0;

    while (L_s <= R_s) {
      int32_t m_s = L_s + (R_s - L_s) / 2;
      uint64_t v_s = sparseIndex[m_s];
      if (v_s == h)
        return true;
      if (v_s < h) {
        best_block = m_s;
        L_s = m_s + 1;
      } else {
        if (m_s == 0)
          break;
        R_s = m_s - 1;
      }
    }
    start_idx = best_block * 128;
    end_idx = start_idx + 127;
    if (end_idx >= numHashes)
      end_idx = numHashes - 1;
  }

  uint32_t count = end_idx - start_idx + 1;
  if (count == 0)
    return false;

  uint32_t bytes_to_read = count * HASH_BYTES;
  uint8_t fbuf[640];

  blocklist.seek(start_idx * HASH_BYTES);
  size_t read_bytes = blocklist.read(fbuf, bytes_to_read);
  if (read_bytes != bytes_to_read)
    return false;

  int32_t L = 0;
  int32_t R = count - 1;
  while (L <= R) {
    int32_t m = L + (R - L) / 2;
    uint32_t offset = m * HASH_BYTES;
    uint64_t v = 0;
    for (int i = 0; i < HASH_BYTES; i++) {
      v |= (uint64_t)fbuf[offset + i] << (8 * i);
    }
    if (v == h)
      return true;
    if (v < h)
      L = m + 1;
    else {
      if (m == 0)
        break;
      R = m - 1;
    }
  }
  return false;
}
static bool inCustom(uint64_t h) {
  for (int i = 0; i < numCustom; i++)
    if (customHash[i] == h)
      return true;
  return false;
}
static bool inAllow(uint64_t h) {
  for (int i = 0; i < numAllow; i++)
    if (allowHash[i] == h)
      return true;
  return false;
}
static bool isWhitelisted(const char *domain) {
  const char *p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inAllow(h))
      return true;
    const char *dot = strchr(p, '.');
    if (!dot)
      break;
    const char *next = dot + 1;
    if (!strchr(next, '.'))
      break;
    p = next;
  }
  return false;
}

static bool isBlocked(const char *domain) {
  xSemaphoreTake(blocklistMutex, portMAX_DELAY);
  const char *p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inFlash(h) || inCustom(h)) {
      xSemaphoreGive(blocklistMutex);
      return true;
    }
    const char *dot = strchr(p, '.');
    if (!dot)
      break;
    const char *next = dot + 1;
    if (!strchr(next, '.'))
      break;
    p = next;
  }
  xSemaphoreGive(blocklistMutex);
  return false;
}

// ========== persistence ==========
static void loadAllow() {
  numAllow = 0;
  File f = LittleFS.open("/allow.txt", "r");
  if (!f) return;
  while (f.available() && numAllow < MAX_CUSTOM) {
    String l = f.readStringUntil('\n');
    l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) {
      allowDom[numAllow] = l;
      allowHash[numAllow] = fnv40(l.c_str(), l.length());
      numAllow++;
    }
  }
  f.close();
}
static void saveAllow() {
  File f = LittleFS.open("/allow.txt", "w");
  if (!f) return;
  for (int i = 0; i < numAllow; i++) f.println(allowDom[i]);
  f.close();
}
static bool addAllow(String d) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numAllow >= MAX_CUSTOM) return false;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) return false;
  allowDom[numAllow] = d;
  allowHash[numAllow] = fnv40(d.c_str(), d.length());
  numAllow++;
  saveAllow();
  memset(dnsCache, 0, sizeof(dnsCache));
  return true;
}
static void removeAllow(String d) {
  d.toLowerCase();
  for (int i = 0; i < numAllow; i++)
    if (allowDom[i] == d) {
      for (int j = i; j < numAllow - 1; j++) {
        allowDom[j] = allowDom[j + 1];
        allowHash[j] = allowHash[j + 1];
      }
      numAllow--;
      saveAllow();
      memset(dnsCache, 0, sizeof(dnsCache));
      return;
    }
}

static void loadCustom() {
  numCustom = 0;
  File f = LittleFS.open("/custom.txt", "r");
  if (!f)
    return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n');
    l.trim();
    l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) {
      customDom[numCustom] = l;
      customHash[numCustom] = fnv40(l.c_str(), l.length());
      numCustom++;
    }
  }
  f.close();
}
static void saveCustom() {
  File f = LittleFS.open("/custom.txt", "w");
  if (!f)
    return;
  for (int i = 0; i < numCustom; i++)
    f.println(customDom[i]);
  f.close();
}
static bool addCustom(String d) {
  d.trim();
  d.toLowerCase();
  if (d.startsWith("www."))
    d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM)
    return false;
  for (int i = 0; i < numCustom; i++)
    if (customDom[i] == d)
      return false;
  customDom[numCustom] = d;
  customHash[numCustom] = fnv40(d.c_str(), d.length());
  numCustom++;
  saveCustom();
  memset(dnsCache, 0, sizeof(dnsCache));
  return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++)
    if (customDom[i] == d) {
      for (int j = i; j < numCustom - 1; j++) {
        customDom[j] = customDom[j + 1];
        customHash[j] = customHash[j + 1];
      }
      numCustom--;
      saveCustom();
      memset(dnsCache, 0, sizeof(dnsCache));
      return;
    }
}
static bool isBannedIP(uint32_t ip) {
  for (int i = 0; i < numBanned; i++)
    if (bannedIP[i] == ip)
      return true;
  return false;
}
static void loadBanned() {
  numBanned = 0;
  File f = LittleFS.open("/banned.txt", "r");
  if (!f)
    return;
  while (f.available() && numBanned < MAX_BAN) {
    String l = f.readStringUntil('\n');
    l.trim();
    IPAddress ip;
    if (l.length() && ip.fromString(l))
      bannedIP[numBanned++] = (uint32_t)ip;
  }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++)
    if (clients[i].banned)
      bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w");
  if (!f)
    return;
  for (int i = 0; i < numBanned; i++) {
    IPAddress ip(bannedIP[i]);
    f.println(ip.toString());
  }
  f.close();
}
static bool loadWifiCfg() {
  File f = LittleFS.open("/wifi.cfg", "r");
  if (!f)
    return false;
  cfgSSID = "";
  cfgPass = "";
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.startsWith("ssid="))
      cfgSSID = line.substring(5);
    else if (line.startsWith("pass="))
      cfgPass = line.substring(5);
  }
  f.close();
  return cfgSSID.length() > 0;
}
static void saveWifiCfg(const String &ssid, const String &pass) {
  File f = LittleFS.open("/wifi.cfg", "w");
  if (!f)
    return;
  f.println("ssid=" + ssid);
  f.println("pass=" + pass);
  f.close();
}
static void loadDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "r");
  if (!f)
    return;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.startsWith("upstream=")) {
      String ip = line.substring(9);
      ip.trim();
      upstreamDNS.fromString(ip);
    } else if (line.startsWith("timeout=")) {
      uint32_t t = line.substring(8).toInt();
      if (t >= 50 && t <= 5000)
        dnsTimeoutMs = t;
    }
  }
  f.close();
}
static void saveDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "w");
  if (!f)
    return;
  f.println("upstream=" + upstreamDNS.toString());
  f.println("timeout=" + String(dnsTimeoutMs));
  f.close();
}
static void loadLangCfg() {
  File f = LittleFS.open("/lang.cfg", "r");
  if (!f)
    return;
  String line = f.readStringUntil('\n');
  line.trim();
  if (line == "uk" || line == "ru" || line == "en")
    currentLang = line;
  f.close();
}
static void saveLangCfg() {
  File f = LittleFS.open("/lang.cfg", "w");
  if (f) {
    f.println(currentLang);
    f.close();
  }
}
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r");
  if (!f)
    return;
  updateUrl = f.readStringUntil('\n');
  updateUrl.trim();
  String iv = f.readStringUntil('\n');
  iv.trim();
  if (iv.length())
    updateIntervalH = iv.toInt();
  f.close();
  if (updateIntervalH < 1)
    updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w");
  if (!f)
    return;
  f.println(updateUrl);
  f.println(updateIntervalH);
  f.close();
}
static void loadCloudCfg() {
  File f = LittleFS.open("/cloud.cfg", "r");
  if (!f)
    return;
  firebaseDbUrl = f.readStringUntil('\n');
  firebaseDbUrl.trim();
  f.close();
}
static void saveCloudCfg() {
  File f = LittleFS.open("/cloud.cfg", "w");
  if (!f)
    return;
  f.println(firebaseDbUrl);
  f.close();
}

// ========== client table ==========
static void getMac(uint32_t ip, uint8_t *mac) {
  memset(mac, 0, 6);
  ip4_addr_t ipa;
  ipa.addr = ip;
  struct eth_addr *eth = nullptr;
  const ip4_addr_t *ipret = nullptr;
  for (struct netif *nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) {
      memcpy(mac, eth->addr, 6);
      return;
    }
}
static Dev *getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++)
    if (clients[i].ip == ip) {
      clients[i].lastSeen = millis();
      return &clients[i];
    }
  if (numClients < MAX_CLIENTS) {
    Dev *c = &clients[numClients++];
    c->ip = ip;
    c->blocked = c->allowed = 0;
    c->lastSeen = millis();
    c->banned = isBannedIP(ip);
    c->label = "";
    getMac(ip, c->mac);
    return c;
  }
  return nullptr;
}

// ========== DNS ==========
static size_t parseQuery(const uint8_t *pkt, int len, char *out,
                         uint16_t *qtype, int *qend) {
  if (len < 13)
    return 0;
  int i = 12;
  size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0)
      break;
    if (l & 0xC0)
      return 0;
    if (o + l + 1 >= 250 || i + l > len)
      return 0;
    if (o)
      out[o++] = '.';
    for (uint8_t k = 0; k < l; k++)
      out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len)
    return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) {
    memmove(out, out + 4, o - 3);
    o -= 4;
  }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81;
  buf[3] = 0x83; // NXDOMAIN (fixes timeouts for AAAA/HTTPS queries)
  buf[6] = 0;
  buf[7] = 0;
  buf[8] = 0;
  buf[9] = 0;
  buf[10] = 0;
  buf[11] = 0;
  return qend;
}
static void forwardUpstreamAsync(int qlen, IPAddress cip, uint16_t cport,
                                 uint64_t dhash, uint16_t qtype) {
  static int last_slot = 0;
  int slot = -1;
  int active_count = 0;
  uint32_t now = millis();
  for (int i = 0; i < MAX_PENDING; i++) {
    if (pendingReqs[i].active) active_count++;
    int idx = (last_slot + i) % MAX_PENDING;
    if (slot == -1 && (!pendingReqs[idx].active ||
        (now - pendingReqs[idx].timestamp > dnsTimeoutMs))) {
      slot = idx;
      last_slot = (idx + 1) % MAX_PENDING;
    }
  }
  if (slot == -1) {
    Serial.printf("[DNS] ERROR: Queue FULL! (depth: %d/%d) Dropped forward for dhash %llu\n", active_count, MAX_PENDING, dhash);
    return;
  }

  uint16_t cTid = (buf[0] << 8) | buf[1];
  uint16_t uTid = nextUpstreamTid++;
  if (nextUpstreamTid == 0)
    nextUpstreamTid = 1;

  pendingReqs[slot].upstreamTid = uTid;
  pendingReqs[slot].clientTid = cTid;
  pendingReqs[slot].clientIp = cip;
  pendingReqs[slot].clientPort = cport;
  pendingReqs[slot].timestamp = now;
  pendingReqs[slot].domain_hash = dhash;
  pendingReqs[slot].qtype = qtype;
  pendingReqs[slot].active = true;

  buf[0] = uTid >> 8;
  buf[1] = uTid & 0xFF;

  upstreamCli.beginPacket(upstreamDNS, 53);
  upstreamCli.write(buf, qlen);
  sendUdpPacket(upstreamCli);
  Serial.printf("[DNS] -> Forwarded dhash %llu (type %d) to upstream (uTid: %d, slot: %d, q_depth: %d/%d)\n", dhash, qtype, uTid, slot, active_count + 1, MAX_PENDING);
}

static void handleUpstreamDns() {
  int usz;
  while ((usz = upstreamCli.parsePacket()) > 0) {
    int rlen = upstreamCli.read(buf, sizeof(buf));
    if (rlen >= 2) {
      uint16_t uTid = (buf[0] << 8) | buf[1];
      bool found = false;
      for (int i = 0; i < MAX_PENDING; i++) {
        if (pendingReqs[i].active && pendingReqs[i].upstreamTid == uTid) {
          found = true;
          uint32_t latency = millis() - pendingReqs[i].timestamp;
          Serial.printf("[DNS] <- Received upstream response (uTid: %d, rlen: %d) for slot %d (Latency: %u ms)\n", uTid, rlen, i, latency);

          if (rlen <= 128 && pendingReqs[i].domain_hash != 0) {
            int c_slot = next_cache_slot++;
            if (next_cache_slot >= DNS_CACHE_SIZE)
              next_cache_slot = 0;
            dnsCache[c_slot].hash = pendingReqs[i].domain_hash;
            dnsCache[c_slot].qtype = pendingReqs[i].qtype;
            dnsCache[c_slot].expire_ts = millis() + 30000;
            memcpy(dnsCache[c_slot].pkt, buf, rlen);
            dnsCache[c_slot].pkt_len = rlen;
            dnsCache[c_slot].active = true;
          }

          buf[0] = pendingReqs[i].clientTid >> 8;
          buf[1] = pendingReqs[i].clientTid & 0xFF;
          dnsServer.beginPacket(pendingReqs[i].clientIp,
                                pendingReqs[i].clientPort);
          dnsServer.write(buf, rlen);
          sendUdpPacket(dnsServer);
          pendingReqs[i].active = false;
          break;
        }
      }
      if (!found) {
        Serial.printf("[DNS] <- Received upstream response (uTid: %d, rlen: %d) but NO ACTIVE SLOT FOUND (timeout?)\n", uTid, rlen);
      }
    }
  }
}
static void handleDns() {
  int sz;
  while ((sz = dnsServer.parsePacket()) > 0) {
    IPAddress cip = dnsServer.remoteIP();
    uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf));
    if (qlen < 13) {
      Serial.printf("[DNS] Malformed request (qlen: %d) from %s\n", qlen, cip.toString().c_str());
      continue;
    }
    char domain[256];
    uint16_t qtype = 0;
    int qend = qlen;
    uint32_t start_m = micros();
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev *c = getClient((uint32_t)cip);

    uint64_t dhash = 0;
    if (dl > 0) {
      dhash = fnv40(domain, dl);
      Serial.printf("\n[DNS] Req: %s (type %d) from %s\n", domain, qtype, cip.toString().c_str());
    } else {
      Serial.printf("\n[DNS] Req: <empty/unparsable> (type %d) from %s\n", qtype, cip.toString().c_str());
    }
    bool cached = false;
    uint32_t now = millis();

    // 1. FAST PATH: Check RAM Cache First!
    if (dhash != 0) {
      for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (dnsCache[i].active && dnsCache[i].hash == dhash &&
            dnsCache[i].qtype == qtype) {
          if (now > dnsCache[i].expire_ts) {
            dnsCache[i].active = false;
          } else {
            uint16_t cTid = (buf[0] << 8) | buf[1];
            memcpy(buf, dnsCache[i].pkt, dnsCache[i].pkt_len);
            buf[0] = cTid >> 8;
            buf[1] = cTid & 0xFF;
            dnsServer.beginPacket(cip, cport);
            dnsServer.write(buf, dnsCache[i].pkt_len);
            sendUdpPacket(dnsServer);
            cached = true;
            if (dl > 0) logQuery(domain, (uint32_t)cip, 3);
            uint32_t took = micros() - start_m;
            Serial.printf("[DNS] -> CACHE HIT! Sent %d bytes back (Lookup took %u us).\n", dnsCache[i].pkt_len, took);
            break;
          }
        }
      }
    }

    // 2. SLOW PATH: If not in cache, check Flash Blocklist or Forward
    if (!cached) {
      bool ban = c && c->banned;
      bool whitelisted = dl && isWhitelisted(domain);
      bool blocked = ban || (!whitelisted && dl && isBlocked(domain));
      if (!licenseActive) blocked = false;

      // NEVER block internal requests from the board itself (OTA/Telemetry)
      if (cip == WiFi.localIP()) {
        blocked = false;
      }

      if (blocked) {
        int rlen = buildBlocked(qend, qtype);
        totalBlocked++;
        if (c)
          c->blocked++;
        if (dl > 0) logQuery(domain, (uint32_t)cip, 1);

        if (rlen > 0) {
          uint32_t took = micros() - start_m;
          Serial.printf("[DNS] -> BLOCKED! Sent %d bytes back (Lookup took %u us).\n", rlen, took);
          // Cache this blocked response to answer instantly next time!
          if (rlen <= 128 && dhash != 0) {
            int c_slot = next_cache_slot++;
            if (next_cache_slot >= DNS_CACHE_SIZE)
              next_cache_slot = 0;
            dnsCache[c_slot].hash = dhash;
            dnsCache[c_slot].qtype = qtype;
            dnsCache[c_slot].expire_ts = now + 300000; // 5 min TTL
            memcpy(dnsCache[c_slot].pkt, buf, rlen);
            dnsCache[c_slot].pkt_len = rlen;
            dnsCache[c_slot].active = true;
          }

          dnsServer.beginPacket(cip, cport);
          dnsServer.write(buf, rlen);
          sendUdpPacket(dnsServer);
        }
      } else {
        Serial.printf("[DNS] -> ALLOWED. Forwarding...\n");
        forwardUpstreamAsync(qlen, cip, cport, dhash, qtype);
        totalAllowed++;
        if (c)
          c->allowed++;
        if (dl > 0) logQuery(domain, (uint32_t)cip, whitelisted ? 2 : 0);
      }
    }
  }
}

// AP captive portal DNS: answer every A query with 192.168.4.1
static void handleApDns() {
  int sz;
  while ((sz = dnsServer.parsePacket()) > 0) {
    IPAddress cip = dnsServer.remoteIP();
    uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf));
    if (qlen < 13)
      continue;
    char domain[256];
    uint16_t qtype = 0;
    int qend = qlen;
    if (parseQuery(buf, qlen, domain, &qtype, &qend) == 0)
      continue;
    buf[2] = 0x81;
    buf[3] = 0x80;
    buf[6] = 0;
    buf[7] = (qtype == 1) ? 1 : 0;
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0;
    int rlen = qend;
    if (qtype == 1) {
      const uint8_t ans[] = {0xC0, 0x0C, 0, 1, 0,   1,   0, 0,
                             0,    60,   0, 4, 192, 168, 4, 1};
      memcpy(buf + qend, ans, sizeof(ans));
      rlen = qend + sizeof(ans);
    }
    dnsServer.beginPacket(cip, cport);
    dnsServer.write(buf, rlen);
    sendUdpPacket(dnsServer);
  }
}

// ========== web helpers ==========
static String macStr(const uint8_t *m) {
  char s[18];
  snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2],
           m[3], m[4], m[5]);
  return String(s);
}
static String jesc(const String &s) {
  String o;
  for (char ch : s) {
    if (ch == '"' || ch == '\\')
      o += '\\';
    o += ch;
  }
  return o;
}

const char SETUP_PAGE[] PROGMEM =
    R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>AdBlock Setup</title><style>
*{box-sizing:border-box}body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
h1{margin:0;font-size:18px}h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
.wrap{padding:16px;max-width:500px;margin:auto}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:12px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128;cursor:pointer}
input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:8px;width:100%;margin:4px 0 10px}
button{background:#238636;color:#fff;border:none;border-radius:6px;padding:10px 16px;cursor:pointer;font-size:14px;width:100%}
button:hover{background:#2ea043}
.lb{background:#21262d;color:#c9d1d9;border:1px solid #30363d;width:auto;padding:4px 8px;font-size:12px;border-radius:5px}
.lb:hover{background:#30363d}.lb.on{border-color:#58a6ff}
.sc{background:#21262d;color:#c9d1d9;border:1px solid #30363d;margin-bottom:14px}
.sc:hover{background:#30363d}
.sg{color:#3fb950}.lk{color:#8b949e;font-size:11px}
#st{display:block;margin-top:10px;color:#3fb950;font-size:13px;min-height:20px}
label{color:#8b949e;font-size:12px}
</style></head><body>
<header><h1 id=tt>🛡️ AdBlock Setup</h1><div>
<button class=lb onclick="sL('uk')">🇺🇦</button>
<button class=lb onclick="sL('ru')">🇷🇺</button>
<button class=lb onclick="sL('en')">🇬🇧</button>
</div></header><div class=wrap>
<h2 id=wh>WiFi Networks</h2>
<table><thead><tr><th id=hn>Network</th><th id=hs>Signal</th><th id=hc>Security</th></tr></thead><tbody id=wt></tbody></table>
<button class=sc onclick="scan()" id=sb>↻ Scan</button>
<h2 id=ch>Connect</h2>
<label id=sl>SSID</label><input id=ss>
<label id=pl>Password</label><input id=pw type=password>
<button onclick="go()" id=cb>Connect</button>
<span id=st></span>
</div><script>
const L={
uk:{tt:'🛡️ Налаштування AdBlock',wh:'WiFi Мережі',hn:'Мережа',hs:'Сигнал',hc:'Захист',
ch:'Підключення',sl:'SSID',pl:'Пароль',cb:'Підключити',sb:'↻ Сканувати',
sc:'Сканування...',sv:'Збережено! Перезавантаження...',op:'Відкрита'},
ru:{tt:'🛡️ Настройка AdBlock',wh:'WiFi Сети',hn:'Сеть',hs:'Сигнал',hc:'Защита',
ch:'Подключение',sl:'SSID',pl:'Пароль',cb:'Подключить',sb:'↻ Сканировать',
sc:'Сканирование...',sv:'Сохранено! Перезагрузка...',op:'Открытая'},
en:{tt:'🛡️ AdBlock Setup',wh:'WiFi Networks',hn:'Network',hs:'Signal',hc:'Security',
ch:'Connect',sl:'SSID',pl:'Password',cb:'Connect',sb:'↻ Scan',
sc:'Scanning...',sv:'Saved! Rebooting...',op:'Open'}
};
let lang='en',nets=[];
function t(k){return L[lang]&&L[lang][k]||L.en[k]||k}
function tr(){['tt','wh','hn','hs','hc','ch','sl','pl','cb','sb'].forEach(k=>{let e=document.getElementById(k);if(e)e.textContent=t(k)});
document.querySelectorAll('.lb').forEach((b,i)=>{b.classList.toggle('on',['uk','ru','en'][i]==lang)})}
function sig(r){return r>-50?'▂▄▆█':r>-60?'▂▄▆░':r>-70?'▂▄░░':'▂░░░'}
function show(){wt.innerHTML=nets.map(n=>`<tr onclick="ss.value='${n.s.replace(/'/g,"\\'")}';pw.focus()"><td>${n.s}</td><td><span class=sg>${sig(n.r)}</span> ${n.r}</td><td class=lk>${n.e?'🔒':t('op')}</td></tr>`).join('')||'<tr><td colspan=3 style=color:#8b949e>—</td></tr>'}
async function scan(){sb.textContent=t('sc');try{let r=await(await fetch('/scan.json')).json();lang=r.lang||'en';
let m={};(r.networks||[]).forEach(n=>{if(!n.ssid)return;if(!m[n.ssid]||n.rssi>m[n.ssid].r)m[n.ssid]={s:n.ssid,r:n.rssi,e:n.enc}});
nets=Object.values(m).sort((a,b)=>b.r-a.r);tr();show()}catch(e){sb.textContent='↻'}}
async function go(){if(!ss.value.trim())return;st.textContent=t('sv');
try{await fetch('/save?s='+encodeURIComponent(ss.value)+'&p='+encodeURIComponent(pw.value))}catch(e){}}
function sL(l){fetch('/setlang?l='+l).then(()=>{lang=l;tr();show()})}
scan();
</script></body></html>)HTML";

const char DASH_PAGE[] PROGMEM =
    R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
*{box-sizing:border-box}body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}
input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
.lb{font-size:12px;padding:3px 7px}.lb.on{border-color:#58a6ff}
.rst{background:#da3633;color:#fff;border-color:#da3633}.rst:hover{background:#b62324}
.bnc{color:#8b949e;font-size:12px;margin-top:6px;min-height:16px}
.hlp{color:#8b949e;font-size:12px;margin-bottom:18px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1><div>
<button class=lb onclick="sL('uk')">🇺🇦</button>
<button class=lb onclick="sL('ru')">🇷🇺</button>
<button class=lb onclick="sL('en')">🇬🇧</button>
</div></header><div class=wrap>
<div class=cards id=sys></div>
<h2 id=hCli></h2><table id=ct><thead><tr><th id=thCli></th><th>MAC</th><th id=thBlk></th><th id=thAlw></th><th></th></tr></thead><tbody></tbody></table>
<div style="display:flex;gap:20px;flex-wrap:wrap"><div style="flex:1;min-width:300px">
<h2 id=hCust></h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom() id=bBlk></button></div>
<table id=cl><tbody></tbody></table>
</div><div style="flex:1;min-width:300px">
<h2 id=hAlw></h2>
<div style=margin-bottom:8px><input id=adom placeholder="mail.example.com" size=30><button onclick=addAllow() id=bAlw></button></div>
<table id=al><tbody></tbody></table>
</div></div>

<h2 id=hLog></h2>
<table id=ql><tbody></tbody></table>

<h2 id=hDns></h2>
<div style=margin-bottom:6px>
<select id=dsel><option value="9.9.9.9">Quad9 (9.9.9.9)</option><option value="1.1.1.1">Cloudflare (1.1.1.1)</option><option value="8.8.8.8">Google (8.8.8.8)</option><option value="208.67.222.222">OpenDNS (208.67.222.222)</option></select>
<span id=tL style="color:#8b949e;font-size:12px;margin-left:8px"></span> <input id=dtout size=4 value=700> <span style="color:#8b949e;font-size:12px">ms</span>
<button onclick=setDns() id=bDn></button> <button onclick=bench() id=bBe></button> <button onclick=benchAll() id=bBA></button></div>
<div class=bnc id=bres></div>
<h2 id=hRst></h2>
<div class=hlp id=rstW></div>
<button class=rst onclick="if(confirm(t('rstC')))fetch('/factory-reset').then(()=>{location.reload()})" id=bRs></button>
</div><script>
const L={
uk:{
sB:'Заблоковано',sA:'Дозволено',sL:'Блоклист',sC:'Клієнти',sW:'WiFi',sT:'Темп',sR:'Вільна RAM',sU:'Аптайм',
hCli:'КЛІЄНТИ',thCli:'Клієнт',thBlk:'Заблок.',thAlw:'Дозвол.',banned:'ЗАБЛОК',ban:'Заблок',unban:'Розблок',
hCust:'ВЛАСНІ ЗАБЛОКОВАНІ ДОМЕНИ',bBlk:'Заблокувати',noCust:'поки немає',
hAlw:'ВЛАСНІ ДОЗВОЛЕНІ ДОМЕНИ',bAlw:'Дозволити',noAlw:'поки немає',
hLog:'ЖУРНАЛ ЗАПИТІВ (ОСТАННІ 50)',
stAlw:'Дозволено',stBlk:'Заблоковано',stWht:'Білий список',stCch:'Кеш',addB:'+ Блок',addW:'+ Білий',
hUp:'БЛОКЛИСТ — ЗАВАНТАЖЕННЯ',bUp:'Завантажити',upH:'зберіть blocklist.bin, потім завантажте сюди — без USB',
hRem:'БЛОКЛИСТ — АВТООНОВЛЕННЯ',bSv:'Зберегти',bFn:'Оновити зараз',
remH:'пристрій завантажує blocklist.bin за розкладом. останнє:',evL:'кожні',hL:'год',
hFw:'ПРОШИВКА — OTA',bFl:'Прошити',fwH:'завантажте firmware.bin — пристрій перевірить і перезавантажиться',
hDns:'НАЛАШТУВАННЯ DNS',bDn:'Змінити',bBe:'Тест',bBA:'Тест всіх',
hRst:'СКИДАННЯ',bRs:'Скинути налаштування',rstW:'WiFi та DNS будуть видалені. Пристрій перезавантажиться.',
rstC:'Скинути всі налаштування?',
fl:'прошивка',ul:'завантаження',rb:'✓ перезавантаження ~15с',uf:'✗ помилка',tst:'тестування...',dom:'доменів',tL:'Таймаут'
},
ru:{
sB:'Заблокировано',sA:'Разрешено',sL:'Блоклист',sC:'Клиенты',sW:'WiFi',sT:'Темп',sR:'Свободная RAM',sU:'Аптайм',
hCli:'КЛИЕНТЫ',thCli:'Клиент',thBlk:'Заблок.',thAlw:'Разреш.',banned:'ЗАБЛОК',ban:'Заблок',unban:'Разблок',
hCust:'СВОИ ЗАБЛОКИРОВАННЫЕ ДОМЕНЫ',bBlk:'Заблокировать',noCust:'пока нет',
hAlw:'СВОИ РАЗРЕШЕННЫЕ ДОМЕНЫ',bAlw:'Разрешить',noAlw:'пока нет',
hLog:'ЖУРНАЛ ЗАПРОСОВ (ПОСЛЕДНИЕ 50)',
stAlw:'Разрешено',stBlk:'Заблокировано',stWht:'Белый список',stCch:'Кэш',addB:'+ Блок',addW:'+ Белый',
hUp:'БЛОКЛИСТ — ЗАГРУЗКА',bUp:'Загрузить',upH:'соберите blocklist.bin, затем загрузите сюда — без USB',
hRem:'БЛОКЛИСТ — АВТООБНОВЛЕНИЕ',bSv:'Сохранить',bFn:'Обновить сейчас',
remH:'устройство загружает blocklist.bin по расписанию. последнее:',evL:'каждые',hL:'ч',
hFw:'ПРОШИВКА — OTA',bFl:'Прошить',fwH:'загрузите firmware.bin — устройство проверит и перезагрузится',
hDns:'НАСТРОЙКИ DNS',bDn:'Сменить',bBe:'Тест',bBA:'Тест всех',
hRst:'СБРОС',bRs:'Сбросить настройки',rstW:'WiFi и DNS будут удалены. Устройство перезагрузится.',
rstC:'Сбросить все настройки?',
fl:'прошивка',ul:'загрузка',rb:'✓ перезагрузка ~15с',uf:'✗ ошибка',tst:'тестирование...',dom:'доменов',tL:'Таймаут'
},
en:{
sB:'Total blocked',sA:'Total allowed',sL:'Blocklist',sC:'Clients',sW:'WiFi',sT:'Temp',sR:'Free RAM',sU:'Uptime',
hCli:'CLIENTS',thCli:'Client',thBlk:'Blocked',thAlw:'Allowed',banned:'BANNED',ban:'Ban',unban:'Unban',
hCust:'CUSTOM BLOCKED DOMAINS',bBlk:'Block domain',noCust:'none yet',
hAlw:'CUSTOM ALLOWED DOMAINS',bAlw:'Allow domain',noAlw:'none yet',
hLog:'QUERY LOG (LAST 50)',
stAlw:'Allowed',stBlk:'Blocked',stWht:'Whitelisted',stCch:'Cache',addB:'+ Block',addW:'+ Allow',
hUp:'BLOCKLIST — UPLOAD',bUp:'Upload',upH:'build blocklist.bin with tools/build_blocklist.py, then upload here — no USB',
hRem:'BLOCKLIST — REMOTE AUTO-UPDATE',bSv:'Save',bFn:'Fetch now',
remH:'device pulls blocklist.bin on a schedule. last:',evL:'every',hL:'h',
hFw:'FIRMWARE — OTA UPDATE',bFl:'Flash firmware',fwH:'upload firmware.bin — device verifies and reboots',
hDns:'DNS SETTINGS',bDn:'Change',bBe:'Benchmark',bBA:'Bench all',
hRst:'FACTORY RESET',bRs:'Reset settings',rstW:'WiFi and DNS settings will be deleted. Device will reboot.',
rstC:'Reset all settings?',
fl:'flashing',ul:'uploading',rb:'✓ rebooting ~15s',uf:'✗ failed',tst:'testing...',dom:'domains',tL:'Timeout'
}};
let lang='en';
function t(k){return L[lang]&&L[lang][k]||L.en[k]||k}
function fmt(n){return n.toLocaleString()}
function tr(){['hCli','thCli','thBlk','thAlw','hCust','bBlk','hAlw','bAlw','hLog','hDns','bDn','bBe','bBA','hRst','bRs'].forEach(k=>{
let e=document.getElementById(k);if(e)e.textContent=t(k)});
['rstW','tL'].forEach(k=>{let e=document.getElementById(k);if(e)e.textContent=t(k)});
document.querySelectorAll('.lb').forEach((b,i)=>{b.classList.toggle('on',['uk','ru','en'][i]==lang)})}
async function load(){let s=await(await fetch('/stats.json')).json();
if(s.lang){lang=s.lang;tr()}
host.textContent='@ '+s.ip;
sys.innerHTML=[[t('sB'),fmt(s.blocked),'b'],[t('sA'),fmt(s.allowed),'a'],[t('sL'),fmt(s.domains)+' '+t('dom'),''],[t('sC'),s.clients.length,''],[t('sW'),s.rssi+' dBm',''],[t('sT'),s.temp+' °C',''],[t('sR'),Math.round(s.heap/1024)+' KB',''],[t('sU'),s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>'+t('banned')+'</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban onclick="fetch('/ban?ip=${c.ip}').then(load)">${c.banned?t('unban'):t('ban')}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${d}</td><td style=text-align:right><button onclick="fetch('/unblock?d='+encodeURIComponent('${d}')).then(load)">✕</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>'+t('noCust')+'</td></tr>';
al.tBodies[0].innerHTML=s.allow.map(d=>`<tr><td>${d}</td><td style=text-align:right><button onclick="fetch('/unallow?d='+encodeURIComponent('${d}')).then(load)">✕</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>'+t('noAlw')+'</td></tr>';

if(document.activeElement!=dtout)dtout.value=s.dnstout||700;
if(s.dns){let f=false;for(let o of dsel.options)if(o.value==s.dns){f=true;break}
if(!f){let o=new Option('Custom ('+s.dns+')',s.dns);dsel.prepend(o)}
dsel.value=s.dns}}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d)).then(()=>{dom.value='';load()})}}
function addAllow(){let d=adom.value.trim();if(d){fetch('/addallow?d='+encodeURIComponent(d)).then(()=>{adom.value='';load()})}}
function aBlk(d){fetch('/addblock?d='+encodeURIComponent(d)).then(()=>{load();updL()})}
function aWht(d){fetch('/addallow?d='+encodeURIComponent(d)).then(()=>{load();updL()})}

function sL(l){fetch('/setlang?l='+l).then(()=>{lang=l;tr();load();updL()})}
function setDns(){fetch('/setdns?ip='+dsel.value+'&timeout='+(parseInt(dtout.value)||700)).then(load)}
function bench(){bres.textContent=t('tst');fetch('/benchmark?ip='+dsel.value).then(r=>r.json()).then(d=>{bres.textContent=dsel.value+': min='+d.min+'ms avg='+d.avg+'ms max='+d.max+'ms'}).catch(()=>{bres.textContent='error'})}
function benchAll(){bres.textContent=t('tst');fetch('/benchmarkall').then(r=>r.json()).then(d=>{bres.innerHTML=Object.entries(d).map(([k,v])=>k+': min='+v.min+'ms avg='+v.avg+'ms max='+v.max+'ms').join('<br>')}).catch(()=>{bres.textContent='error'})}

async function updL(){try{
let d=await(await fetch('/logs.json')).json();
let st=[['#8b949e',t('stAlw')],['#f85149',t('stBlk')],['#3fb950',t('stWht')],['#8b949e',t('stCch')]];
ql.tBodies[0].innerHTML=d.map(r=>`<tr><td style=color:#8b949e;width:40px>${r.ago}s</td><td style=color:#c9d1d9>${r.dom}</td><td style=color:#8b949e;font-size:11px>${r.ip}</td><td style="color:${st[r.st][0]}">${st[r.st][1]}</td><td style="text-align:right"><button style=margin-right:4px onclick="aBlk('${r.dom}')">${t('addB')}</button><button onclick="aWht('${r.dom}')">${t('addW')}</button></td></tr>`).join('');
}catch(e){}}

load();setInterval(load,3000);
updL();setInterval(updL,2000);
</script></body></html>)HTML";

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24];
  snprintf(ut, sizeof(ut), "%lud %luh %lum", up / 86400, (up % 86400) / 3600,
           (up % 3600) / 60);

  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "application/json", "");

  String j = "{\"ip\":\"" + WiFi.localIP().toString() +
             "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() +
             ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"lang\":\"" + currentLang + "\"" + ",\"dns\":\"" +
             upstreamDNS.toString() + "\"" +
             ",\"dnstout\":" + String(dnsTimeoutMs) + ",\"upurl\":\"" +
             jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH +
             ",\"upstat\":\"" + jesc(updateStatus) +
             "\",\"last_list_ts\":" + String(last_list_ts) + ",\"furl\":\"" +
             jesc(firebaseDbUrl) + "\"" + ",\"clients\":[";
  web.sendContent(j);

  for (int i = 0; i < numClients; i++) {
    Dev &c = clients[i];
    IPAddress ip(c.ip);
    j = (i ? "," : "");
    j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) +
         "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed +
         ",\"banned\":" + (c.banned ? "true" : "false") + "}";
    web.sendContent(j);
  }

  web.sendContent("],\"custom\":[");

  for (int i = 0; i < numCustom; i++) {
    j = (i ? "," : "");
    j += "\"" + jesc(customDom[i]) + "\"";
    web.sendContent(j);
  }

  web.sendContent("],\"allow\":[");

  for (int i = 0; i < numAllow; i++) {
    j = (i ? "," : "");
    j += "\"" + jesc(allowDom[i]) + "\"";
    web.sendContent(j);
  }

  web.sendContent("]}");
  web.sendContent("");
}
static void handleBan() {
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    Dev *c = getClient((uint32_t)ip);
    if (c) {
      c->banned = !c->banned;
      saveBanned();
    }
  }
  web.send(200, "text/plain", "ok");
}
static void handleSetLang() {
  String l = web.arg("l");
  l.trim();
  l.toLowerCase();
  if (l == "uk" || l == "ru" || l == "en") {
    currentLang = l;
    saveLangCfg();
  }
  web.send(200, "text/plain", "ok");
}
static void handleScanJson() {
  int n = WiFi.scanNetworks();
  String j = "{\"lang\":\"" + currentLang + "\",\"networks\":[";
  bool first = true;
  for (int i = 0; i < n; i++) {
    String ssid = WiFi.SSID(i);
    if (ssid.length() == 0)
      continue;
    if (!first)
      j += ",";
    first = false;
    j += "{\"ssid\":\"" + jesc(ssid) + "\",\"rssi\":" + WiFi.RSSI(i) +
         ",\"enc\":" +
         String(WiFi.encryptionType(i) != WIFI_AUTH_OPEN ? "true" : "false") +
         "}";
  }
  j += "]}";
  WiFi.scanDelete();
  web.send(200, "application/json", j);
}
static void handleSaveWifi() {
  String ssid = web.arg("s");
  ssid.trim();
  String pass = web.arg("p");
  if (ssid.length() == 0) {
    web.send(400, "text/plain", "empty ssid");
    return;
  }
  saveWifiCfg(ssid, pass);
  web.send(200, "text/plain", "ok");
  delay(1000);
  ESP.restart();
}
static void handleSetDns() {
  if (web.hasArg("ip")) {
    IPAddress dns;
    if (dns.fromString(web.arg("ip"))) {
      upstreamDNS = dns;
    }
  }
  if (web.hasArg("timeout")) {
    uint32_t t = web.arg("timeout").toInt();
    if (t >= 50 && t <= 5000)
      dnsTimeoutMs = t;
  }
  saveDnsCfg();
  web.send(200, "text/plain", "ok");
}
static void handleFactoryReset() {
  LittleFS.remove("/wifi.cfg");
  LittleFS.remove("/dns.cfg");
  LittleFS.remove("/lang.cfg");
  web.send(200, "text/plain", "ok");
  delay(500);
  ESP.restart();
}

// -- DNS benchmark --
static uint8_t benchQ[29] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 7,    'e',  'x',  'a',
                             'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
                             0,    0x00, 0x01, 0x00, 0x01};
static void doBenchmark(IPAddress dns, int count, uint32_t &outMin,
                        uint32_t &outAvg, uint32_t &outMax) {
  WiFiUDP bUdp;
  bUdp.begin(0);
  uint32_t minT = 99999, maxT = 0, sumT = 0;
  for (int i = 0; i < count; i++) {
    benchQ[0] = random(256);
    benchQ[1] = random(256);
    uint32_t t0 = micros();
    bUdp.beginPacket(dns, 53);
    bUdp.write(benchQ, 29);
    bUdp.endPacket();
    bool got = false;
    uint32_t deadline = millis() + 3000;
    while (millis() < deadline) {
      if (bUdp.parsePacket() > 0) {
        uint8_t tmp[64];
        bUdp.read(tmp, sizeof(tmp));
        uint32_t dt = (micros() - t0) / 1000;
        if (dt < minT)
          minT = dt;
        if (dt > maxT)
          maxT = dt;
        sumT += dt;
        got = true;
        break;
      }
      delay(1);
    }
    if (!got) {
      sumT += 3000;
      if (3000 > maxT)
        maxT = 3000;
    }
  }
  bUdp.stop();
  outMin = (minT == 99999) ? 0 : minT;
  outAvg = count > 0 ? sumT / count : 0;
  outMax = maxT;
}
static void handleBenchmark() {
  IPAddress dns;
  if (!dns.fromString(web.arg("ip"))) {
    web.send(400, "text/plain", "bad ip");
    return;
  }
  uint32_t mn, avg, mx;
  doBenchmark(dns, 15, mn, avg, mx);
  web.send(200, "application/json",
           "{\"min\":" + String(mn) + ",\"avg\":" + String(avg) +
               ",\"max\":" + String(mx) + "}");
}
static void handleBenchmarkAll() {
  const char *names[] = {"Quad9", "Cloudflare", "Google", "OpenDNS"};
  IPAddress ips[4] = {IPAddress(9, 9, 9, 9), IPAddress(1, 1, 1, 1),
                      IPAddress(8, 8, 8, 8), IPAddress(208, 67, 222, 222)};
  String j = "{";
  for (int s = 0; s < 4; s++) {
    uint32_t mn, avg, mx;
    doBenchmark(ips[s], 5, mn, avg, mx);
    if (s)
      j += ",";
    j += "\"" + String(names[s]) + "\":{\"min\":" + String(mn) +
         ",\"avg\":" + String(avg) + ",\"max\":" + String(mx) + "}";
  }
  j += "}";
  web.send(200, "application/json", j);
}

// ========== blocklist swap ==========
static void reopenBlocklist() {
  xSemaphoreTake(blocklistMutex, portMAX_DELAY);
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildSparseIndex();
  xSemaphoreGive(blocklistMutex);
}
static void beginBlocklistSwap() {
  xSemaphoreTake(blocklistMutex, portMAX_DELAY);
  if (blocklist)
    blocklist.close();
  numHashes = 0;
  xSemaphoreGive(blocklistMutex);
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0;
  if (f)
    f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;
  if (ok)
    LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else
    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

static bool upOk = false;
static File upFile;
static void handleUploadDone() {
  web.send(upOk ? 200 : 500, "text/plain", upOk ? "ok" : "rejected");
}
static void handleUpload() {
  HTTPUpload &u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    upOk = false;
    beginBlocklistSwap();
    upFile = LittleFS.open("/blocklist.new", "w");
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (upFile)
      upFile.write(u.buf, u.currentSize);
  } else if (u.status == UPLOAD_FILE_END) {
    if (upFile)
      upFile.close();
    upOk = commitNewBlocklist();
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (upFile)
      upFile.close();
    LittleFS.remove("/blocklist.new");
    reopenBlocklist();
  }
}

static String checkFirmwareUpdate() {
  if (!fwUpdateUrl.length())
    return "No FW URL set";
  Serial.println("[OTA] Checking for firmware update...");

  String verUrl = fwUpdateUrl;
  if (!verUrl.endsWith("/"))
    verUrl += "/";

  int remoteVer = -1;

  // Create a strict scope for the version check so RAM is freed!
  {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (http.begin(client, verUrl + "version.txt")) {
      int code = http.GET();
      if (code == HTTP_CODE_OK) {
        remoteVer = http.getString().toInt();
      }
      http.end();
    }
  } // `client` is destroyed here, freeing ~40KB of heap for the actual OTA
    // update!

  if (remoteVer > FW_VERSION) {
    Serial.printf("[OTA] New version %d found! Updating...\n", remoteVer);

    WiFiClientSecure otaClient;
    otaClient.setInsecure();

    httpUpdate.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    t_httpUpdate_return ret =
        httpUpdate.update(otaClient, verUrl + "firmware.bin");

    if (ret == HTTP_UPDATE_FAILED) {
      Serial.printf("HTTP_UPDATE_FAILED Error (%d): %s\n",
                    httpUpdate.getLastError(),
                    httpUpdate.getLastErrorString().c_str());
      return "FW Update Failed";
    }
    return "Updating...";
  } else if (remoteVer != -1) {
    Serial.println("[OTA] Up to date.");
    return "No new versions";
  } else {
    return "Check Failed (Network Error)";
  }
}

static bool fetchBlocklist(String url) {
  url.trim();
  if (!url.length()) {
    updateStatus = "no url set";
    return false;
  }
  WiFiClientSecure cs;
  cs.setInsecure();
  WiFiClient cl;
  HTTPClient http;
  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  if (!(url.startsWith("https") ? http.begin(cs, url) : http.begin(cl, url))) {
    updateStatus = "begin failed";
    return false;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end();
    updateStatus = "HTTP " + String(code);
    return false;
  }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) {
    http.end();
    updateStatus = "fs open failed";
    reopenBlocklist();
    return false;
  }
  WiFiClient *stream = http.getStreamPtr();
  int len = http.getSize();
  uint8_t b[1024];
  size_t total = 0;
  uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) {
      int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) {
        f.write(b, n);
        total += n;
        idle = millis();
      }
    } else {
      if (millis() - idle > 15000)
        break;
      delay(2);
    }
  }
  f.close();
  http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains")
                    : ("bad data (" + String(total) + "B)");
  return ok;
}

static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok" : "failed");
  if (ok) {
    delay(300);
    ESP.restart();
  }
}
static void handleFwUpload() {
  HTTPUpload &u = web.upload();
  if (u.status == UPLOAD_FILE_START)
    Update.begin(UPDATE_SIZE_UNKNOWN);
  else if (u.status == UPLOAD_FILE_WRITE)
    Update.write(u.buf, u.currentSize);
  else if (u.status == UPLOAD_FILE_END)
    Update.end(true);
  else if (u.status == UPLOAD_FILE_ABORTED)
    Update.abort();
}

// ========== boot button factory reset ==========
static void checkBootButton() {
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) {
    Serial.println("[boot] button held, waiting 3s...");
    uint32_t t0 = millis();
    while (digitalRead(BOOT_PIN) == LOW && millis() - t0 < 3000) {
      digitalWrite(LED_PIN, (millis() / 100) % 2 ? LOW : HIGH); // fast blink
      delay(10);
    }
    if (millis() - t0 >= 3000) {
      Serial.println("[boot] FACTORY RESET");
      LittleFS.remove("/wifi.cfg");
      LittleFS.remove("/dns.cfg");
      LittleFS.remove("/lang.cfg");
      digitalWrite(LED_PIN, LOW);
      delay(200);
      ESP.restart();
    } else {
      Serial.println("[boot] canceled");
      digitalWrite(LED_PIN, HIGH);
    }
  }
}

// ========== mode startup helpers ==========
static void startMainServices() {
  if (servicesStarted)
    return;
  servicesStarted = true;
  Serial.printf("\nWiFi up: %s\n", WiFi.localIP().toString().c_str());
  digitalWrite(LED_PIN, LOW); // solid ON

  if (MDNS.begin("c3adblock")) {
    MDNS.addService("http", "tcp", 80);
    Serial.println("dashboard: http://c3adblock.local");
  }

  // Setup NTP for Kyiv Time
  sntp_servermode_dhcp(1); // Optional: use DHCP provided NTP if available
  configTzTime("EET-2EEST,M3.5.0/3,M10.5.0/4", "pool.ntp.org", "time.nist.gov");

  // FORCE LwIP to use our upstream DNS to prevent Sinkhole Deadlock
  ip_addr_t dnsserver;
  IP_ADDR4(&dnsserver, upstreamDNS[0], upstreamDNS[1], upstreamDNS[2],
           upstreamDNS[3]);
  dns_setserver(0, &dnsserver);

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(0);

  web.on("/", []() { web.send_P(200, "text/html", DASH_PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    addCustom(web.arg("d"));
    web.send(200, "text/plain", "ok");
  });
  web.on("/unblock", []() {
    removeCustom(web.arg("d"));
    web.send(200, "text/plain", "ok");
  });
  web.on("/addallow", []() {
    addAllow(web.arg("d"));
    web.send(200, "text/plain", "ok");
  });
  web.on("/unallow", []() {
    removeAllow(web.arg("d"));
    web.send(200, "text/plain", "ok");
  });
  web.on("/logs.json", []() {
    String out = "[";
    int count = 0;
    uint32_t now = millis() / 1000;
    for (int i = 0; i < QLOG_SIZE; i++) {
      int idx = (qLogIdx - 1 - i + QLOG_SIZE) % QLOG_SIZE;
      if (qLog[idx].ts == 0) break; // empty
      if (count > 0) out += ",";
      out += "{\"ago\":";
      out += String(now >= qLog[idx].ts ? now - qLog[idx].ts : 0);
      out += ",\"dom\":\"";
      out += jesc(qLog[idx].dom);
      out += "\",\"ip\":\"";
      out += IPAddress(qLog[idx].ip).toString();
      out += "\",\"st\":";
      out += String(qLog[idx].status);
      out += "}";
      count++;
    }
    out += "]";
    web.send(200, "application/json", out);
  });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);
  web.on("/fetchnow", []() {
    if (fetchBlocklist(updateUrl)) {
      uint32_t nowTime = time(nullptr);
      if (nowTime > 1600000000) { // If time is synced
        prefs.putUInt("last_list_ts", nowTime);
        last_list_ts = nowTime;
      }
      pushTelemetry();
    }
    web.send(200, "text/plain", updateStatus);
  });
  web.on("/test_auto", []() {
    last_list_ts = 1893456000; // Сдвигаем в 2030 год
    prefs.putUInt("last_list_ts", last_list_ts);
    web.send(200, "text/plain",
             "Time shifted to 2030! The board will detect this glitch, "
             "self-heal, and trigger an auto-update in a few seconds.");
  });
  web.on("/setupdate", []() {
    if (web.hasArg("u"))
      updateUrl = web.arg("u");
    if (web.hasArg("h")) {
      updateIntervalH = web.arg("h").toInt();
      if (updateIntervalH < 1)
        updateIntervalH = 1;
    }
    saveUpdateCfg();
    web.send(200, "text/plain", "ok");
  });
  web.on("/setcloud", []() {
    if (web.hasArg("u"))
      firebaseDbUrl = web.arg("u");
    saveCloudCfg();
    web.send(200, "text/plain", "ok");
  });
  web.on("/setlang", handleSetLang);
  web.on("/setdns", handleSetDns);
  web.on("/benchmark", handleBenchmark);
  web.on("/benchmarkall", handleBenchmarkAll);
  web.on("/factory-reset", handleFactoryReset);
  web.begin();

  ArduinoOTA.setHostname("c3adblock");
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

static void startSetupMode() {
  WiFi.mode(WIFI_AP);
  WiFi.setSleep(
      false); // ОЧЕНЬ ВАЖНО для одноядерного ESP32-C3 (иначе тормозит DHCP)
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1),
                    IPAddress(255, 255, 255, 0));
  WiFi.softAP("AdBlock-Setup", NULL, 6); // Явно указываем 6-й канал
  Serial.printf("AP: AdBlock-Setup @ %s\n", WiFi.softAPIP().toString().c_str());
  digitalWrite(LED_PIN, LOW);
  dnsServer.begin(DNS_PORT);
  web.on("/", []() { web.send_P(200, "text/html", SETUP_PAGE); });
  web.on("/scan.json", handleScanJson);
  web.on("/save", handleSaveWifi);
  web.on("/setlang", handleSetLang);
  web.onNotFound([]() {
    web.sendHeader("Location", "http://192.168.4.1/", true);
    web.send(302, "text/plain", "");
  });
  web.begin();
  Serial.println("Setup mode: DNS redirect + web :80");
}

static void wifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    Serial.printf("[WIFI] Disconnected! Reason: %d\n", info.wifi_sta_disconnected.reason);
  } else if (event == ARDUINO_EVENT_WIFI_STA_CONNECTED) {
    Serial.println("[WIFI] Connected to AP");
  } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
    Serial.printf("[WIFI] Got IP: %s\n", IPAddress(info.got_ip.ip_info.ip.addr).toString().c_str());
  }
}


void sysTask(void *pvParameters) {
  while (true) {
    if (deviceMode != MODE_MAIN || WiFi.status() != WL_CONNECTED) {
      vTaskDelay(pdMS_TO_TICKS(1000));
      continue;
    }
  time_t nowTime;
  time(&nowTime);
  struct tm timeinfo;
  bool timeValid = false;
  if (localtime_r(&nowTime, &timeinfo)) {
    if (timeinfo.tm_year > 120) { // Time is set (year > 2020)
      timeValid = true;
    }
  }

  if (timeValid && pendingFwTsSave) {
    prefs.putUInt("last_fw_ts", (uint32_t)nowTime);
    last_fw_ts = (uint32_t)nowTime;
    pendingFwTsSave = false;
  }

  if (updateUrl.length() && WiFi.status() == WL_CONNECTED) {
    bool shouldUpdate = false;

    if (numHashes == 0) {
      // Если список отсутствует (например, сбой при прошлом обновлении),
      // пытаемся загрузить его. Чтобы не "заспамить" GitHub Pages частыми
      // запросами и не получить бан, делаем попытки не чаще чем раз в 5 минут
      // (300 000 мс).
      static uint32_t lastRetry = 0;
      if (millis() - lastRetry > 300000) {
        lastRetry = millis();
        shouldUpdate = true;
      }
    } else if (timeValid) {
      // Защита от сбоев NTP: если сохраненное время из будущего, сбрасываем его
      if (last_list_ts > (uint32_t)nowTime) {
        last_list_ts = (uint32_t)nowTime - (updateIntervalH * 3600) - 10;
      }

      // Плановое обновление
      // Пытаемся сохранить обновление в 4 утра, либо если прошло больше
      // времени, чем updateIntervalH
      static int lastUpdateDay = -1;
      if (timeinfo.tm_hour == 4 && timeinfo.tm_min == 0 &&
          lastUpdateDay != timeinfo.tm_yday) {
        lastUpdateDay = timeinfo.tm_yday;
        shouldUpdate = true;
      } else if (last_list_ts > 0 && (uint32_t)nowTime > last_list_ts &&
                 ((uint32_t)nowTime - last_list_ts) >=
                     (updateIntervalH * 3600)) {
        // Если интервал задан в UI и это время истекло
        shouldUpdate = true;
      }
    }

    if (shouldUpdate) {
      if (fetchBlocklist(updateUrl) && timeValid) {
        prefs.putUInt("last_list_ts", (uint32_t)nowTime);
        last_list_ts = (uint32_t)nowTime;
        pushTelemetry();
      }
    }
  }

  if (firebaseDbUrl.length()) {
    uint32_t now = millis();
    if (lastTelemetryMs == 0 ||
        now - lastTelemetryMs >= 300000UL) { // every 5 minutes
      lastTelemetryMs = now;
      pushTelemetry();
    }

    if (lastCmdCheckMs == 0 ||
        now - lastCmdCheckMs >= 60000UL) { // every 60 seconds
      lastCmdCheckMs = now;
      String mac = WiFi.macAddress();
      mac.replace(":", "");

      WiFiClientSecure client;
      client.setInsecure();
      HTTPClient http;

      // Check for remote commands & license status
      String baseUrl = firebaseDbUrl;
      if (!baseUrl.endsWith("/"))
        baseUrl += "/";

      // 1. Check License Status
      String activeUrl = baseUrl + "devices/" + mac + "/active.json";
      if (String(FIREBASE_SECRET).length() > 0)
        activeUrl += "?auth=" + String(FIREBASE_SECRET);

      if (firebaseDbUrl.startsWith("https"))
        http.begin(client, activeUrl);
      else
        http.begin(activeUrl);

      int aCode = http.GET();
      if (aCode == HTTP_CODE_OK) {
        String resp = http.getString();
        resp.trim();
        if (resp == "false") licenseActive = false;
        else if (resp == "true" || resp == "null") licenseActive = true;
      }
      http.end();

      // 2. Check Commands
      String cmdUrl = baseUrl + "devices/" + mac + "/command.json";
      if (String(FIREBASE_SECRET).length() > 0)
        cmdUrl += "?auth=" + String(FIREBASE_SECRET);

      if (firebaseDbUrl.startsWith("https"))
        http.begin(client, cmdUrl);
      else
        http.begin(cmdUrl);

      int code = http.GET();
      if (code == HTTP_CODE_OK) {
        String cmd = http.getString();
        cmd.replace("\"", ""); // remove quotes
        if (cmd == "reboot" || cmd == "update_fw" || cmd == "ping" ||
            cmd == "update_blocklist") {
          // Clear command in Firebase FIRST
          if (firebaseDbUrl.startsWith("https"))
            http.begin(client, cmdUrl);
          else
            http.begin(cmdUrl);
          http.addHeader("Content-Type", "application/json");
          http.PUT("null");
          http.end();

          if (cmd == "reboot") {
            actionStatus = "Rebooting...";
            pushTelemetry();
            delay(500);
            ESP.restart();
          } else if (cmd == "update_fw") {
            actionStatus = "Downloading FW...";
            pushTelemetry();
            delay(500); // Give LwIP time to free sockets
            actionStatus = checkFirmwareUpdate();
            delay(500);
            pushTelemetry();
          } else if (cmd == "ping") {
            actionStatus = "Ping received";
            pushTelemetry();
          } else if (cmd == "update_blocklist") {
            actionStatus = "Updating blocklist...";
            pushTelemetry();
            delay(500);
            if (fetchBlocklist(updateUrl) && timeValid) {
              prefs.putUInt("last_list_ts", (uint32_t)nowTime);
              last_list_ts = (uint32_t)nowTime;
            }
            actionStatus = "Blocklist updated";
            pushTelemetry();
          }
        }
      }
      http.end();
    }
  }


    vTaskDelay(pdMS_TO_TICKS(100)); // Sleep 100ms
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);
  delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true))
    Serial.println("LittleFS FAILED");
  blocklistMutex = xSemaphoreCreateMutex();
  reopenBlocklist();
  if (blocklist) {
    Serial.printf("blocklist: %u domains\n", numHashes);
  }

  loadCustom();
  loadAllow();
  loadBanned();
  loadUpdateCfg();
  loadCloudCfg();
  loadDnsCfg();
  loadLangCfg();

  prefs.begin("adblock", false);
  int storedVer = prefs.getInt("fw_ver", 0);
  if (storedVer != FW_VERSION) {
    prefs.putInt("fw_ver", FW_VERSION);
    pendingFwTsSave = true;
  }
  last_fw_ts = prefs.getUInt("last_fw_ts", 0);
  last_list_ts = prefs.getUInt("last_list_ts", 0);

  checkBootButton();

  if (loadWifiCfg()) {
    deviceMode = MODE_MAIN;
    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    WiFi.onEvent(wifiEvent);
    WiFi.begin(cfgSSID.c_str(), cfgPass.c_str());
    uint32_t t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 10000) {
      delay(300);
      Serial.print(".");
      digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    }
    xTaskCreate(sysTask, "sysTask", 8192, NULL, 1, NULL);
    
    if (WiFi.status() == WL_CONNECTED) {
      WiFi.setSleep(true);
      esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
      startMainServices();
    }
  } else {
    deviceMode = MODE_SETUP;
    startSetupMode();
  }
}

void loop() {
  uint32_t nowMs = millis();
  
  static uint32_t last_stat_log = 0;
  if (nowMs - last_stat_log > 10000) {
    last_stat_log = nowMs;
    float temp = temperatureRead();
    Serial.printf("[SYS] Heap: %u, MaxAlloc: %u, RSSI: %d, Temp: %.1fC, Blocked: %u, Allowed: %u\n", ESP.getFreeHeap(), ESP.getMaxAllocHeap(), WiFi.RSSI(), temp, totalBlocked, totalAllowed);
  }

  // Unconditionally check boot button (works in AP, STA, and Retry)
  checkBootButton();

  // Test triggers via Serial because host AP isolation might block HTTP
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd == "WEB_RESET_TEST") {
      Serial.println("[TEST] Web Factory Reset Triggered via Serial");
      handleFactoryReset();
    } else if (cmd == "BOOT_RESET_TEST") {
      Serial.println("[TEST] Boot Button 3s hold Triggered via Serial");
      LittleFS.remove("/wifi.cfg");
      LittleFS.remove("/dns.cfg");
      LittleFS.remove("/lang.cfg");
      ESP.restart();
    }
  }

  if (deviceMode == MODE_SETUP) {
    handleApDns();
    web.handleClient();
    static uint32_t lb = 0;
    if (millis() - lb > 1000) {
      lb = millis();
      digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    }
    yield();
    return;
  }

  if (!servicesStarted) {
    if (WiFi.status() == WL_CONNECTED) {
      WiFi.setSleep(true);
      esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
      startMainServices();
    } else {
      static uint32_t lb2 = 0;
      if (millis() - lb2 > 300) {
        lb2 = millis();
        digitalWrite(LED_PIN, !digitalRead(LED_PIN));
      }
      static uint32_t lr = 0;
      if (lr == 0)
        lr = millis();
      if (millis() - lr > 10000) {
        lr = millis();
        WiFi.disconnect();
        WiFi.begin(cfgSSID.c_str(), cfgPass.c_str());
      }
      delay(100);
      return;
    }
  }

  ArduinoOTA.handle();
  web.handleClient();
  handleDns();
  handleUpstreamDns();

  static uint32_t lastReconnectAttempt = 0;
  if (WiFi.status() != WL_CONNECTED) {
    static uint32_t lb3 = 0;
    if (millis() - lb3 > 200) {
      lb3 = millis();
      digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    }
    if (millis() - lastReconnectAttempt > 10000) {
      lastReconnectAttempt = millis();
      WiFi.disconnect();
      WiFi.begin(cfgSSID.c_str(), cfgPass.c_str());
    }
  } else {
    digitalWrite(LED_PIN, LOW);
    lastReconnectAttempt = millis();
  }

  yield();
}
