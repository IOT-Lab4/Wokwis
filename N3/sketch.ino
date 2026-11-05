// ===== G3 Minería de tajo abierto (TMS) - Nodo 3: Bomba 1 (N3, sector fondo) =====
// Detecta: potenciómetro (analógica): corriente del motor 0-10 A. Interruptor (digital): caudal 0/1.
// Actúa:   relé de la bomba 1 y LED de estado.
// Ataque 3: orden falsa para apagar la bomba 1 durante la lluvia.
// Defensa:  solo acepta órdenes firmadas por el gateway: HMAC-SHA256(N3|orden|contador|ts),
//           contador creciente y ts de máximo 30 s. Cada rechazo se publica en /alerta.
// Claves en secrets.h (fuera de GitHub).

#include <WiFi.h>
#include <PubSubClient.h>
#include <time.h>
#include "mbedtls/md.h"
#include "secrets.h"

// ---------- Pines (iguales a Cirkit) ----------
const int PIN_CORRIENTE = 34;  // analógica (potenciómetro)
const int PIN_CAUDAL    = 27;  // digital (interruptor, INPUT_PULLUP): LOW = hay caudal
const int PIN_RELE      = 26;  // relé bomba 1
const int PIN_LED       = 25;  // LED de estado

// ---------- Identidad del nodo ----------
const char* NODO   = "bomba1";
const char* ID     = "N3";
const char* SECTOR = "fondo";
const char* T_GW_ESTADO = "upc/g3/gateway/estado";

char T_DATOS[40], T_ALERTA[40], T_ESTADO[40], T_CMD[40], T_ATAQUE[40];

const long VENTANA_TS_S = 30;
const unsigned long MODO_SEGURO_MS = 60000;
const int MAX_MSG_S = 10;

WiFiClient espClient;
PubSubClient mqtt(espClient);

bool bombaOn = false;
long ultimoContador = 0;
unsigned long tDatos = 0, tLatido = 0, tGateway = 0, tIntento = 0;
bool ntpPedido = false;

// ---------- Utilidades ----------
long ahora() {                                   // segundos UTC; 0 si NTP aún no sincroniza
  time_t t = time(nullptr);
  return t > 1700000000 ? (long)t : 0;
}

void hmacHex(const char* msg, char* out65) {
  unsigned char h[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const unsigned char*)HMAC_KEY, strlen(HMAC_KEY),
                  (const unsigned char*)msg, strlen(msg), h);
  for (int i = 0; i < 32; i++) sprintf(out65 + 2 * i, "%02x", h[i]);
  out65[64] = 0;
}

bool igualConstante(const char* a, const char* b) {
  if (strlen(a) != strlen(b)) return false;
  unsigned char d = 0;
  for (size_t i = 0; a[i]; i++) d |= (unsigned char)(a[i] ^ b[i]);
  return d == 0;
}

bool campo(const char* js, const char* clave, char* out, size_t n) {
  char patron[32];
  snprintf(patron, sizeof patron, "\"%s\":", clave);
  const char* p = strstr(js, patron);
  out[0] = 0;
  if (!p) return false;
  p += strlen(patron);
  size_t k = 0;
  if (*p == '"') { p++; while (*p && *p != '"' && k < n - 1) out[k++] = *p++; }
  else { while (*p && *p != ',' && *p != '}' && k < n - 1) out[k++] = *p++; }
  out[k] = 0;
  return true;
}

bool permitirPublicar() {
  static unsigned long inicio = 0;
  static int cuenta = 0;
  if (millis() - inicio >= 1000) { inicio = millis(); cuenta = 0; }
  if (cuenta >= MAX_MSG_S) return false;
  cuenta++;
  return true;
}

void setBomba(bool on) {
  bombaOn = on;
  digitalWrite(PIN_RELE, on ? HIGH : LOW);
  digitalWrite(PIN_LED,  on ? HIGH : LOW);
}

float leerCorriente() {
  return analogRead(PIN_CORRIENTE) / 4095.0 * 10.0;   // 0 a 10 A
}

int leerCaudal() {
  return digitalRead(PIN_CAUDAL) == LOW ? 1 : 0;
}

// ---------- Publicación firmada: HMAC(id|sector|ts|valor|unidad|calidad) ----------
void publicar(const char* topic, const char* valor, bool texto, const char* unidad, const char* cal,
              const char* extra, bool retener) {
  if (!mqtt.connected() || !permitirPublicar()) return;
  long ts = ahora();
  char canon[160], firma[65], msg[420];
  snprintf(canon, sizeof canon, "%s|%s|%ld|%s|%s|%s", ID, SECTOR, ts, valor, unidad, cal);
  hmacHex(canon, firma);
  snprintf(msg, sizeof msg,
           texto ? "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%ld,\"valor\":\"%s\",\"unidad\":\"%s\",\"calidad\":\"%s\",\"firma\":\"%s\"%s}"
                 : "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%ld,\"valor\":%s,\"unidad\":\"%s\",\"calidad\":\"%s\",\"firma\":\"%s\"%s}",
           ID, SECTOR, ts, valor, unidad, cal, firma, extra ? extra : "");
  mqtt.publish(topic, msg, retener);
}

void publicarDatos() {
  float corriente = leerCorriente();
  int caudal = leerCaudal();
  const char* cal = (ahora() == 0 || (bombaOn && corriente < 0.5)) ? "dudosa" : "ok";
  char v[12], extra[60];
  snprintf(v, sizeof v, "%.2f", corriente);
  snprintf(extra, sizeof extra, ",\"caudal\":%d,\"bomba\":\"%s\"", caudal, bombaOn ? "on" : "off");
  publicar(T_DATOS, v, false, "A", cal, extra, false);
}

void publicarEstado() {
  char extra[80];
  snprintf(extra, sizeof extra, ",\"bomba\":\"%s\",\"modo_seguro\":%s", bombaOn ? "on" : "off",
           millis() - tGateway > MODO_SEGURO_MS ? "true" : "false");
  publicar(T_ESTADO, "online", true, "estado", "ok", extra, true);
}

void rechazar(const char* tipo, const char* motivo) {
  char extra[160];
  snprintf(extra, sizeof extra, ",\"tipo\":\"%s\",\"accion\":\"orden_rechazada\",\"motivo\":\"%s\",\"bomba\":\"%s\"",
           tipo, motivo, bombaOn ? "on" : "off");
  publicar(T_ALERTA, tipo, true, "alerta", "ok", extra, false);
  Serial.printf("[SEGURIDAD] orden rechazada: %s (%s). La bomba sigue %s\n", tipo, motivo, bombaOn ? "ON" : "OFF");
}

// ---------- Órdenes: {"orden","contador","ts","firma"} ----------
void procesarOrden(const char* js) {
  char orden[16], ctr[20], ts[20], firma[72];
  campo(js, "orden", orden, sizeof orden);
  campo(js, "contador", ctr, sizeof ctr);
  campo(js, "ts", ts, sizeof ts);
  bool conFirma = campo(js, "firma", firma, sizeof firma);
  if (!conFirma) { rechazar("orden_falsa", "orden_sin_firma"); return; }

  char canon[96], esperada[65];
  snprintf(canon, sizeof canon, "%s|%s|%s|%s", ID, orden, ctr, ts);
  hmacHex(canon, esperada);
  if (!igualConstante(esperada, firma)) { rechazar("orden_falsa", "firma_invalida"); return; }
  long c = atol(ctr), t = atol(ts), now = ahora();
  if (c <= ultimoContador) { rechazar("repeticion", "contador_repetido"); return; }
  if (now == 0 || labs(now - t) > VENTANA_TS_S) { rechazar("repeticion", "ts_fuera_de_ventana"); return; }
  ultimoContador = c;
  tGateway = millis();

  if (!strcmp(orden, "encender")) setBomba(true);
  else if (!strcmp(orden, "apagar")) setBomba(false);
  else { rechazar("orden_falsa", "orden_desconocida"); return; }
  Serial.printf("[CMD] %s aceptada (contador %ld)\n", orden, c);
  publicarEstado();
}

void alRecibir(char* topic, byte* payload, unsigned int len) {
  char js[400];
  unsigned int n = len < sizeof(js) - 1 ? len : sizeof(js) - 1;
  memcpy(js, payload, n); js[n] = 0;
  if (!strcmp(topic, T_GW_ESTADO)) { if (!strstr(js, "offline")) tGateway = millis(); return; }
  if (!strcmp(topic, T_ATAQUE)) {                // simula el ataque 3: "apagar" sin firma
    mqtt.publish(T_CMD, "{\"orden\":\"apagar\",\"contador\":999999999,\"ts\":0}");
    Serial.println("[ATAQUE 3] publicada orden falsa de apagar la bomba 1");
    return;
  }
  if (!strcmp(topic, T_CMD)) procesarOrden(js);
}

// ---------- Conexión sin bloquear: la bomba sigue en su estado aunque no haya red ----------
void mantenerConexion() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (!ntpPedido) { configTime(0, 0, "pool.ntp.org", "time.google.com"); ntpPedido = true; }
  if (mqtt.connected() || millis() - tIntento < 3000) return;
  tIntento = millis();
  String cid = String("upc-g3-") + NODO + "-" + String((uint32_t)esp_random(), HEX);
  if (mqtt.connect(cid.c_str(), nullptr, nullptr, T_ESTADO, 0, true, "offline")) {   // LWT
    mqtt.subscribe(T_CMD);
    mqtt.subscribe(T_ATAQUE);
    mqtt.subscribe(T_GW_ESTADO);
    publicarEstado();
    Serial.println("MQTT conectado");
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_CAUDAL, INPUT_PULLUP);
  pinMode(PIN_RELE, OUTPUT);
  pinMode(PIN_LED, OUTPUT);
  setBomba(false);

  snprintf(T_DATOS,  sizeof(T_DATOS),  "upc/g3/%s/datos",  NODO);
  snprintf(T_ALERTA, sizeof(T_ALERTA), "upc/g3/%s/alerta", NODO);
  snprintf(T_ESTADO, sizeof(T_ESTADO), "upc/g3/%s/estado", NODO);
  snprintf(T_CMD,    sizeof(T_CMD),    "upc/g3/%s/cmd",    NODO);
  snprintf(T_ATAQUE, sizeof(T_ATAQUE), "upc/g3/%s/ataque", NODO);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CANAL);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  mqtt.setCallback(alRecibir);
  tGateway = millis();
  Serial.println("Nodo 3 - Bomba 1 listo. Serial: 'x' = ataque orden falsa.");
}

void loop() {
  mantenerConexion();
  mqtt.loop();
  if (Serial.available() && Serial.read() == 'x' && mqtt.connected())
    alRecibir(T_ATAQUE, (byte*)"", 0);

  unsigned long t = millis();
  if (t - tDatos >= 2000)  { tDatos = t;  publicarDatos(); }     // datos cada 2 s
  if (t - tLatido >= 30000) { tLatido = t; publicarEstado(); }   // latido cada 30 s
}
