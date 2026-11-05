// ===== G3 Minería de tajo abierto (TMS) - Nodo 2: Sumidero (N2, sector fondo) =====
// Detecta: HC-SR04 (digital): nivel del agua acumulada en el fondo del tajo, en %.
// Actúa:   relé de la bomba de respaldo (edge: arranca sola al 80 %, sin esperar al gateway)
//          y LED de alerta (amarillo >= 60 %, parpadeo >= 80 %).
// Ataque 2: suplantación (otro equipo publica con el id del sumidero, sin firma).
// Defensa:  todo lo que publica N2 va firmado con HMAC-SHA256; N2 vigila su propio tópico y
//           denuncia cada mensaje con su id que no trae su firma; el gateway lo descarta.
// Claves en secrets.h (fuera de GitHub).

#include <WiFi.h>
#include <PubSubClient.h>
#include <time.h>
#include "mbedtls/md.h"
#include "secrets.h"

// ---------- PINES ----------
const int PIN_TRIG = 5;
const int PIN_ECHO = 18;
const int PIN_RELE = 26;   // bomba de respaldo
const int PIN_LED  = 25;   // LED de alerta

// ---------- IDENTIDAD / TÓPICOS (contrato del grupo) ----------
const char* NODE_ID  = "N2";
const char* SECTOR   = "fondo";
const char* T_DATOS  = "upc/g3/sumidero/datos";
const char* T_ALERTA = "upc/g3/sumidero/alerta";
const char* T_ESTADO = "upc/g3/sumidero/estado";
const char* T_ATAQUE = "upc/g3/sumidero/ataque";   // botón del panel HTML
const char* T_GW_ESTADO = "upc/g3/gateway/estado";

// ---------- CONFIGURACIÓN ----------
const float DIST_VACIO_CM = 200.0;   // sumidero vacío (0 %)
const float DIST_LLENO_CM = 20.0;    // sumidero lleno (100 %)
const float NIVEL_AMARILLO = 60.0;   // umbral del grupo
const float NIVEL_MAXIMO   = 80.0;   // edge: arranca la bomba de respaldo
const float NIVEL_APAGAR   = 60.0;   // histéresis: apaga la bomba de respaldo
const unsigned long LECTURA_MS = 1000;
const unsigned long DATOS_MS   = 2000;
const unsigned long LATIDO_MS  = 30000;
const unsigned long MODO_SEGURO_MS = 60000;
const int MAX_MSG_S = 10;

// ---------- ESTADO ----------
WiFiClient net;
PubSubClient mqtt(net);
float nivel = 0;
const char* calidad = "ok";
bool releOn = false;
int zona = 0;                                  // 0 normal, 1 amarillo, 2 máximo
unsigned long tLectura = 0, tDatos = 0, tLatido = 0, tGateway = 0, tIntento = 0, tResumen = 0;
unsigned long suplantaciones = 0;
bool ntpPedido = false;

// ---------- UTILIDADES ----------
unsigned long nowTs() {
  time_t t = time(nullptr);
  return t > 1700000000 ? (unsigned long)t : 0;
}

void hmacHex(const char* msg, char* out65) {
  unsigned char h[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const unsigned char*)HMAC_KEY, strlen(HMAC_KEY),
                  (const unsigned char*)msg, strlen(msg), h);
  for (int i = 0; i < 32; i++) sprintf(out65 + 2 * i, "%02x", h[i]);
  out65[64] = 0;
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

// Firma = HMAC-SHA256( id|sector|ts|valor|unidad|calidad ), valor sin comillas.
void publicar(const char* topic, const char* valor, bool texto, const char* unidad, const char* cal,
              const char* extra, bool retener) {
  if (!mqtt.connected() || !permitirPublicar()) return;
  unsigned long ts = nowTs();
  char canon[160], firma[65], msg[420];
  snprintf(canon, sizeof canon, "%s|%s|%lu|%s|%s|%s", NODE_ID, SECTOR, ts, valor, unidad, cal);
  hmacHex(canon, firma);
  snprintf(msg, sizeof msg,
           texto ? "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%lu,\"valor\":\"%s\",\"unidad\":\"%s\",\"calidad\":\"%s\",\"firma\":\"%s\"%s}"
                 : "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%lu,\"valor\":%s,\"unidad\":\"%s\",\"calidad\":\"%s\",\"firma\":\"%s\"%s}",
           NODE_ID, SECTOR, ts, valor, unidad, cal, firma, extra ? extra : "");
  mqtt.publish(topic, msg, retener);
}

void alerta(const char* tipo, const char* accion, const char* motivo) {
  char extra[200];
  snprintf(extra, sizeof extra, ",\"tipo\":\"%s\",\"accion\":\"%s\",\"motivo\":\"%s\",\"nivel\":%.1f,\"rele\":\"%s\"",
           tipo, accion, motivo, nivel, releOn ? "on" : "off");
  publicar(T_ALERTA, tipo, true, "alerta", "ok", extra, false);
  Serial.printf("[ALERTA] %s | %s | %s\n", tipo, accion, motivo);
}

void publicarEstado() {
  char extra[80];
  snprintf(extra, sizeof extra, ",\"rele\":\"%s\",\"modo_seguro\":%s", releOn ? "on" : "off",
           (millis() - tGateway > MODO_SEGURO_MS) ? "true" : "false");
  publicar(T_ESTADO, "online", true, "estado", "ok", extra, true);
}

// ---------- SENSOR ----------
float leerDistancia() {
  digitalWrite(PIN_TRIG, LOW);  delayMicroseconds(2);
  digitalWrite(PIN_TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(PIN_TRIG, LOW);
  long d = pulseIn(PIN_ECHO, HIGH, 30000);
  return d == 0 ? -1 : d * 0.0343 / 2.0;
}

void setRele(bool on) {
  releOn = on;
  digitalWrite(PIN_RELE, on ? HIGH : LOW);
}

// Edge: decide sola, sin gateway ni internet.
void actuar() {
  int nueva = nivel >= NIVEL_MAXIMO ? 2 : (nivel >= NIVEL_AMARILLO ? 1 : 0);
  if (!releOn && nivel >= NIVEL_MAXIMO) {
    setRele(true);
    alerta("nivel_maximo", "bomba_respaldo_encendida", "nivel >= 80 %");
  } else if (releOn && nivel < NIVEL_APAGAR) {
    setRele(false);
    alerta("nivel_normal", "bomba_respaldo_apagada", "nivel < 60 %");
  }
  if (nueva == 1 && zona == 0) alerta("nivel_amarillo", "avisar_gateway", "nivel >= 60 %");
  zona = nueva;
  bool parpadeo = (millis() / 300) % 2;
  digitalWrite(PIN_LED, zona == 2 ? parpadeo : (zona == 1 ? HIGH : LOW));
}

// ---------- MQTT ----------
void onMensaje(char* topic, byte* payload, unsigned int len) {
  char js[400];
  unsigned int n = len < sizeof(js) - 1 ? len : sizeof(js) - 1;
  memcpy(js, payload, n); js[n] = 0;

  if (!strcmp(topic, T_GW_ESTADO)) {
    if (!strstr(js, "offline")) tGateway = millis();
    return;
  }
  if (!strcmp(topic, T_ATAQUE)) {               // simula al otro equipo: mismo id, sin firma
    mqtt.publish(T_DATOS, "{\"id\":\"N2\",\"sector\":\"fondo\",\"ts\":0,\"valor\":5.0,\"unidad\":\"%\",\"calidad\":\"ok\"}");
    Serial.println("[ATAQUE 2] publicado dato falso de nivel 5 % sin firma");
    return;
  }
  if (!strcmp(topic, T_DATOS)) {                // defensa: revisa todo lo que llega con mi id
    char id[8], sec[16], ts[16], val[16], uni[8], cal[12], firma[72], canon[160], esperada[65];
    campo(js, "id", id, sizeof id);
    if (strcmp(id, NODE_ID) != 0) return;
    campo(js, "sector", sec, sizeof sec);
    campo(js, "ts", ts, sizeof ts);
    campo(js, "valor", val, sizeof val);
    campo(js, "unidad", uni, sizeof uni);
    campo(js, "calidad", cal, sizeof cal);
    bool tiene = campo(js, "firma", firma, sizeof firma);
    snprintf(canon, sizeof canon, "%s|%s|%s|%s|%s|%s", id, sec, ts, val, uni, cal);
    hmacHex(canon, esperada);
    if (!tiene || strcmp(esperada, firma) != 0) suplantaciones++;
  }
}

void mantenerMqtt() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (!ntpPedido) { configTime(0, 0, "pool.ntp.org", "time.google.com"); ntpPedido = true; }
  if (mqtt.connected() || millis() - tIntento < 3000) return;
  tIntento = millis();
  String cid = "upc-g3-n2-" + String((uint32_t)esp_random(), HEX);
  if (mqtt.connect(cid.c_str(), NULL, NULL, T_ESTADO, 0, true, "offline")) {   // LWT = offline
    mqtt.subscribe(T_GW_ESTADO);
    mqtt.subscribe(T_ATAQUE);
    mqtt.subscribe(T_DATOS);
    publicarEstado();
    Serial.println("[MQTT] conectado");
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_TRIG, OUTPUT);
  pinMode(PIN_ECHO, INPUT);
  pinMode(PIN_RELE, OUTPUT);
  pinMode(PIN_LED, OUTPUT);
  setRele(false);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CANAL);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMensaje);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  tGateway = millis();
  Serial.println("Nodo 2 - Sumidero listo. Serial: 's' = ataque de suplantacion.");
}

void loop() {
  mantenerMqtt();
  mqtt.loop();

  if (Serial.available() && Serial.read() == 's' && mqtt.connected())
    onMensaje((char*)T_ATAQUE, (byte*)"", 0);

  if (millis() - tLectura >= LECTURA_MS) {
    tLectura = millis();
    float d = leerDistancia();
    if (d < 0) {
      calidad = "falla";                         // sin eco: se mantiene el último nivel y el relé
    } else {
      calidad = "ok";
      nivel = constrain((DIST_VACIO_CM - d) / (DIST_VACIO_CM - DIST_LLENO_CM) * 100.0, 0, 100);
    }
    Serial.printf("dist=%.1f cm | nivel=%.1f %% | rele=%s | calidad=%s | modo_seguro=%d\n", d, nivel,
                  releOn ? "ON" : "OFF", calidad, millis() - tGateway > MODO_SEGURO_MS);
  }
  actuar();

  if (millis() - tDatos >= DATOS_MS) {
    tDatos = millis();
    char v[12], extra[40];
    snprintf(v, sizeof v, "%.1f", nivel);
    snprintf(extra, sizeof extra, ",\"rele\":\"%s\"", releOn ? "on" : "off");
    publicar(T_DATOS, v, false, "%", calidad, extra, false);
  }
  if (millis() - tLatido >= LATIDO_MS) {
    tLatido = millis();
    publicarEstado();
  }
  if (suplantaciones && millis() - tResumen >= 5000) {   // agrupado: no amplifica el ataque
    tResumen = millis();
    char accion[48];
    snprintf(accion, sizeof accion, "descartados %lu mensajes", suplantaciones);
    alerta("suplantacion", accion, "firma HMAC invalida o ausente");
    suplantaciones = 0;
  }
}
