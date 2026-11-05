// G3 Minería de tajo abierto - Nodo 4: Bomba 2 (respaldo de la bomba 1)
// Detecta: corriente del motor (potenciómetro) y confirmación de caudal (interruptor)
// Actúa:   relé de la bomba 2
// Seguridad: solo acepta órdenes firmadas (HMAC-SHA256) con contador y marca de tiempo
#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include "mbedtls/md.h"
#include "secrets.h"   // WIFI_SSID, WIFI_PASS, WIFI_CANAL, MQTT_HOST, MQTT_PORT, CLAVE_N4

// ---------- Identidad del nodo ----------
const char* ID_NODO    = "N4";
const char* SECTOR     = "fondo";
const char* TOPIC_BASE = "upc/g3/bomba2";
const char* TOPIC_GW_ESTADO = "upc/g3/gateway/estado";

// ---------- Pines ----------
const int PIN_CORRIENTE  = 34;  // potenciómetro (entrada analógica)
const int PIN_CAUDAL     = 27;  // interruptor (entrada digital): HIGH = hay caudal
const int PIN_RELE       = 26;  // relé de la bomba 2
const int PIN_LED_ALERTA = 33;  // LED rojo de alerta
const bool RELE_ACTIVO_ALTO = true;  // pon false si tu relé funciona al revés

// ---------- Parámetros (propuestas del grupo, a calibrar) ----------
const float CORRIENTE_MAX_A       = 10.0;   // 4095 en el ADC = 10 A
const float UMBRAL_SOBRECARGA_A   = 9.0;    // apaga el relé por encima de este valor
const float UMBRAL_SIN_CARGA_A    = 0.5;    // bomba encendida con menos corriente = lectura dudosa
const unsigned long PERIODO_DATOS_MS   = 2000;
const unsigned long PERIODO_ESTADO_MS  = 30000;   // latido
const unsigned long TIEMPO_CAUDAL_MS   = 15000;   // confirmación de caudal tras encender
const unsigned long TIEMPO_SEGURO_MS   = 60000;   // sin gateway más de 60 s = modo seguro
const long VENTANA_TS_S = 30;                     // una orden vale 30 s

// ---------- Estado ----------
WiFiClient wifi;
PubSubClient mqtt(wifi);
char tDatos[48], tAlerta[48], tEstado[48], tCmd[48];

bool bombaOn = false;
bool esperandoCaudal = false;
bool alertaActiva = false;
unsigned long inicioOrden = 0;
unsigned long ultimoGateway = 0;
long ultimoContador = 0;
unsigned long tDatosMs = 0, tEstadoMs = 0, tReintentoMs = 0;

// ---------- Utilidades ----------
long ahoraS() {
  time_t t = time(nullptr);
  return (t > 1700000000) ? (long)t : 0;   // 0 = reloj aún sin sincronizar
}

void hmacHex(const char* msg, char* out65) {
  unsigned char h[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const unsigned char*)CLAVE_N4, strlen(CLAVE_N4),
                  (const unsigned char*)msg, strlen(msg), h);
  for (int i = 0; i < 32; i++) sprintf(out65 + 2 * i, "%02x", h[i]);
  out65[64] = 0;
}

bool igualConstante(const char* a, const char* b) {
  size_t la = strlen(a), lb = strlen(b);
  if (la != lb) return false;
  unsigned char d = 0;
  for (size_t i = 0; i < la; i++) d |= (unsigned char)(a[i] ^ b[i]);
  return d == 0;
}

void setRele(bool on) {
  bombaOn = on;
  digitalWrite(PIN_RELE, (on == RELE_ACTIVO_ALTO) ? HIGH : LOW);
}

float leerCorrienteA() {
  long suma = 0;
  for (int i = 0; i < 8; i++) suma += analogRead(PIN_CORRIENTE);
  return (suma / 8.0) * CORRIENTE_MAX_A / 4095.0;
}

bool hayCaudal() { return digitalRead(PIN_CAUDAL) == HIGH; }
bool modoSeguro() { return (millis() - ultimoGateway) > TIEMPO_SEGURO_MS; }

// ---------- Publicación firmada ----------
// La firma cubre: id|sector|ts|valor|unidad|calidad. Los campos extra son informativos.
void publicarFirmado(const char* topic, const char* valor, bool esTexto, const char* unidad,
                     const char* calidad, const char* extraJson, bool retener) {
  long ts = ahoraS();
  char canon[128], firma[65], msg[420];
  snprintf(canon, sizeof canon, "%s|%s|%ld|%s|%s|%s", ID_NODO, SECTOR, ts, valor, unidad, calidad);
  hmacHex(canon, firma);
  snprintf(msg, sizeof msg,
           esTexto ? "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%ld,\"valor\":\"%s\",\"unidad\":\"%s\",\"calidad\":\"%s\",\"firma\":\"%s\"%s}"
                   : "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%ld,\"valor\":%s,\"unidad\":\"%s\",\"calidad\":\"%s\",\"firma\":\"%s\"%s}",
           ID_NODO, SECTOR, ts, valor, unidad, calidad, firma, extraJson ? extraJson : "");
  mqtt.publish(topic, msg, retener);
}

void publicarAlerta(const char* tipo, const char* motivo, const char* accion) {
  char extra[140];
  snprintf(extra, sizeof extra, ",\"motivo\":\"%s\",\"accion\":\"%s\"", motivo, accion);
  publicarFirmado(tAlerta, tipo, true, "alerta", "ok", extra, false);
  Serial.printf("[ALERTA] tipo=%s motivo=%s accion=%s\n", tipo, motivo, accion);
}

void publicarEstado() {
  char extra[80];
  snprintf(extra, sizeof extra, ",\"bomba\":\"%s\",\"modo\":\"%s\"",
           bombaOn ? "on" : "off", modoSeguro() ? "seguro" : "normal");
  publicarFirmado(tEstado, "online", true, "estado", "ok", extra, true);
}

void publicarDatos() {
  float a = leerCorrienteA();
  const char* cal = (ahoraS() == 0 || (bombaOn && a < UMBRAL_SIN_CARGA_A)) ? "dudosa" : "ok";
  char v[16];
  snprintf(v, sizeof v, "%.2f", a);
  publicarFirmado(tDatos, v, false, "A", cal, nullptr, false);
  publicarFirmado(tDatos, hayCaudal() ? "1" : "0", false, "0/1", "ok", nullptr, false);
}

// ---------- Órdenes recibidas ----------
void rechazar(const char* tipo, const char* motivo) {
  Serial.printf("[SEGURIDAD] orden rechazada: tipo=%s motivo=%s\n", tipo, motivo);
  publicarAlerta(tipo, motivo, "orden_rechazada");
}

void procesarOrden(const byte* payload, unsigned int len) {
  JsonDocument doc;
  if (deserializeJson(doc, payload, len)) { rechazar("orden_falsa", "formato_invalido"); return; }
  const char* orden = doc["orden"] | "";
  long contador = doc["contador"] | 0L;
  long ts = doc["ts"] | 0L;
  const char* firma = doc["firma"] | "";

  char canon[96], esperada[65];
  snprintf(canon, sizeof canon, "%s|%s|%ld|%ld", ID_NODO, orden, contador, ts);
  hmacHex(canon, esperada);

  if (!igualConstante(esperada, firma)) { rechazar("orden_falsa", "firma_invalida"); return; }
  if (contador <= ultimoContador)        { rechazar("repeticion", "contador_repetido"); return; }
  long ahora = ahoraS();
  if (ahora == 0 || labs(ahora - ts) > VENTANA_TS_S) { rechazar("repeticion", "ts_fuera_de_ventana"); return; }

  ultimoContador = contador;     // solo se actualiza si pasó todas las validaciones
  ultimoGateway = millis();

  if (strcmp(orden, "encender") == 0) {
    setRele(true);
    esperandoCaudal = true;
    inicioOrden = millis();
    Serial.printf("[CMD] encender aceptada (contador %ld). Esperando caudal 15 s\n", contador);
  } else if (strcmp(orden, "apagar") == 0) {
    setRele(false);
    esperandoCaudal = false;
    alertaActiva = false;
    Serial.printf("[CMD] apagar aceptada (contador %ld)\n", contador);
  } else {
    rechazar("orden_falsa", "orden_desconocida");
    return;
  }
  publicarEstado();
}

void alRecibir(char* topic, byte* payload, unsigned int len) {
  if (strcmp(topic, TOPIC_GW_ESTADO) == 0) {
    char buf[200];
    unsigned int n = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, payload, n); buf[n] = 0;
    if (!strstr(buf, "offline")) ultimoGateway = millis();   // el gateway sigue vivo
    return;
  }
  if (strcmp(topic, tCmd) == 0) procesarOrden(payload, len);
}

// ---------- Vigilancia local (no depende del gateway) ----------
void vigilar() {
  if (bombaOn && leerCorrienteA() > UMBRAL_SOBRECARGA_A) {
    setRele(false);
    esperandoCaudal = false;
    alertaActiva = true;
    publicarAlerta("sobrecarga", "corriente_mayor_9A", "apagar_bomba2");
    publicarEstado();
  }
  if (esperandoCaudal) {
    if (hayCaudal()) {
      esperandoCaudal = false;
      alertaActiva = false;
      Serial.println("[BOMBA2] caudal confirmado");
      publicarEstado();
    } else if (millis() - inicioOrden >= TIEMPO_CAUDAL_MS) {
      esperandoCaudal = false;
      alertaActiva = true;
      publicarAlerta("falla_bomba2", "sin_caudal_15s", "avisar_gateway");
    }
  }
  digitalWrite(PIN_LED_ALERTA, alertaActiva ? HIGH : LOW);
}

// ---------- Conexión ----------
void conectarMqtt() {
  char cid[24];
  snprintf(cid, sizeof cid, "g3-bomba2-%lu", (unsigned long)(micros() & 0xFFFF));
  // LWT: si el nodo se cae, el broker publica "offline" (no puede llevar firma con hora actual)
  bool ok = mqtt.connect(cid, nullptr, nullptr, tEstado, 0, true,
                         "{\"id\":\"N4\",\"valor\":\"offline\",\"unidad\":\"estado\"}");
  if (ok) {
    mqtt.subscribe(tCmd);
    mqtt.subscribe(TOPIC_GW_ESTADO);
    publicarEstado();
    Serial.println("[MQTT] conectado");
  } else {
    Serial.printf("[MQTT] fallo, estado=%d\n", mqtt.state());
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_CAUDAL, INPUT);
  pinMode(PIN_RELE, OUTPUT);
  pinMode(PIN_LED_ALERTA, OUTPUT);
  setRele(false);
  digitalWrite(PIN_LED_ALERTA, LOW);

  snprintf(tDatos, sizeof tDatos, "%s/datos", TOPIC_BASE);
  snprintf(tAlerta, sizeof tAlerta, "%s/alerta", TOPIC_BASE);
  snprintf(tEstado, sizeof tEstado, "%s/estado", TOPIC_BASE);
  snprintf(tCmd, sizeof tCmd, "%s/cmd", TOPIC_BASE);

  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CANAL);
  Serial.print("Conectando WiFi");
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print("."); }
  Serial.println(WiFi.status() == WL_CONNECTED ? " OK" : " sin WiFi (el nodo sigue con acciones locales)");

  configTime(0, 0, "pool.ntp.org", "time.google.com");   // hora UTC para ts
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(512);
  mqtt.setCallback(alRecibir);
  ultimoGateway = millis();
  tReintentoMs = millis() - 5001;   // primer intento de MQTT sin esperar
}

void loop() {
  if (WiFi.status() == WL_CONNECTED && !mqtt.connected() && millis() - tReintentoMs > 5000) {
    tReintentoMs = millis();
    conectarMqtt();
  }
  mqtt.loop();
  vigilar();   // sobrecarga y caudal: funciona aunque no haya red

  if (mqtt.connected()) {
    if (millis() - tDatosMs >= PERIODO_DATOS_MS)  { tDatosMs = millis();  publicarDatos(); }
    if (millis() - tEstadoMs >= PERIODO_ESTADO_MS) { tEstadoMs = millis(); publicarEstado(); }
  }
}
