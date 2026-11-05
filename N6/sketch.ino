// G3 - Minería de tajo abierto (TMS) - Nodo 6: Piezómetro
// Detecta: potenciómetro en GPIO34 que simula el lazo 4-20 mA del piezómetro (presión de agua en la pared).
// Actúa:   LED RGB = baliza de presión (verde / amarillo / rojo; azul parpadeando = falla del sensor).
// Edge:    la baliza decide con umbrales propios, sin esperar al gateway (modo seguro si no hay gateway > 60 s).
// Ataque 6: inundación de mensajes en /cmd. Defensa: límite de 5 msg/s (cubeta de fichas) y descarte del exceso.
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include "mbedtls/md.h"
#include "secrets.h"  // HMAC_KEY y credenciales: nunca se sube a GitHub

const int PIN_PIEZO = 34;
const int PIN_R = 25, PIN_G = 26, PIN_B = 27;

const char* NODO_ID = "N6";      // convención del grupo: N1 a N8
const char* SECTOR  = "pared";   // convención: superficie, fondo, poza, pared, control
const char* T_DATOS  = "upc/g3/piezometro/datos";
const char* T_ALERTA = "upc/g3/piezometro/alerta";
const char* T_ESTADO = "upc/g3/piezometro/estado";
const char* T_CMD    = "upc/g3/piezometro/cmd";

// Escala y umbrales: SUPUESTOS del grupo, se ajustan con la ficha del piezómetro y el estudio geotécnico.
const float KPA_MAX       = 600.0;  // 20 mA = 600 kPa
const float UMBRAL_AMAR   = 200.0;  // kPa (umbral del grupo, sección 5)
const float UMBRAL_ROJO   = 300.0;  // kPa (umbral del grupo, sección 5)
const float HISTERESIS    = 10.0;   // kPa, evita que la baliza parpadee en el borde
const float MA_MIN_VALIDO = 3.6;    // menos = cable cortado (NAMUR NE43)
const float MA_MAX_VALIDO = 21.0;   // más = sensor saturado o en corto

const unsigned long PERIODO_DATOS = 2000;   // dashboard edge: cada 1 a 2 s
const unsigned long PERIODO_LATIDO = 30000;
const unsigned long TIMEOUT_GW = 60000;     // regla 4: modo seguro
const float RATE_MSG_S = 10.0, RAFAGA_MAX = 10.0;  // defensa contra inundación: 10 msg/s del grupo

WiFiClient red;
PubSubClient mqtt(red);

enum Nivel { VERDE, AMARILLO, ROJO, FALLA };
const char* NOMBRE_NIVEL[] = {"verde", "amarillo", "rojo", "falla_sensor"};
Nivel nivel = VERDE;
float presionKpa = 0, corrienteMa = 0;
const char* calidad = "ok";

unsigned long ultDatos = 0, ultLatido = 0, ultGateway = 0;
bool modoSeguro = true;  // arranca sin gateway hasta recibir su primer latido firmado
unsigned long ultimoCtrGw = 0;
bool ntpPedido = false;

float fichas = RAFAGA_MAX;
unsigned long ultRecarga = 0, descartados = 0, sinFirma = 0, repetidas = 0, ultAvisoAtaque = 0;

// ts del contrato: segundos UTC por NTP (se pide recién con WiFi conectado). 0 = aún sin hora.
unsigned long ahora() {
  time_t t = time(nullptr);
  return t > 1700000000 ? (unsigned long)t : 0;
}

String hmacHex(const String& msg) {
  uint8_t out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const uint8_t*)HMAC_KEY, strlen(HMAC_KEY));
  mbedtls_md_hmac_update(&ctx, (const uint8_t*)msg.c_str(), msg.length());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", out[i]);
  return String(hex);
}

// Mensaje del contrato: id, sector, ts, valor, unidad, calidad y firma.
// firma = HMAC(id|sector|ts|valor|unidad|calidad), con valor tal como sale en el JSON y sin comillas.
void publicarFirmado(const char* topico, JsonDocument& doc, bool retener = false) {
  doc["id"] = NODO_ID;
  doc["sector"] = SECTOR;
  unsigned long ts = ahora();
  doc["ts"] = ts;
  String valor;
  serializeJson(doc["valor"], valor);
  valor.replace("\"", "");
  String canon = String(NODO_ID) + "|" + SECTOR + "|" + String(ts) + "|" + valor + "|" +
                 String(doc["unidad"] | "") + "|" + String(doc["calidad"] | "");
  doc["firma"] = hmacHex(canon);
  String msg;
  serializeJson(doc, msg);
  mqtt.publish(topico, msg.c_str(), retener);
}

void baliza(Nivel n) {
  bool on = (millis() / 400) % 2;
  switch (n) {
    case VERDE:    analogWrite(PIN_R, 0);   analogWrite(PIN_G, 255); analogWrite(PIN_B, 0); break;
    case AMARILLO: analogWrite(PIN_R, 255); analogWrite(PIN_G, 120); analogWrite(PIN_B, 0); break;
    case ROJO:     analogWrite(PIN_R, 255); analogWrite(PIN_G, 0);   analogWrite(PIN_B, 0); break;
    case FALLA:    analogWrite(PIN_R, 0);   analogWrite(PIN_G, 0);   analogWrite(PIN_B, on ? 255 : 0); break;
  }
}

Nivel clasificar(float kpa, Nivel previo) {
  if (kpa >= UMBRAL_ROJO || (previo == ROJO && kpa >= UMBRAL_ROJO - HISTERESIS)) return ROJO;
  if (kpa >= UMBRAL_AMAR || (previo >= AMARILLO && previo != FALLA && kpa >= UMBRAL_AMAR - HISTERESIS)) return AMARILLO;
  return VERDE;
}

void leerPiezometro() {
  corrienteMa = analogRead(PIN_PIEZO) * 24.0 / 4095.0;  // el pot recorre 0-24 mA para poder simular fallas
  Nivel previo = nivel;
  if (corrienteMa < MA_MIN_VALIDO)      { calidad = "falla_lazo"; nivel = FALLA; }
  else if (corrienteMa > MA_MAX_VALIDO) { calidad = "saturado";   nivel = FALLA; }
  else {
    calidad = "ok";
    presionKpa = constrain((corrienteMa - 4.0) / 16.0 * KPA_MAX, 0, KPA_MAX);
    nivel = clasificar(presionKpa, previo);
  }
  if (nivel != previo) {
    JsonDocument a;
    a["tipo"] = "presion";
    a["valor"] = NOMBRE_NIVEL[nivel];
    a["unidad"] = "nivel";
    a["calidad"] = calidad;
    a["kpa"] = presionKpa;
    publicarFirmado(T_ALERTA, a);
    Serial.printf("[EDGE] baliza %s -> %s (%.0f kPa, %.2f mA)\n", NOMBRE_NIVEL[previo], NOMBRE_NIVEL[nivel], presionKpa, corrienteMa);
  }
}

void eventoSeguridad(const char* ataque, const String& accion, const char* motivo) {
  JsonDocument e;
  e["tipo"] = "seguridad";
  e["ataque"] = ataque;
  e["valor"] = accion;
  e["unidad"] = "evento";
  e["calidad"] = "ok";
  e["motivo"] = motivo;
  publicarFirmado(T_ALERTA, e);
  Serial.printf("[SEG] %s: %s (%s)\n", ataque, accion.c_str(), motivo);
}

bool pasaLimite() {
  unsigned long t = millis();
  fichas = min(RAFAGA_MAX, fichas + (t - ultRecarga) * RATE_MSG_S / 1000.0f);
  ultRecarga = t;
  if (fichas >= 1) { fichas -= 1; return true; }
  descartados++;
  return false;
}

// Orden del gateway (formato del grupo): {"orden","contador","ts","firma"}
// firma = HMAC(N6|orden|contador|ts); contador creciente; ts de máximo 30 s.
void alRecibir(char* topico, byte* datos, unsigned int largo) {
  if (!pasaLimite()) return;  // exceso descartado antes de parsear o verificar firma
  JsonDocument d;
  if (deserializeJson(d, datos, largo)) { sinFirma++; return; }
  const char* firma = d["firma"] | "";
  unsigned long ctr = d["contador"] | 0UL;
  unsigned long ts = d["ts"] | 0UL;
  String orden = d["orden"] | "";
  String canon = String(NODO_ID) + "|" + orden + "|" + String(ctr) + "|" + String(ts);
  if (hmacHex(canon) != firma) { sinFirma++; return; }
  unsigned long t = ahora();
  if (ctr <= ultimoCtrGw || (t != 0 && labs((long)(t - ts)) > 30)) { repetidas++; return; }
  ultimoCtrGw = ctr;
  ultGateway = millis();
  if (modoSeguro) { modoSeguro = false; Serial.println("[FOG] gateway en linea, sale de modo seguro"); }
}

// Los rechazos se cuentan y se reportan juntos cada 5 s: un evento por mensaje amplificaría el ataque.
void revisarInundacion() {
  if (descartados + sinFirma + repetidas == 0 || millis() - ultAvisoAtaque < 5000) return;
  if (descartados) eventoSeguridad("inundacion", "descartados " + String(descartados) + " mensajes", "supera 5 msg/s en /cmd");
  if (sinFirma)    eventoSeguridad("orden_sin_firma", "rechazadas " + String(sinFirma) + " ordenes", "firma HMAC invalida");
  if (repetidas)   eventoSeguridad("repeticion", "rechazadas " + String(repetidas) + " ordenes", "contador repetido");
  descartados = sinFirma = repetidas = 0;
  ultAvisoAtaque = millis();
}

void publicarEstado(const char* estado) {
  JsonDocument s;
  s["valor"] = estado;
  s["unidad"] = "estado";
  s["calidad"] = calidad;
  s["modo_seguro"] = modoSeguro;
  publicarFirmado(T_ESTADO, s, true);
}

void conectar() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (!ntpPedido) { configTime(0, 0, "pool.ntp.org", "time.google.com"); ntpPedido = true; }
  if (mqtt.connected()) return;
  static unsigned long ultIntento = 0;
  if (millis() - ultIntento < 3000) return;  // reintenta sin bloquear la baliza
  ultIntento = millis();
  String cid = String(NODO_ID) + "-" + String((uint32_t)ESP.getEfuseMac(), HEX);
  if (mqtt.connect(cid.c_str(), T_ESTADO, 1, true, "offline")) {  // LWT = offline
    mqtt.subscribe(T_CMD);
    publicarEstado("online");
    Serial.println("[MQTT] conectado");
  }
}

// Autoprueba por el monitor serie: FLOOD envía 300 órdenes sin firma a su propio /cmd.
void comandosSerie() {
  if (!Serial.available()) return;
  String c = Serial.readStringUntil('\n');
  c.trim();
  if (c == "FLOOD") {
    for (int i = 0; i < 300; i++) mqtt.publish(T_CMD, "{\"orden\":\"apagar_baliza\",\"contador\":1,\"ts\":0}");
    Serial.println("[TEST] 300 mensajes enviados a /cmd");
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_R, OUTPUT); pinMode(PIN_G, OUTPUT); pinMode(PIN_B, OUTPUT);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(512);
  mqtt.setCallback(alRecibir);
  ultRecarga = millis();
  Serial.println("[N6] piezometro listo. Comando de prueba: FLOOD");
}

void loop() {
  leerPiezometro();
  baliza(nivel);  // acción local primero: no depende de WiFi, MQTT ni gateway
  conectar();
  mqtt.loop();
  revisarInundacion();
  comandosSerie();

  if (!modoSeguro && millis() - ultGateway > TIMEOUT_GW) {
    modoSeguro = true;
    Serial.println("[EDGE] sin gateway > 60 s: modo seguro, la baliza sigue con sus umbrales");
    if (mqtt.connected()) publicarEstado("modo_seguro");
  }
  if (!mqtt.connected()) return;

  if (millis() - ultDatos >= PERIODO_DATOS) {
    ultDatos = millis();
    JsonDocument d;
    d["valor"] = round(presionKpa * 10) / 10.0;
    d["unidad"] = "kPa";
    d["calidad"] = calidad;
    d["ma"] = round(corrienteMa * 100) / 100.0;
    d["nivel"] = NOMBRE_NIVEL[nivel];
    publicarFirmado(T_DATOS, d);
  }
  if (millis() - ultLatido >= PERIODO_LATIDO) {
    ultLatido = millis();
    publicarEstado(modoSeguro ? "modo_seguro" : "online");
  }
}
