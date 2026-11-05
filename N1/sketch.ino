// ===== Nodo 1 - Pluviometro (N1, sector superficie) =====
// Pulsos con ISR + antirrebote, intensidad por ventana, barra de LED con histeresis,
// validacion de rango/salto (ataque 1), MQTT (HiveMQ), HMAC-SHA256, latido, LWT, modo seguro.
// Credenciales y clave HMAC en secrets.h (NO subir a GitHub).

#include <WiFi.h>
#include <PubSubClient.h>
#include <time.h>
#include "mbedtls/md.h"
#include "secrets.h"

// ---------- PINES ----------
const int PIN_BTN = 27;
const int LED_PINS[10] = {13, 14, 16, 17, 18, 19, 21, 22, 23, 25};

// ---------- IDENTIDAD / TOPICOS (contrato del grupo) ----------
const char* NODE_ID = "N1";
const char* SECTOR  = "superficie";
const char* T_DATOS   = "upc/g3/pluviometro/datos";
const char* T_ALERTA  = "upc/g3/pluviometro/alerta";
const char* T_ESTADO  = "upc/g3/pluviometro/estado";
// PROPUESTA: disparo del ataque desde el panel HTML. Ponerse de acuerdo con quien hace la pagina.
const char* T_ATAQUE  = "upc/g3/pluviometro/ataque";
const char* T_GATEWAY = "upc/g3/gateway/#";   // para saber si el gateway esta vivo

// ---------- CONFIGURACION (parametros que te pueden pedir cambiar) ----------
const float MM_POR_PULSO      = 0.2;      // 1 pulso = 0.2 mm
const unsigned long VENTANA_S = 60;       // DECIDE: ventana de intensidad (s)
const unsigned long DEBOUNCE_MS = 50;     // antirrebote
const float RANGO_MAX_MMH     = 200.0;    // DECIDE: maximo fisico plausible
const float SALTO_MAX_MMH     = 60.0;     // DECIDE: salto maximo entre lecturas (1 s)
const int   N_CONFIRMAR       = 5;        // DECIDE: lecturas coherentes seguidas para aceptar un salto real
const unsigned long ATASCADO_MS = 5000;   // pulsador presionado > 5 s = dudoso
const float HISTERESIS        = 0.10;     // 10 %
const unsigned long DATOS_MS  = 2000;     // publicar datos cada 2 s
const unsigned long LATIDO_MS = 30000;    // latido cada 30 s
const unsigned long MODO_SEGURO_MS = 60000; // sin gateway > 60 s
const int   MAX_MSG_S         = 10;       // limite del grupo: 10 mensajes/s por nodo

// Umbrales por segmento (mm/h). LED5 = 10 y LED8 = 25 vienen del grupo. El resto es PROVISIONAL: DECIDE.
const float UMBRAL[10] = {1, 2.5, 5, 7.5, 10, 15, 20, 25, 35, 50};

// ---------- ESTADO ----------
const int RING_N = 128;
volatile unsigned long ringTs[RING_N];
volatile int ringHead = 0;
volatile unsigned long ultimoIsr = 0;
volatile unsigned long totalPulsos = 0;

bool ledOn[10] = {false};
float ultimaValida = 0.0;
float lastRaw = 0.0;
int   saltoSeguidos = 0;
int   ataqueTicks = 0;
float ataqueValor = 0.0;
unsigned long tTick = 0, tDatos = 0, tLatido = 0, tBtnBajo = 0, lastGatewayMs = 0;
String calidadActual = "ok";

WiFiClient net;
PubSubClient mqtt(net);

// ---------- ISR: solo guarda timestamp, nada de Serial ni MQTT ----------
void IRAM_ATTR isrPulso() {
  unsigned long ahora = millis();
  if (ahora - ultimoIsr >= DEBOUNCE_MS) {
    ringTs[ringHead % RING_N] = ahora;
    ringHead++;
    totalPulsos++;
    ultimoIsr = ahora;
  }
}

// ---------- Intensidad (mm/h) con ventana deslizante ----------
float calcularIntensidad() {
  unsigned long ahora = millis();
  int head;
  noInterrupts(); head = ringHead; interrupts();
  int n = head < RING_N ? head : RING_N;
  int enVentana = 0;
  for (int i = 0; i < n; i++) {
    unsigned long ts;
    noInterrupts(); ts = ringTs[(head - 1 - i) % RING_N]; interrupts();
    if (ahora - ts <= VENTANA_S * 1000UL) enVentana++;
    else break;
  }
  return enVentana * MM_POR_PULSO * (3600.0 / VENTANA_S);
}

// ---------- Barra de LED con histeresis ----------
void actualizarBarra(float mmh) {
  for (int i = 0; i < 10; i++) {
    if (!ledOn[i] && mmh >= UMBRAL[i]) ledOn[i] = true;
    else if (ledOn[i] && mmh < UMBRAL[i] * (1.0 - HISTERESIS)) ledOn[i] = false;
    digitalWrite(LED_PINS[i], ledOn[i] ? HIGH : LOW);
  }
}

// ---------- Tiempo y firma ----------
unsigned long nowTs() {                 // segundos UTC; 0 si NTP aun no sincroniza
  time_t t = time(nullptr);
  return t > 1700000000 ? (unsigned long)t : 0;
}

String firmar(const String& msg) {      // HMAC-SHA256 en hex minuscula
  byte out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)HMAC_KEY, strlen(HMAC_KEY));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)msg.c_str(), msg.length());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", out[i]);
  return String(hex);
}

// ---------- Limite de 10 mensajes/s ----------
bool permitirPublicar() {
  static unsigned long inicio = 0;
  static int cuenta = 0;
  unsigned long ahora = millis();
  if (ahora - inicio >= 1000) { inicio = ahora; cuenta = 0; }
  if (cuenta >= MAX_MSG_S) return false;   // exceso descartado
  cuenta++;
  return true;
}

// ---------- Publicacion firmada ----------
// Firma = HMAC-SHA256( id|sector|ts|valor|unidad|calidad ), valor sin comillas.
// valorTok: token JSON ya formateado (numero, o texto entre comillas).
void publicar(const char* topic, const String& valorTok, const char* unidad,
              const char* calidad, const String& extra) {
  if (!mqtt.connected() || !permitirPublicar()) return;
  unsigned long ts = nowTs();
  String valorPlano = valorTok;
  valorPlano.replace("\"", "");
  String canon = String(NODE_ID) + "|" + SECTOR + "|" + ts + "|" + valorPlano + "|" + unidad + "|" + calidad;
  String p = String("{\"id\":\"") + NODE_ID + "\",\"sector\":\"" + SECTOR + "\",\"ts\":" + ts +
             ",\"valor\":" + valorTok + ",\"unidad\":\"" + unidad + "\",\"calidad\":\"" + calidad +
             "\",\"firma\":\"" + firmar(canon) + "\"" + extra + "}";
  mqtt.publish(topic, p.c_str());
}

void publicarAlerta(float valorRechazado, const char* motivo) {
  String extra = String(",\"tipo\":\"lectura_falsificada\",\"accion\":\"descartada, se mantiene ultimo valor valido\",\"motivo\":\"") + motivo + "\"";
  publicar(T_ALERTA, String(valorRechazado, 1), "mm/h", "falla", extra);
}

void publicarEstado(bool modoSeguro) {
  publicar(T_ESTADO, modoSeguro ? "\"modo_seguro\"" : "\"online\"", "", "ok", "");
}

// ---------- Callback MQTT ----------
void onMensaje(char* topic, byte* payload, unsigned int len) {
  String t(topic);
  if (t.startsWith("upc/g3/gateway/")) { lastGatewayMs = millis(); return; }
  if (t == T_ATAQUE) {
    String m; for (unsigned int i = 0; i < len; i++) m += (char)payload[i];
    if (m.indexOf("salto") >= 0)      { ataqueValor = 150.0; ataqueTicks = 3; }  // dentro de rango, salto brusco
    else if (m.indexOf("rango") >= 0) { ataqueValor = 500.0; ataqueTicks = 3; }  // fuera de rango
  }
}

// ---------- Conexion MQTT sin bloquear (modo seguro: lo local sigue sin red) ----------
void mantenerMqtt() {
  static unsigned long tIntento = 0, backoff = 2000;
  if (WiFi.status() != WL_CONNECTED || mqtt.connected()) return;
  if (millis() - tIntento < backoff) return;
  tIntento = millis();
  String cid = "upc-g3-n1-" + String(random(0xffff), HEX);
  if (mqtt.connect(cid.c_str(), NULL, NULL, T_ESTADO, 0, true, "offline")) {   // LWT = offline
    mqtt.subscribe(T_ATAQUE);
    mqtt.subscribe(T_GATEWAY);
    backoff = 2000;
    publicarEstado(false);
    Serial.println("MQTT conectado");
  } else {
    backoff = min(backoff * 2, 30000UL);
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_BTN, INPUT_PULLUP);
  for (int i = 0; i < 10; i++) pinMode(LED_PINS[i], OUTPUT);
  for (int i = 0; i < 10; i++) { digitalWrite(LED_PINS[i], HIGH); delay(80); }
  for (int i = 0; i < 10; i++) digitalWrite(LED_PINS[i], LOW);

  attachInterrupt(digitalPinToInterrupt(PIN_BTN), isrPulso, FALLING);

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS, 6);          // Wokwi-GUEST usa canal 6
  configTime(0, 0, "pool.ntp.org", "time.google.com");   // UTC
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMensaje);
  mqtt.setBufferSize(512);
  mqtt.setSocketTimeout(2);
  lastGatewayMs = millis();
  Serial.println("Nodo 1 listo. Serial: 'a' = ataque rango, 's' = ataque salto.");
}

void loop() {
  mantenerMqtt();
  mqtt.loop();

  if (Serial.available()) {                      // disparo local de respaldo
    char c = Serial.read();
    if (c == 'a') { ataqueValor = 500.0; ataqueTicks = 3; }
    if (c == 's') { ataqueValor = 150.0; ataqueTicks = 3; }
  }

  // Pulsador atascado
  if (digitalRead(PIN_BTN) == LOW) { if (tBtnBajo == 0) tBtnBajo = millis(); }
  else tBtnBajo = 0;
  bool atascado = (tBtnBajo != 0) && (millis() - tBtnBajo > ATASCADO_MS);

  bool modoSeguro = (millis() - lastGatewayMs) > MODO_SEGURO_MS;   // la barra sigue igual: es local

  // ---- Tick de 1 s: medir, validar, actuar ----
  if (millis() - tTick >= 1000) {
    tTick = millis();
    float raw = calcularIntensidad();
    if (ataqueTicks > 0) { raw = ataqueValor; ataqueTicks--; }   // ataque 1: lectura falsificada

    bool rechazada = false;
    const char* motivo = "";
    if (raw < 0 || raw > RANGO_MAX_MMH) {
      rechazada = true; motivo = "fuera de rango"; saltoSeguidos = 0;
    } else if (raw - ultimaValida > SALTO_MAX_MMH) {
      // Si el salto se mantiene coherente N lecturas, es lluvia real: se acepta (evita falso positivo)
      if (fabs(raw - lastRaw) <= SALTO_MAX_MMH) saltoSeguidos++; else saltoSeguidos = 1;
      if (saltoSeguidos >= N_CONFIRMAR) saltoSeguidos = 0;
      else { rechazada = true; motivo = "salto excesivo"; }
    } else {
      saltoSeguidos = 0;
    }
    lastRaw = raw;

    if (rechazada) {
      calidadActual = "falla";
      Serial.printf("[ALERTA] rechazada %.1f mm/h, motivo: %s, accion: se mantiene %.1f\n", raw, motivo, ultimaValida);
      publicarAlerta(raw, motivo);
    } else {
      ultimaValida = raw;
      calidadActual = atascado ? "dudosa" : "ok";
    }
    actualizarBarra(ultimaValida);
    Serial.printf("acum=%.1f mm | int=%.1f mm/h | calidad=%s | modo_seguro=%d\n",
                  totalPulsos * MM_POR_PULSO, ultimaValida, calidadActual.c_str(), modoSeguro);
  }

  // ---- Datos cada 2 s ----
  if (millis() - tDatos >= DATOS_MS) {
    tDatos = millis();
    String extra = String(",\"acum_mm\":") + String(totalPulsos * MM_POR_PULSO, 1);
    publicar(T_DATOS, String(ultimaValida, 1), "mm/h", calidadActual.c_str(), extra);
  }

  // ---- Latido cada 30 s ----
  if (millis() - tLatido >= LATIDO_MS) {
    tLatido = millis();
    publicarEstado(modoSeguro);
  }
}
