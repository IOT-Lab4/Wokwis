// ===== G3 Minería de tajo abierto (TMS) - Nodo 8: Gateway (fog), integrador =====
// Detecta: pulsador de reconocimiento (digital) y reloj DS1307 (I2C, hora sin internet).
// Actúa:   pantalla TFT ILI9341 (SPI, panel de operación) y NeoPixel (semáforo de evacuación).
// Fog:     combina lluvia (N1), nivel del sumidero (N2), presión (N6) y desplazamiento (N7)
//          en alerta verde / amarilla / roja (alternativa B) y calcula también la alternativa A.
// Lazo:    ordena la bomba 1, exige caudal en 15 s; si no llega, "falla de bomba" y bomba 2 en 5 s más.
// Nube:    único nodo que escribe en ThingSpeak, cada 16 s (>= 15 s) cuando hay enlace.
// Ataque 8: cambio de configuración no autorizado. Defensa: firma + contador + ts,
//          rango seguro, doble confirmación local (pulsador) y registro de eventos.
// Claves en secrets.h (fuera de GitHub).

#include <WiFi.h>
#include <PubSubClient.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <SPI.h>
#include <RTClib.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <Adafruit_NeoPixel.h>
#include <time.h>
#include <math.h>
#include "mbedtls/md.h"
#include "secrets.h"

// ---------- PINES ----------
const int PIN_TFT_CS  = 15;
const int PIN_TFT_DC  = 2;
const int PIN_TFT_RST = 4;      // SPI por hardware: SCK 18, MOSI 23, MISO 19
const int PIN_NEOPIXEL = 13;
const int N_PIXELES    = 12;
const int PIN_BOTON    = 14;    // pulsador de reconocimiento a GND (INPUT_PULLUP)
const int PIN_SDA      = 21;    // DS1307
const int PIN_SCL      = 22;

// ---------- IDENTIDAD Y TÓPICOS (contrato del grupo) ----------
const char* ID_GW      = "N8";
const char* SECTOR_GW  = "control";
const char* T_GW_DATOS  = "upc/g3/gateway/datos";
const char* T_GW_ALERTA = "upc/g3/gateway/alerta";
const char* T_GW_ESTADO = "upc/g3/gateway/estado";
const char* T_GW_CONFIG = "upc/g3/gateway/config";   // solicitudes de cambio de parámetros (ataque 8)
const char* T_GW_ATAQUE = "upc/g3/gateway/ataque";   // botón de ataque del panel HTML

// ---------- PARÁMETROS DE LAS REGLAS (los que el docente puede pedir cambiar) ----------
struct Parametros {
  float lluviaAmar, lluviaRojo;     // mm/h
  float sumAmar, sumMax, sumApagar; // %
  float presAmar, presRojo;         // kPa
  float despAmar, despComb, despRojo; // mm/h
};
Parametros P = {10, 25, 60, 80, 40, 200, 300, 2, 5, 10};

// Rango seguro: ni con firma válida se acepta un valor fuera de aquí (defensa del ataque 8).
struct ParamDef { const char* nombre; float* ptr; float minSeg; float maxSeg; };
ParamDef PARAMS[] = {
  {"lluvia_amarillo",   &P.lluviaAmar, 5,   20},
  {"lluvia_rojo",       &P.lluviaRojo, 15,  40},
  {"sumidero_amarillo", &P.sumAmar,    40,  75},
  {"sumidero_max",      &P.sumMax,     60,  90},
  {"presion_amarillo",  &P.presAmar,   100, 300},
  {"presion_rojo",      &P.presRojo,   200, 400},
  {"desp_amarillo",     &P.despAmar,   1,   5},
  {"desp_combinado",    &P.despComb,   2,   10},
  {"desp_rojo",         &P.despRojo,   5,   15},
};
const int N_PARAMS = sizeof(PARAMS) / sizeof(PARAMS[0]);

char alternativa = 'B';   // la que manda el semáforo; las dos se calculan y publican

// N7 publica inclinación (grados) y giro (grados/s), no mm/h. Conversión PROPUESTA del gateway,
// calibrada con los umbrales del propio N7: 12° o 5 °/s = 10 mm/h (rojo); 5° o 2 °/s ~ 4 mm/h (amarillo).
const float K_ANGULO = 10.0 / 12.0;   // mm/h por grado
const float K_GIRO   = 2.0;           // mm/h por grado/s

// ---------- TIEMPOS ----------
const unsigned long DATOS_MS        = 2000;    // panel en vivo cada 2 s
const unsigned long LATIDO_MS       = 30000;   // latido del gateway
const unsigned long NUBE_MS         = 16000;   // ThingSpeak, >= 15 s
const unsigned long VIGENCIA_MS     = 20000;   // una lectura más vieja no cuenta en las reglas
const unsigned long NODO_CAIDO_MS   = 65000;   // sin mensajes > 65 s = nodo caído (latido 30 s)
const unsigned long CAUDAL_MS       = 15000;   // confirmación de caudal
const unsigned long RESPALDO_MS     = 5000;    // arranque de la otra bomba
const unsigned long REINTENTO_MS    = 60000;   // reintento si fallan las dos bombas
const unsigned long CONFIRMAR_MS    = 20000;   // ventana para la doble confirmación
const unsigned long LATIDO_N6_MS    = 20000;   // N6 sale de modo seguro con órdenes firmadas
const unsigned long RESUMEN_SEG_MS  = 5000;    // eventos de seguridad agrupados
const long          TS_VENTANA_S    = 30;      // una orden o solicitud vale 30 s
const int           MAX_MSG_S       = 10;      // límite del grupo por nodo

// ---------- NODOS ----------
enum Firma { F_CONTRATO, F_N5, F_N6_CUERPO, F_N7, F_NINGUNA };
// F_CONTRATO : HMAC(id|sector|ts|valor|unidad|calidad)        todos los nodos (versión integrada)
// Los otros formatos quedan para leer las versiones anteriores de N3, N5, N6 y N7.
// F_N5       : HMAC(id|sector|ts|valor), solo en /datos        N5
// F_N6_CUERPO: HMAC(JSON completo sin el campo firma)           N6
// F_N7       : HMAC(id|sector|ts|valor|unidad)                 N7
// F_NINGUNA  : N3 publica "firma":"pendiente"

struct Nodo {
  const char* topico;
  const char* etiqueta;
  const char* clave;
  Firma firma;
  unsigned long ultimoMs;
  bool lwtCaido;
  unsigned long ventanaMs;
  int cuentaVentana;
  unsigned long descartados;
  unsigned long firmasMalas;
};
Nodo nodos[7] = {
  {"pluviometro",  "N1", CLAVE_N1, F_CONTRATO,  0, false, 0, 0, 0, 0},
  {"sumidero",     "N2", CLAVE_N2, F_CONTRATO,  0, false, 0, 0, 0, 0},
  {"bomba1",       "N3", CLAVE_N3, F_CONTRATO,   0, false, 0, 0, 0, 0},
  {"bomba2",       "N4", CLAVE_N4, F_CONTRATO,  0, false, 0, 0, 0, 0},
  {"poza",         "N5", CLAVE_N5, F_CONTRATO,        0, false, 0, 0, 0, 0},
  {"piezometro",   "N6", CLAVE_N6, F_CONTRATO, 0, false, 0, 0, 0, 0},
  {"inclinometro", "N7", CLAVE_N7, F_CONTRATO,        0, false, 0, 0, 0, 0},
};
const int N_NODOS = 7;

// ---------- VARIABLES DEL TAJO ----------
enum { V_LLUVIA, V_SUMIDERO, V_POZA, V_PRESION, V_DESP, N_VARS };
struct Variable {
  const char* nombre;
  const char* unidad;
  float valor;
  unsigned long ms;
  float sim;
  unsigned long simHasta;
};
Variable vars[N_VARS] = {
  {"Lluvia",   "mm/h", NAN, 0, NAN, 0},
  {"Sumidero", "%",    NAN, 0, NAN, 0},
  {"Poza",     "%",    NAN, 0, NAN, 0},
  {"Presion",  "kPa",  NAN, 0, NAN, 0},
  {"Desplaz.", "mm/h", NAN, 0, NAN, 0},
};
bool sirenaN7 = false;

// ---------- BOMBAS Y LAZO CERRADO ----------
struct Bomba {
  int nodo;               // índice en nodos[]
  const char* nombre;
  int caudal;             // -1 sin dato, 0 o 1
  unsigned long caudalMs; // última vez que llegó el dato de caudal
  unsigned long ultimoCaudal1Ms;
  float corriente;
  bool on;
};
Bomba bombas[2] = {
  {2, "bomba1", -1, 0, 0, NAN, false},
  {3, "bomba2", -1, 0, 0, NAN, false},
};
enum EstadoLazo { L_REPOSO, L_ESPERA_B1, L_B1_OK, L_PAUSA_RESPALDO, L_ESPERA_B2, L_B2_OK, L_FALLA_TOTAL };
const char* NOMBRE_LAZO[] = {"reposo", "espera_caudal_b1", "bomba1_ok", "arranque_respaldo",
                             "espera_caudal_b2", "bomba2_ok", "falla_ambas"};
EstadoLazo lazo = L_REPOSO;
unsigned long tLazo = 0, tOrdenInicial = 0;
int bombaActiva = -1;
int forzarBombeo = -1;     // -1 automático, 0 apagado, 1 encendido (comando serie)
bool demandaLatch = false;
bool pozaOrdenada = false;

// ---------- ALERTA ----------
const char* NOMBRE_NIVEL[] = {"verde", "amarillo", "rojo"};
int nivelA = 0, nivelB = 0, nivelActual = 0;
bool reconocida = false;
unsigned long tCambioNivel = 0;

// ---------- SEGURIDAD ----------
struct Evento { char hora[24]; char nodo[6]; char ataque[32]; char accion[44]; char motivo[48]; };
Evento ultimoEvento = {"", "", "", "", ""};
unsigned long totalEventos = 0;
unsigned long eventosNodos = 0;         // rechazos reportados por los propios nodos
char ultimoEventoNodo[64] = "";
unsigned long ultimoCtrConfig = 0;
int cuentaConfig = 0; unsigned long ventanaConfig = 0, descartesConfig = 0;
struct Pendiente { bool activo; int def; float valor; unsigned long expira; char origen[12]; };
Pendiente pendiente = {false, -1, 0, 0, ""};

// ---------- OBJETOS ----------
WiFiClient red;
PubSubClient mqtt(red);
Adafruit_ILI9341 tft(PIN_TFT_CS, PIN_TFT_DC, PIN_TFT_RST);
Adafruit_NeoPixel semaforo(N_PIXELES, PIN_NEOPIXEL, NEO_GRB + NEO_KHZ800);
RTC_DS1307 rtc;
bool rtcOk = false, rtcSincronizado = false;
unsigned long tRtcSync = 0;
unsigned long ultimoContador = 0;

// Foto para la tarea de la nube (corre en el otro núcleo)
struct Foto { float v[N_VARS]; int nivelA, nivelB; unsigned long eventos; };
Foto foto;
portMUX_TYPE muxFoto = portMUX_INITIALIZER_UNLOCKED;
volatile int nubeCodigo = 0;
volatile unsigned long nubeEnvios = 0;

unsigned long tEval = 0, tDatos = 0, tLatido = 0, tN6 = 0, tResumen = 0, tIntentoMqtt = 0;
int nivelDibujado = -1;

// =====================================================================
//                              UTILIDADES
// =====================================================================
unsigned long ahoraUtc() {                       // segundos UTC; NTP y, sin internet, el DS1307
  time_t t = time(nullptr);
  if (t > 1700000000) return (unsigned long)t;
  if (rtcOk) {
    uint32_t u = rtc.now().unixtime();
    if (u > 1700000000UL) return u;
  }
  return 0;
}

void horaTexto(char* out, size_t n, bool soloHora) {   // hora local de Lima (UTC-5)
  unsigned long u = ahoraUtc();
  if (u == 0) { snprintf(out, n, soloHora ? "--:--:--" : "sin hora"); return; }
  time_t lt = (time_t)u - 5 * 3600;
  struct tm tmv;
  gmtime_r(&lt, &tmv);
  if (soloHora) snprintf(out, n, "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
  else snprintf(out, n, "%04d-%02d-%02d %02d:%02d:%02d", tmv.tm_year + 1900, tmv.tm_mon + 1,
                tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

void hmacHex(const char* clave, const char* msg, char* out65) {
  unsigned char h[32];
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                  (const unsigned char*)clave, strlen(clave),
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

// Extrae el texto crudo de un campo de un JSON plano, tal como viene en el mensaje.
// Se usa el texto crudo (y no un número ya convertido) para rehacer la firma exactamente igual.
bool campo(const char* js, const char* clave, char* out, size_t n) {
  char patron[40];
  snprintf(patron, sizeof patron, "\"%s\":", clave);
  const char* p = strstr(js, patron);
  out[0] = 0;
  if (!p) return false;
  p += strlen(patron);
  while (*p == ' ') p++;
  size_t k = 0;
  if (*p == '"') {
    p++;
    while (*p && *p != '"' && k < n - 1) out[k++] = *p++;
  } else {
    while (*p && *p != ',' && *p != '}' && k < n - 1) out[k++] = *p++;
    while (k > 0 && out[k - 1] == ' ') k--;
  }
  out[k] = 0;
  return true;
}

float campoF(const char* js, const char* clave, float porDefecto) {
  char b[24];
  if (!campo(js, clave, b, sizeof b) || b[0] == 0 || !strcmp(b, "null")) return porDefecto;
  return atof(b);
}

unsigned long siguienteContador() {              // creciente aunque el gateway se reinicie
  unsigned long t = ahoraUtc();
  unsigned long c = (t > 1700000000UL) ? (t - 1700000000UL) * 10UL : ultimoContador + 1;
  if (c <= ultimoContador) c = ultimoContador + 1;
  ultimoContador = c;
  return c;
}

void numTexto(float v, char* out, size_t n) {
  if (isnan(v)) snprintf(out, n, "null");
  else snprintf(out, n, "%.1f", v);
}

// ---------- Variables con vigencia y simulación ----------
bool esSimulada(int i) {
  return vars[i].simHasta != 0 && (long)(vars[i].simHasta - millis()) > 0;
}
float leerVar(int i) {
  if (esSimulada(i)) return vars[i].sim;
  if (vars[i].ms != 0 && millis() - vars[i].ms <= VIGENCIA_MS) return vars[i].valor;
  return NAN;
}
void ponerVar(int i, float v) { vars[i].valor = v; vars[i].ms = millis(); }

bool nodoEnLinea(int i) {
  return nodos[i].ultimoMs != 0 && !nodos[i].lwtCaido && millis() - nodos[i].ultimoMs <= NODO_CAIDO_MS;
}

// =====================================================================
//                       PUBLICACIÓN DEL GATEWAY
// =====================================================================
int cuentaPropia = 0; unsigned long ventanaPropia = 0;

// Mensaje del contrato, firmado: HMAC(id|sector|ts|valor|unidad|calidad).
void publicarGw(const char* topico, const char* valor, bool valorEsTexto, const char* unidad,
                const char* extra, bool retener) {
  if (!mqtt.connected()) return;
  if (millis() - ventanaPropia >= 1000) { ventanaPropia = millis(); cuentaPropia = 0; }
  if (cuentaPropia >= MAX_MSG_S) return;           // el gateway también respeta 10 msg/s
  cuentaPropia++;
  unsigned long ts = ahoraUtc();
  char canon[200], firma[65];
  snprintf(canon, sizeof canon, "%s|%s|%lu|%s|%s|ok", ID_GW, SECTOR_GW, ts, valor, unidad);
  hmacHex(CLAVE_N8, canon, firma);
  static char msg[960];
  snprintf(msg, sizeof msg,
           valorEsTexto
             ? "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%lu,\"valor\":\"%s\",\"unidad\":\"%s\",\"calidad\":\"ok\",\"firma\":\"%s\"%s}"
             : "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%lu,\"valor\":%s,\"unidad\":\"%s\",\"calidad\":\"ok\",\"firma\":\"%s\"%s}",
           ID_GW, SECTOR_GW, ts, valor, unidad, firma, extra ? extra : "");
  mqtt.publish(topico, msg, retener);
}

void eventoSeguridad(const char* nodo, const char* ataque, const char* accion, const char* motivo) {
  horaTexto(ultimoEvento.hora, sizeof ultimoEvento.hora, false);
  strncpy(ultimoEvento.nodo, nodo, sizeof ultimoEvento.nodo - 1);
  strncpy(ultimoEvento.ataque, ataque, sizeof ultimoEvento.ataque - 1);
  strncpy(ultimoEvento.accion, accion, sizeof ultimoEvento.accion - 1);
  strncpy(ultimoEvento.motivo, motivo, sizeof ultimoEvento.motivo - 1);
  ultimoEvento.nodo[sizeof ultimoEvento.nodo - 1] = 0;
  ultimoEvento.ataque[sizeof ultimoEvento.ataque - 1] = 0;
  ultimoEvento.accion[sizeof ultimoEvento.accion - 1] = 0;
  ultimoEvento.motivo[sizeof ultimoEvento.motivo - 1] = 0;
  totalEventos++;
  char extra[320];
  snprintf(extra, sizeof extra,
           ",\"tipo\":\"seguridad\",\"hora\":\"%s\",\"nodo\":\"%s\",\"ataque\":\"%s\",\"accion\":\"%s\",\"motivo\":\"%s\"",
           ultimoEvento.hora, ultimoEvento.nodo, ultimoEvento.ataque, ultimoEvento.accion, ultimoEvento.motivo);
  publicarGw(T_GW_ALERTA, ultimoEvento.accion, true, "evento", extra, false);
  Serial.printf("[SEGURIDAD] %s | nodo %s | %s | %s | %s\n", ultimoEvento.hora, nodo, ataque, accion, motivo);
}

void eventoOperacion(const char* tipo, const char* valor, const char* detalle) {
  char hora[24];
  horaTexto(hora, sizeof hora, false);
  char extra[300];
  snprintf(extra, sizeof extra, ",\"tipo\":\"%s\",\"hora\":\"%s\",\"detalle\":\"%s\"", tipo, hora, detalle);
  publicarGw(T_GW_ALERTA, valor, true, "evento", extra, false);
  Serial.printf("[OPERACION] %s | %s | %s | %s\n", hora, tipo, valor, detalle);
}

// =====================================================================
//                     ÓRDENES FIRMADAS A LOS NODOS
// =====================================================================
// N3 y N4: {"orden","contador","ts","firma"}  firma = HMAC(clave_nodo, id|orden|contador|ts)
void ordenBomba(int k, const char* orden) {
  const Nodo& nd = nodos[bombas[k].nodo];
  unsigned long c = siguienteContador();
  unsigned long ts = ahoraUtc();
  char canon[96], firma[65], msg[220], topico[40];
  snprintf(canon, sizeof canon, "%s|%s|%lu|%lu", nd.etiqueta, orden, c, ts);
  hmacHex(nd.clave, canon, firma);
  snprintf(msg, sizeof msg, "{\"orden\":\"%s\",\"contador\":%lu,\"ts\":%lu,\"firma\":\"%s\"}", orden, c, ts, firma);
  snprintf(topico, sizeof topico, "upc/g3/%s/cmd", nd.topico);
  if (mqtt.connected()) mqtt.publish(topico, msg);
  Serial.printf("[CMD] %s -> %s (contador %lu)\n", topico, orden, c);
}

// N5: {"orden","contador","ts","firma"}  firma = HMAC(clave_N5, N5|orden|contador|ts)
void ordenPoza(const char* cmd) {
  unsigned long c = siguienteContador();
  unsigned long ts = ahoraUtc();
  char canon[96], firma[65], msg[220];
  snprintf(canon, sizeof canon, "N5|%s|%lu|%lu", cmd, c, ts);
  hmacHex(CLAVE_N5, canon, firma);
  snprintf(msg, sizeof msg, "{\"orden\":\"%s\",\"contador\":%lu,\"ts\":%lu,\"firma\":\"%s\"}", cmd, c, ts, firma);
  if (mqtt.connected()) mqtt.publish("upc/g3/poza/cmd", msg);
  Serial.printf("[CMD] upc/g3/poza/cmd -> %s (contador %lu)\n", cmd, c);
}

// N6: {"orden":"latido","contador","ts","firma"}  firma = HMAC(clave_N6, N6|latido|contador|ts).
// Con esta orden firmada N6 sabe que el gateway está vivo y sale de modo seguro.
void latidoN6() {
  unsigned long c = siguienteContador();
  unsigned long ts = ahoraUtc();
  char canon[64], firma[65], msg[200];
  snprintf(canon, sizeof canon, "N6|latido|%lu|%lu", c, ts);
  hmacHex(CLAVE_N6, canon, firma);
  snprintf(msg, sizeof msg, "{\"orden\":\"latido\",\"contador\":%lu,\"ts\":%lu,\"firma\":\"%s\"}", c, ts, firma);
  if (mqtt.connected()) mqtt.publish("upc/g3/piezometro/cmd", msg);
}

// =====================================================================
//                     RECEPCIÓN Y VERIFICACIÓN DE MENSAJES
// =====================================================================
int indiceNodo(const char* nombre) {
  if (!strcmp(nombre, "nodo")) return 6;          // tópico antiguo de N7 (compatibilidad)
  for (int i = 0; i < N_NODOS; i++) if (!strcmp(nombre, nodos[i].topico)) return i;
  return -1;
}

bool partirTopico(const char* t, char* nombre, size_t nn, char* tipo, size_t nt) {
  const char* pre = "upc/g3/";
  if (strncmp(t, pre, strlen(pre)) != 0) return false;
  const char* a = t + strlen(pre);
  const char* b = strchr(a, '/');
  if (!b) return false;
  size_t la = (size_t)(b - a);
  if (la >= nn) return false;
  memcpy(nombre, a, la); nombre[la] = 0;
  strncpy(tipo, b + 1, nt - 1); tipo[nt - 1] = 0;
  return true;
}

bool limiteMensajes(Nodo& nd) {                  // 10 msg/s por nodo; el exceso se descarta
  unsigned long a = millis();
  if (a - nd.ventanaMs >= 1000) { nd.ventanaMs = a; nd.cuentaVentana = 0; }
  if (nd.cuentaVentana >= MAX_MSG_S) { nd.descartados++; return false; }
  nd.cuentaVentana++;
  return true;
}

bool verificarFirma(const Nodo& nd, const char* js) {
  char firma[72];
  if (!campo(js, "firma", firma, sizeof firma) || strlen(firma) != 64) return false;
  char canon[400];
  char id[24], sec[32], ts[24], val[40], uni[16], cal[16];
  campo(js, "id", id, sizeof id);
  campo(js, "sector", sec, sizeof sec);
  campo(js, "ts", ts, sizeof ts);
  campo(js, "valor", val, sizeof val);
  campo(js, "unidad", uni, sizeof uni);
  campo(js, "calidad", cal, sizeof cal);
  switch (nd.firma) {
    case F_CONTRATO: snprintf(canon, sizeof canon, "%s|%s|%s|%s|%s|%s", id, sec, ts, val, uni, cal); break;
    case F_N5:       snprintf(canon, sizeof canon, "%s|%s|%s|%s", id, sec, ts, val); break;
    case F_N7:       snprintf(canon, sizeof canon, "%s|%s|%s|%s|%s", id, sec, ts, val, uni); break;
    case F_N6_CUERPO: {
      const char* f = strstr(js, ",\"firma\":\"");
      if (!f) return false;
      size_t largo = (size_t)(f - js);
      if (largo + 2 >= sizeof canon) return false;
      memcpy(canon, js, largo);
      canon[largo] = '}';
      canon[largo + 1] = 0;
      break;
    }
    default: return true;
  }
  char esperada[65];
  hmacHex(nd.clave, canon, esperada);
  return igualConstante(esperada, firma);
}

bool calidadUtil(const char* js) {
  char cal[16];
  campo(js, "calidad", cal, sizeof cal);
  return strcmp(cal, "falla") != 0 && strcmp(cal, "falla_lazo") != 0 && strcmp(cal, "saturado") != 0;
}

void procesarDatos(int i, const char* js) {
  float v = campoF(js, "valor", NAN);
  bool ok = calidadUtil(js) && !isnan(v);
  char u[16];
  campo(js, "unidad", u, sizeof u);
  switch (i) {
    case 0: if (ok) ponerVar(V_LLUVIA, v); break;                       // N1 mm/h
    case 1: if (ok && !strcmp(u, "%")) ponerVar(V_SUMIDERO, v); break;  // N2 %
    case 2: {                                                            // N3: corriente + caudal + bomba
      char c[8], b[8];
      bombas[0].corriente = v;
      if (campo(js, "caudal", c, sizeof c)) {
        bombas[0].caudal = atoi(c);
        bombas[0].caudalMs = millis();
        if (bombas[0].caudal == 1) bombas[0].ultimoCaudal1Ms = millis();
      }
      if (campo(js, "bomba", b, sizeof b)) bombas[0].on = !strcmp(b, "on");
      break;
    }
    case 3:                                                              // N4: dos mensajes, A y 0/1
      if (!strcmp(u, "A")) bombas[1].corriente = v;
      else if (!strcmp(u, "0/1") && !isnan(v)) {
        bombas[1].caudal = (int)v;
        bombas[1].caudalMs = millis();
        if (bombas[1].caudal == 1) bombas[1].ultimoCaudal1Ms = millis();
      }
      break;
    case 4: if (ok && v >= 0) ponerVar(V_POZA, v); break;               // N5 %
    case 5: if (ok && !strcmp(u, "kPa")) ponerVar(V_PRESION, v); break; // N6 kPa
    case 6: {                                                            // N7: mm/h (o grados, versión anterior)
      if (isnan(v)) break;
      char s[8];
      campo(js, "sirena", s, sizeof s);
      sirenaN7 = !strcmp(s, "true");
      float d = v;
      if (strcmp(u, "mm/h") != 0) d = fmaxf(fabsf(v) * K_ANGULO, fabsf(campoF(js, "giro_deg_s", 0)) * K_GIRO);
      if (sirenaN7) d = fmaxf(d, P.despRojo);   // la sirena local ya decidió rojo: el gateway lo respeta
      ponerVar(V_DESP, d);
      break;
    }
  }
}

void procesarEstadoNodo(int i, const char* js) {
  if (i == 3) {                                   // N4 informa el estado del relé en /estado
    char b[8];
    if (campo(js, "bomba", b, sizeof b)) bombas[1].on = !strcmp(b, "on");
  }
}

// Los nodos publican sus propios rechazos de ataques en /alerta: el gateway los cuenta y los muestra.
void procesarAlertaNodo(int i, const char* js) {
  bool esSeguridad = strstr(js, "rechaz") || strstr(js, "ATAQUE") || strstr(js, "\"seguridad\"") ||
                     strstr(js, "falsificada") || strstr(js, "repeticion") || strstr(js, "orden_falsa");
  if (esSeguridad) {
    eventosNodos++;
    char m[40] = "";
    if (!campo(js, "motivo", m, sizeof m) || !m[0]) campo(js, "tipo", m, sizeof m);
    snprintf(ultimoEventoNodo, sizeof ultimoEventoNodo, "%s rechazo: %s", nodos[i].etiqueta, m);
  }
  if (strstr(js, "falla_bomba2")) Serial.println("[N4] reporta falla de bomba 2 (sin caudal)");
}

void procesarConfig(const char* js);
void dispararAtaque8();
void publicarEstadoGw();
void publicarDatosGw();

void alRecibir(char* topic, byte* payload, unsigned int len) {
  static char js[900];
  unsigned int n = len < sizeof(js) - 1 ? len : sizeof(js) - 1;
  memcpy(js, payload, n);
  js[n] = 0;

  char nombre[24], tipo[16];
  if (!partirTopico(topic, nombre, sizeof nombre, tipo, sizeof tipo)) return;

  if (!strcmp(nombre, "gateway")) {
    if (!strcmp(tipo, "config")) {
      if (millis() - ventanaConfig >= 1000) { ventanaConfig = millis(); cuentaConfig = 0; }
      if (++cuentaConfig > MAX_MSG_S) { descartesConfig++; return; }
      procesarConfig(js);
    } else if (!strcmp(tipo, "ataque")) {
      if (strstr(js, "config")) dispararAtaque8();
    }
    return;
  }

  int i = indiceNodo(nombre);
  if (i < 0) return;
  Nodo& nd = nodos[i];
  if (!limiteMensajes(nd)) return;

  bool esDatos = !strcmp(tipo, "datos");
  bool esAlerta = !strcmp(tipo, "alerta");
  bool esEstado = !strcmp(tipo, "estado");
  if (!esDatos && !esAlerta && !esEstado) return;

  // LWT y estados en texto plano ("online"/"offline") o JSON sin firma con "offline"
  bool tieneFirma = strstr(js, "\"firma\"") != nullptr;
  if (esEstado && (js[0] != '{' || (!tieneFirma && strstr(js, "offline")))) {
    nd.lwtCaido = strstr(js, "offline") != nullptr;
    if (!nd.lwtCaido) nd.ultimoMs = millis();
    return;
  }

  bool firmaRequerida = nd.firma != F_NINGUNA && !(nd.firma == F_N5 && !esDatos);
  if (firmaRequerida && (!tieneFirma || !verificarFirma(nd, js))) {
    nd.firmasMalas++;                               // suplantación: se descarta, no toca las reglas
    return;
  }

  nd.ultimoMs = millis();
  nd.lwtCaido = false;
  if (esDatos) procesarDatos(i, js);
  else if (esAlerta) procesarAlertaNodo(i, js);
  else procesarEstadoNodo(i, js);
}

// Rechazos agrupados cada 5 s: un evento por mensaje amplificaría una inundación.
void revisarSeguridad() {
  if (millis() - tResumen < RESUMEN_SEG_MS) return;
  tResumen = millis();
  char accion[44];
  for (int i = 0; i < N_NODOS; i++) {
    if (nodos[i].firmasMalas) {
      snprintf(accion, sizeof accion, "descartados %lu mensajes", nodos[i].firmasMalas);
      eventoSeguridad(nodos[i].etiqueta, "suplantacion", accion, "firma HMAC invalida o ausente");
      nodos[i].firmasMalas = 0;
    }
    if (nodos[i].descartados) {
      snprintf(accion, sizeof accion, "descartados %lu mensajes", nodos[i].descartados);
      eventoSeguridad(nodos[i].etiqueta, "inundacion", accion, "supera 10 msg/s");
      nodos[i].descartados = 0;
    }
  }
  if (descartesConfig) {
    snprintf(accion, sizeof accion, "descartadas %lu solicitudes", descartesConfig);
    eventoSeguridad("N8", "inundacion_config", accion, "supera 10 msg/s");
    descartesConfig = 0;
  }
}

// =====================================================================
//        ATAQUE 8: CAMBIO DE CONFIGURACIÓN NO AUTORIZADO Y SU DEFENSA
// =====================================================================
int buscarParam(const char* nombre) {
  for (int i = 0; i < N_PARAMS; i++) if (!strcmp(nombre, PARAMS[i].nombre)) return i;
  return -1;
}

void dejarPendiente(int d, float v, const char* origen) {
  pendiente.activo = true;
  pendiente.def = d;
  pendiente.valor = v;
  pendiente.expira = millis() + CONFIRMAR_MS;
  strncpy(pendiente.origen, origen, sizeof pendiente.origen - 1);
  pendiente.origen[sizeof pendiente.origen - 1] = 0;
  char motivo[48];
  snprintf(motivo, sizeof motivo, "%s=%.1f, pulsar boton en 20 s", PARAMS[d].nombre, v);
  eventoSeguridad("N8", "cambio_config", "pendiente de confirmacion local", motivo);
}

// Solicitud remota: {"param","valor","contador","ts","firma"}
// firma = HMAC(CLAVE_N8, N8|param|valor|contador|ts)
void procesarConfig(const char* js) {
  char param[28], val[20], ctr[20], ts[20], firma[72];
  campo(js, "param", param, sizeof param);
  campo(js, "valor", val, sizeof val);
  campo(js, "contador", ctr, sizeof ctr);
  campo(js, "ts", ts, sizeof ts);
  campo(js, "firma", firma, sizeof firma);

  char canon[128], esperada[65];
  snprintf(canon, sizeof canon, "N8|%s|%s|%s|%s", param, val, ctr, ts);
  hmacHex(CLAVE_N8, canon, esperada);
  if (!igualConstante(esperada, firma)) {
    eventoSeguridad("N8", "cambio_config_no_autorizado", "cambio rechazado", "firma HMAC invalida");
    return;
  }
  unsigned long c = strtoul(ctr, nullptr, 10);
  if (c <= ultimoCtrConfig) {
    eventoSeguridad("N8", "repeticion_config", "cambio rechazado", "contador repetido");
    return;
  }
  unsigned long t = strtoul(ts, nullptr, 10);
  unsigned long ahora = ahoraUtc();
  if (ahora == 0 || labs((long)(ahora - t)) > TS_VENTANA_S) {
    eventoSeguridad("N8", "repeticion_config", "cambio rechazado", "ts fuera de ventana de 30 s");
    return;
  }
  ultimoCtrConfig = c;
  int d = buscarParam(param);
  if (d < 0) {
    eventoSeguridad("N8", "cambio_config_incoherente", "cambio rechazado", "parametro desconocido");
    return;
  }
  float v = atof(val);
  if (v < PARAMS[d].minSeg || v > PARAMS[d].maxSeg) {
    eventoSeguridad("N8", "cambio_config_incoherente", "cambio rechazado", "fuera del rango seguro");
    return;
  }
  dejarPendiente(d, v, "remoto");
}

// Simula al atacante: publica un cambio sin la clave del gateway (sube el umbral de evacuación).
void dispararAtaque8() {
  if (!mqtt.connected()) return;
  char msg[200];
  snprintf(msg, sizeof msg,
           "{\"param\":\"desp_rojo\",\"valor\":50,\"contador\":%lu,\"ts\":%lu,\"firma\":\"%s\"}",
           ultimoCtrConfig + 1, ahoraUtc(),
           "0000000000000000000000000000000000000000000000000000000000000000");
  mqtt.publish(T_GW_CONFIG, msg);
  Serial.println("[ATAQUE 8] publicado cambio de umbral sin firma valida");
}

// Solicitud legítima firmada (como la haría el ingeniero autorizado), útil para la demo.
void solicitudFirmada(const char* param, float v) {
  if (!mqtt.connected()) { Serial.println("Sin MQTT"); return; }
  unsigned long c = siguienteContador();
  unsigned long ts = ahoraUtc();
  char val[20], canon[128], firma[65], msg[220];
  snprintf(val, sizeof val, "%.1f", v);
  snprintf(canon, sizeof canon, "N8|%s|%s|%lu|%lu", param, val, c, ts);
  hmacHex(CLAVE_N8, canon, firma);
  snprintf(msg, sizeof msg, "{\"param\":\"%s\",\"valor\":%s,\"contador\":%lu,\"ts\":%lu,\"firma\":\"%s\"}",
           param, val, c, ts, firma);
  mqtt.publish(T_GW_CONFIG, msg);
}

void aplicarPendiente() {
  ParamDef& d = PARAMS[pendiente.def];
  float anterior = *d.ptr;
  *d.ptr = pendiente.valor;
  pendiente.activo = false;
  char motivo[48];
  snprintf(motivo, sizeof motivo, "%s %.1f -> %.1f", d.nombre, anterior, pendiente.valor);
  eventoSeguridad("N8", "cambio_config", "aplicado con doble confirmacion", motivo);
}

void revisarPendiente() {
  if (pendiente.activo && (long)(millis() - pendiente.expira) >= 0) {
    pendiente.activo = false;
    eventoSeguridad("N8", "cambio_config", "cambio descartado", "sin confirmacion local en 20 s");
  }
}

// =====================================================================
//                          REGLAS FOG Y LAZO
// =====================================================================
int evaluarB(float L, float S, float Pr, float D) {
  if (D >= P.despRojo || (D >= P.despComb && (Pr >= P.presRojo || L >= P.lluviaRojo))) return 2;
  int k = (L >= P.lluviaAmar) + (S >= P.sumAmar) + (Pr >= P.presAmar) + (D >= P.despAmar);
  return k >= 2 ? 1 : 0;
}
int evaluarA(float D) {                          // alternativa A: solo el desplazamiento
  if (D >= P.despRojo) return 2;
  if (D >= P.despAmar) return 1;
  return 0;
}

void evaluarAlerta() {
  float L = leerVar(V_LLUVIA), S = leerVar(V_SUMIDERO), Pr = leerVar(V_PRESION), D = leerVar(V_DESP);
  nivelB = evaluarB(L, S, Pr, D);
  nivelA = evaluarA(D);
  int nuevo = (alternativa == 'A') ? nivelA : nivelB;
  if (nuevo == nivelActual) return;
  int previo = nivelActual;
  nivelActual = nuevo;
  reconocida = false;
  tCambioNivel = millis();
  char l[12], s[12], p[12], d[12], extra[300];
  numTexto(L, l, sizeof l); numTexto(S, s, sizeof s); numTexto(Pr, p, sizeof p); numTexto(D, d, sizeof d);
  char hora[24];
  horaTexto(hora, sizeof hora, false);
  snprintf(extra, sizeof extra,
           ",\"tipo\":\"alerta_tajo\",\"hora\":\"%s\",\"previo\":\"%s\",\"alternativa\":\"%c\",\"accion\":\"%s\","
           "\"lluvia\":%s,\"sumidero\":%s,\"presion\":%s,\"desp\":%s",
           hora, NOMBRE_NIVEL[previo], alternativa,
           nuevo == 2 ? "evacuar_tajo" : (nuevo == 1 ? "preparar_evacuacion" : "operacion_normal"),
           l, s, p, d);
  publicarGw(T_GW_ALERTA, NOMBRE_NIVEL[nuevo], true, "nivel", extra, false);
  Serial.printf("[FOG] alerta %s -> %s (alt %c) lluvia=%s sumidero=%s presion=%s desp=%s\n",
                NOMBRE_NIVEL[previo], NOMBRE_NIVEL[nuevo], alternativa, l, s, p, d);
}

bool demandaBombeo() {
  if (forzarBombeo >= 0) return forzarBombeo == 1;
  float S = leerVar(V_SUMIDERO);
  if (!isnan(S)) {                               // con dato del sumidero: histéresis 60 % / 40 %
    if (S >= P.sumAmar) demandaLatch = true;
    else if (S <= P.sumApagar) demandaLatch = false;
    return demandaLatch;
  }
  float L = leerVar(V_LLUVIA);                   // sin N2: la lluvia intensa anticipa la subida del agua
  if (!isnan(L)) {
    if (L >= P.lluviaAmar) demandaLatch = true;
    else if (L < P.lluviaAmar * 0.5f) demandaLatch = false;
  }
  return demandaLatch;
}

bool caudalConfirmado(int k, unsigned long desde) {
  return bombas[k].caudal == 1 && bombas[k].caudalMs > desde;
}
bool caudalPerdido(int k) {
  return millis() - bombas[k].ultimoCaudal1Ms >= CAUDAL_MS;
}

void fallaBomba(int k, unsigned long msDesdeOrden) {
  char detalle[80];
  snprintf(detalle, sizeof detalle, "%s sin caudal; detectada en %.1f s", bombas[k].nombre, msDesdeOrden / 1000.0);
  eventoOperacion("falla_bomba", bombas[k].nombre, detalle);
}

void lazoCerrado() {
  if (!mqtt.connected()) return;                 // sin broker no hay órdenes: los nodos siguen en modo local
  bool dem = demandaBombeo();
  unsigned long a = millis();
  char det[80];
  if (!dem) {
    if (lazo != L_REPOSO) {
      if (bombaActiva >= 0) ordenBomba(bombaActiva, "apagar");
      bombaActiva = -1;
      lazo = L_REPOSO;
      eventoOperacion("bombeo", "detenido", "nivel normal");
    }
    return;
  }
  switch (lazo) {
    case L_REPOSO:
      ordenBomba(0, "encender");
      bombaActiva = 0;
      lazo = L_ESPERA_B1;
      tLazo = tOrdenInicial = a;
      eventoOperacion("bombeo", "orden_bomba1", "esperando caudal 15 s");
      break;
    case L_ESPERA_B1:
      if (caudalConfirmado(0, tLazo)) {
        lazo = L_B1_OK;
        snprintf(det, sizeof det, "bomba1 confirmo caudal en %.1f s", (a - tLazo) / 1000.0);
        eventoOperacion("bombeo", "caudal_confirmado", det);
      } else if (a - tLazo >= CAUDAL_MS) {
        fallaBomba(0, a - tLazo);
        ordenBomba(0, "apagar");
        lazo = L_PAUSA_RESPALDO;
        tLazo = a;
      }
      break;
    case L_B1_OK:
      if (caudalPerdido(0)) {
        fallaBomba(0, a - bombas[0].ultimoCaudal1Ms);
        ordenBomba(0, "apagar");
        lazo = L_PAUSA_RESPALDO;
        tLazo = tOrdenInicial = a;
      }
      break;
    case L_PAUSA_RESPALDO:
      if (a - tLazo >= RESPALDO_MS) {
        ordenBomba(1, "encender");
        bombaActiva = 1;
        lazo = L_ESPERA_B2;
        tLazo = a;
        snprintf(det, sizeof det, "bomba2 ordenada %.1f s despues de la primera orden", (a - tOrdenInicial) / 1000.0);
        eventoOperacion("bombeo", "orden_bomba2", det);
      }
      break;
    case L_ESPERA_B2:
      if (caudalConfirmado(1, tLazo)) {
        lazo = L_B2_OK;
        snprintf(det, sizeof det, "bomba2 con caudal; respaldo en marcha a %.1f s", (a - tOrdenInicial) / 1000.0);
        eventoOperacion("bombeo", "respaldo_en_marcha", det);
      } else if (a - tLazo >= CAUDAL_MS) {
        fallaBomba(1, a - tLazo);
        lazo = L_FALLA_TOTAL;
        tLazo = a;
      }
      break;
    case L_B2_OK:
      if (caudalPerdido(1)) {
        fallaBomba(1, a - bombas[1].ultimoCaudal1Ms);
        lazo = L_FALLA_TOTAL;
        tLazo = a;
      }
      break;
    case L_FALLA_TOTAL:
      if (a - tLazo >= REINTENTO_MS) {           // reintenta la secuencia cada 60 s
        if (bombaActiva >= 0) ordenBomba(bombaActiva, "apagar");
        bombaActiva = -1;
        lazo = L_REPOSO;
      }
      break;
  }
}

void vigilarPoza() {                             // N5 ya abre por su cuenta a 85 %; el gateway lo respalda
  float poza = leerVar(V_POZA);
  if (isnan(poza)) return;
  if (poza >= 85.0 && !pozaOrdenada) { ordenPoza("abrir_valvula"); pozaOrdenada = true; }
  else if (poza <= 70.0) pozaOrdenada = false;
}

// =====================================================================
//                       PANTALLA TFT Y SEMÁFORO
// =====================================================================
uint16_t colorNivel(int n) {
  return n == 2 ? ILI9341_RED : (n == 1 ? ILI9341_YELLOW : ILI9341_DARKGREEN);
}

void texto(int x, int y, int tam, uint16_t fg, uint16_t bg, const char* s) {
  tft.setTextSize(tam);
  tft.setTextColor(fg, bg);
  tft.setCursor(x, y);
  tft.print(s);
}

void dibujarPantalla() {
  char b[64], hora[12];
  horaTexto(hora, sizeof hora, true);
  texto(222, 4, 2, ILI9341_WHITE, ILI9341_NAVY, hora);

  // Banda de alerta
  uint16_t bg = colorNivel(nivelActual);
  uint16_t fg = nivelActual == 1 ? ILI9341_BLACK : ILI9341_WHITE;
  if (nivelDibujado != nivelActual) {
    tft.fillRect(0, 24, 320, 62, bg);
    nivelDibujado = nivelActual;
  }
  const char* titulo = nivelActual == 2 ? "ALERTA ROJA   " : (nivelActual == 1 ? "ALERTA AMARILLA" : "ALERTA VERDE  ");
  texto(8, 30, 3, fg, bg, titulo);
  snprintf(b, sizeof b, "%-12s A:%c %-8s",
           nivelActual == 2 ? "EVACUAR TAJO" : (nivelActual == 1 ? "PREPARARSE" : "NORMAL"),
           alternativa, reconocida ? "RECONOC." : (sirenaN7 ? "SIRENA7" : ""));
  texto(8, 62, 2, fg, bg, b);

  // Variables
  for (int i = 0; i < N_VARS; i++) {
    float v = leerVar(i);
    char vt[12];
    if (isnan(v)) snprintf(vt, sizeof vt, "--");
    else snprintf(vt, sizeof vt, "%.1f", v);
    snprintf(b, sizeof b, "%-9s %7s %-4s%c", vars[i].nombre, vt, vars[i].unidad, esSimulada(i) ? '*' : ' ');
    texto(4, 92 + i * 18, 2, ILI9341_WHITE, ILI9341_BLACK, b);
  }

  // Bombas y lazo cerrado
  for (int k = 0; k < 2; k++) {
    char ct[8];
    if (isnan(bombas[k].corriente)) snprintf(ct, sizeof ct, "--");
    else snprintf(ct, sizeof ct, "%.1f", bombas[k].corriente);
    snprintf(b, sizeof b, "B%d %-3s caudal %-2s %5s A %-26s", k + 1, bombas[k].on ? "ON" : "OFF",
             bombas[k].caudal < 0 ? "--" : (bombas[k].caudal ? "1" : "0"), ct,
             bombaActiva == k ? NOMBRE_LAZO[lazo] : "");
    texto(4, 184 + k * 9, 1, bombas[k].caudal == 0 && bombaActiva == k ? ILI9341_ORANGE : ILI9341_CYAN,
          ILI9341_BLACK, b);
  }

  // Nodos en línea
  for (int i = 0; i < N_NODOS; i++) {
    bool en = nodoEnLinea(i);
    texto(4 + i * 44, 204, 2, ILI9341_BLACK, en ? ILI9341_GREEN : ILI9341_RED, nodos[i].etiqueta);
  }

  // Pie: confirmación pendiente o último evento de seguridad, y enlaces
  if (pendiente.activo) {
    long resta = (long)(pendiente.expira - millis()) / 1000;
    snprintf(b, sizeof b, "CONFIRMAR %s=%.1f: PULSE BOTON (%lds)      ", PARAMS[pendiente.def].nombre,
             pendiente.valor, resta < 0 ? 0 : resta);
    texto(4, 222, 1, ILI9341_BLACK, ILI9341_YELLOW, b);
  } else if (ultimoEvento.ataque[0]) {
    snprintf(b, sizeof b, "SEG %s %.20s: %.22s", ultimoEvento.nodo, ultimoEvento.ataque, ultimoEvento.accion);
    char linea[54];
    snprintf(linea, sizeof linea, "%-53s", b);
    texto(4, 222, 1, ILI9341_WHITE, ILI9341_MAROON, linea);
  } else {
    texto(4, 222, 1, ILI9341_LIGHTGREY, ILI9341_BLACK, "Sin eventos de seguridad                             ");
  }
  snprintf(b, sizeof b, "WiFi %-2s MQTT %-2s Nube %-4d Eventos %-4lu %-12s",
           WiFi.status() == WL_CONNECTED ? "ok" : "--", mqtt.connected() ? "ok" : "--",
           nubeCodigo, totalEventos + eventosNodos, rtcOk ? "RTC ok" : "RTC --");
  texto(4, 231, 1, ILI9341_LIGHTGREY, ILI9341_BLACK, b);
}

void pantallaInicial() {
  tft.begin();
  tft.setRotation(1);                            // 320 x 240
  tft.setTextWrap(false);
  tft.fillScreen(ILI9341_BLACK);
  tft.fillRect(0, 0, 320, 22, ILI9341_NAVY);
  texto(4, 4, 2, ILI9341_WHITE, ILI9341_NAVY, "GATEWAY N8 - G3");
  nivelDibujado = -1;
}

void actualizarSemaforo() {
  static unsigned long tPx = 0;
  if (millis() - tPx < 100) return;
  tPx = millis();
  uint32_t c;
  if (nivelActual == 2) c = semaforo.Color(220, 0, 0);
  else if (nivelActual == 1) c = semaforo.Color(200, 130, 0);
  else c = semaforo.Color(0, 160, 0);
  bool parpadeo = nivelActual == 2 && !reconocida && ((millis() / 400) % 2 == 0);
  for (int i = 0; i < N_PIXELES; i++) semaforo.setPixelColor(i, parpadeo ? 0 : c);
  semaforo.show();
}

// =====================================================================
//                   PULSADOR, CONSOLA SERIE Y NUBE
// =====================================================================
void leerBoton() {
  static bool previo = HIGH;
  static unsigned long tCambio = 0;
  bool actual = digitalRead(PIN_BOTON);
  if (actual != previo && millis() - tCambio > 50) {
    tCambio = millis();
    previo = actual;
    if (actual == LOW) {                         // pulsación
      if (pendiente.activo) {
        aplicarPendiente();                      // segunda confirmación, física y local
      } else if (nivelActual > 0 && !reconocida) {
        reconocida = true;                       // reconoce la alerta; NO la apaga mientras dure la condición
        eventoOperacion("reconocimiento", NOMBRE_NIVEL[nivelActual], "alerta reconocida con el pulsador");
      }
    }
  }
}

void ayuda() {
  Serial.println("Comandos: SIM <lluvia|sumidero|poza|presion|desp> <valor> | SIM OFF | ALT A | ALT B");
  Serial.println("          SET <parametro> <valor> (pide pulsador) | CFG <parametro> <valor> (solicitud firmada)");
  Serial.println("          ATAQUE8 | BOMBA ON | BOMBA OFF | BOMBA AUTO | ESTADO | PARAMS");
}

void imprimirEstado() {
  for (int i = 0; i < N_VARS; i++) {
    float v = leerVar(i);
    Serial.printf("  %-9s %8.1f %s%s\n", vars[i].nombre, v, vars[i].unidad, esSimulada(i) ? " (sim)" : "");
  }
  for (int i = 0; i < N_NODOS; i++) Serial.printf("  %s %s %s\n", nodos[i].etiqueta, nodos[i].topico, nodoEnLinea(i) ? "en linea" : "caido");
  Serial.printf("  Alerta: %s (A=%s, B=%s, alt %c) | Lazo: %s\n", NOMBRE_NIVEL[nivelActual], NOMBRE_NIVEL[nivelA],
                NOMBRE_NIVEL[nivelB], alternativa, NOMBRE_LAZO[lazo]);
}

void leerSerie() {
  static char linea[64];
  static int n = 0;
  while (Serial.available()) {
    char ch = Serial.read();
    if (ch == '\r') continue;
    if (ch != '\n' && n < (int)sizeof(linea) - 1) { linea[n++] = ch; continue; }
    linea[n] = 0;
    n = 0;
    char cmd[16] = "", a1[24] = "", a2[16] = "";
    sscanf(linea, "%15s %23s %15s", cmd, a1, a2);
    for (char* p = cmd; *p; p++) *p = toupper(*p);
    if (!strcmp(cmd, "SIM")) {
      const char* nom[] = {"lluvia", "sumidero", "poza", "presion", "desp"};
      if (!strcasecmp(a1, "off")) { for (int i = 0; i < N_VARS; i++) vars[i].simHasta = 0; Serial.println("Simulacion apagada"); }
      for (int i = 0; i < N_VARS; i++)
        if (!strcasecmp(a1, nom[i])) {
          vars[i].sim = atof(a2);
          vars[i].simHasta = millis() + 120000UL;   // 2 min
          Serial.printf("SIM %s = %.1f por 120 s\n", nom[i], vars[i].sim);
        }
    } else if (!strcmp(cmd, "ALT")) {
      alternativa = (toupper(a1[0]) == 'A') ? 'A' : 'B';
      Serial.printf("Alternativa activa: %c\n", alternativa);
    } else if (!strcmp(cmd, "SET")) {
      int d = buscarParam(a1);
      float v = atof(a2);
      if (d < 0) Serial.println("Parametro desconocido (ver PARAMS)");
      else if (v < PARAMS[d].minSeg || v > PARAMS[d].maxSeg) Serial.printf("Fuera del rango seguro %.1f a %.1f\n", PARAMS[d].minSeg, PARAMS[d].maxSeg);
      else dejarPendiente(d, v, "consola");
    } else if (!strcmp(cmd, "CFG")) {
      solicitudFirmada(a1, atof(a2));
    } else if (!strcmp(cmd, "ATAQUE8")) {
      dispararAtaque8();
    } else if (!strcmp(cmd, "BOMBA")) {
      if (!strcasecmp(a1, "on")) forzarBombeo = 1;
      else if (!strcasecmp(a1, "off")) forzarBombeo = 0;
      else forzarBombeo = -1;
      Serial.printf("Bombeo: %s\n", forzarBombeo < 0 ? "automatico" : (forzarBombeo ? "forzado ON" : "forzado OFF"));
    } else if (!strcmp(cmd, "ESTADO")) {
      imprimirEstado();
    } else if (!strcmp(cmd, "PARAMS")) {
      for (int i = 0; i < N_PARAMS; i++)
        Serial.printf("  %-18s %6.1f  (rango seguro %.1f a %.1f)\n", PARAMS[i].nombre, *PARAMS[i].ptr, PARAMS[i].minSeg, PARAMS[i].maxSeg);
    } else if (cmd[0]) {
      ayuda();
    }
  }
}

void actualizarFoto() {
  Foto f;
  for (int i = 0; i < N_VARS; i++) f.v[i] = leerVar(i);
  f.nivelA = nivelA;
  f.nivelB = nivelB;
  f.eventos = totalEventos + eventosNodos;
  portENTER_CRITICAL(&muxFoto);
  foto = f;
  portEXIT_CRITICAL(&muxFoto);
}

// ThingSpeak en el otro núcleo: una petición lenta no congela la pantalla ni el lazo.
// field1 lluvia, field2 sumidero, field3 poza, field4 presión, field5 desplazamiento,
// field6 nivel B, field7 nivel A, field8 eventos de seguridad.
void tareaNube(void*) {
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(NUBE_MS));
    if (WiFi.status() != WL_CONNECTED || strncmp(TS_WRITE_KEY, "TU_", 3) == 0) continue;
    Foto f;
    portENTER_CRITICAL(&muxFoto);
    f = foto;
    portEXIT_CRITICAL(&muxFoto);
    char url[360];
    int k = snprintf(url, sizeof url, "http://api.thingspeak.com/update?api_key=%s", TS_WRITE_KEY);
    for (int i = 0; i < N_VARS && k < (int)sizeof(url) - 40; i++)
      if (!isnan(f.v[i])) k += snprintf(url + k, sizeof(url) - k, "&field%d=%.2f", i + 1, f.v[i]);
    snprintf(url + k, sizeof(url) - k, "&field6=%d&field7=%d&field8=%lu", f.nivelB, f.nivelA, f.eventos);
    HTTPClient http;
    http.setTimeout(5000);
    http.begin(url);
    nubeCodigo = http.GET();
    http.end();
    nubeEnvios++;
  }
}

// =====================================================================
//                         WIFI, MQTT Y RELOJ
// =====================================================================
void mantenerConexion() {
  if (WiFi.status() != WL_CONNECTED || mqtt.connected()) return;
  if (millis() - tIntentoMqtt < 5000) return;
  tIntentoMqtt = millis();
  char cid[32];
  snprintf(cid, sizeof cid, "g3-gateway-n8-%04x", (unsigned)(esp_random() & 0xFFFF));
  // LWT: si el gateway se cae, el broker publica "offline" (N4 y N1 entran en modo seguro a los 60 s)
  if (mqtt.connect(cid, nullptr, nullptr, T_GW_ESTADO, 0, true, "offline")) {
    mqtt.subscribe("upc/g3/+/datos");
    mqtt.subscribe("upc/g3/+/alerta");
    mqtt.subscribe("upc/g3/+/estado");
    mqtt.subscribe(T_GW_CONFIG);
    mqtt.subscribe(T_GW_ATAQUE);
    publicarEstadoGw();
    latidoN6();
    Serial.println("[MQTT] conectado");
  } else {
    Serial.printf("[MQTT] fallo, estado=%d\n", mqtt.state());
  }
}

void publicarEstadoGw() {
  char extra[80];
  snprintf(extra, sizeof extra, ",\"alternativa\":\"%c\",\"nivel\":\"%s\"", alternativa, NOMBRE_NIVEL[nivelActual]);
  publicarGw(T_GW_ESTADO, "online", true, "estado", extra, true);   // sin la palabra "offline": N4 la busca
}

void publicarDatosGw() {
  float v[N_VARS];
  char t[N_VARS][12];
  for (int i = 0; i < N_VARS; i++) { v[i] = leerVar(i); numTexto(v[i], t[i], sizeof t[i]); }
  char nodosTxt[120];
  int k = snprintf(nodosTxt, sizeof nodosTxt, "{");
  for (int i = 0; i < N_NODOS; i++)
    k += snprintf(nodosTxt + k, sizeof(nodosTxt) - k, "%s\"%s\":%d", i ? "," : "", nodos[i].etiqueta, nodoEnLinea(i) ? 1 : 0);
  snprintf(nodosTxt + k, sizeof(nodosTxt) - k, "}");
  char extra[760];
  snprintf(extra, sizeof extra,
           ",\"lluvia\":%s,\"sumidero\":%s,\"poza\":%s,\"presion\":%s,\"desp\":%s,"
           "\"nivel_a\":\"%s\",\"nivel_b\":\"%s\",\"alternativa\":\"%c\",\"reconocida\":%s,"
           "\"lazo\":\"%s\",\"bomba1\":\"%s\",\"caudal1\":%d,\"bomba2\":\"%s\",\"caudal2\":%d,"
           "\"sirena_n7\":%s,\"eventos\":%lu,\"nodos\":%s",
           t[V_LLUVIA], t[V_SUMIDERO], t[V_POZA], t[V_PRESION], t[V_DESP],
           NOMBRE_NIVEL[nivelA], NOMBRE_NIVEL[nivelB], alternativa, reconocida ? "true" : "false",
           NOMBRE_LAZO[lazo], bombas[0].on ? "on" : "off", bombas[0].caudal,
           bombas[1].on ? "on" : "off", bombas[1].caudal,
           sirenaN7 ? "true" : "false", totalEventos + eventosNodos, nodosTxt);
  publicarGw(T_GW_DATOS, NOMBRE_NIVEL[nivelActual], true, "nivel", extra, false);
}

void sincronizarRtc() {                          // con NTP se corrige el DS1307; sin internet manda el DS1307
  time_t t = time(nullptr);
  if (rtcOk && t > 1700000000 && (!rtcSincronizado || millis() - tRtcSync > 3600000UL)) {
    rtc.adjust(DateTime((uint32_t)t));
    rtcSincronizado = true;
    tRtcSync = millis();
    Serial.println("[RTC] DS1307 sincronizado con NTP (UTC)");
  }
}

// =====================================================================
//                              SETUP Y LOOP
// =====================================================================
void setup() {
  Serial.begin(115200);
  pinMode(PIN_BOTON, INPUT_PULLUP);

  semaforo.begin();
  semaforo.setBrightness(80);
  semaforo.clear();
  semaforo.show();

  pantallaInicial();

  Wire.begin(PIN_SDA, PIN_SCL);
  rtcOk = rtc.begin();
  Serial.println(rtcOk ? "[RTC] DS1307 detectado" : "[RTC] DS1307 NO detectado");

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CANAL);
  configTime(0, 0, "pool.ntp.org", "time.google.com");   // UTC
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(alRecibir);
  mqtt.setBufferSize(1024);
  mqtt.setSocketTimeout(2);

  xTaskCreatePinnedToCore(tareaNube, "nube", 8192, nullptr, 1, nullptr, 0);

  Serial.println("Nodo 8 - Gateway (fog) listo.");
  ayuda();
}

void loop() {
  mantenerConexion();
  mqtt.loop();
  leerSerie();
  leerBoton();
  actualizarSemaforo();

  unsigned long a = millis();
  if (a - tEval >= 1000) {                       // decisión fog cada 1 s
    tEval = a;
    evaluarAlerta();
    lazoCerrado();
    vigilarPoza();
    revisarSeguridad();
    revisarPendiente();
    sincronizarRtc();
    actualizarFoto();
    dibujarPantalla();
  }
  if (mqtt.connected()) {
    if (a - tDatos >= DATOS_MS)       { tDatos = a;  publicarDatosGw(); }
    if (a - tLatido >= LATIDO_MS)     { tLatido = a; publicarEstadoGw(); }
    if (a - tN6 >= LATIDO_N6_MS)      { tN6 = a;     latidoN6(); }
  }
}
