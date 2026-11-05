#include <WiFi.h>
#include <PubSubClient.h>
#include <ESP32Servo.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <time.h>
#include "secrets.h"

// ===================== Configuración de pines =====================
#define TRIG_PIN 5
#define ECHO_PIN 18
#define SERVO_PIN 13

// ===================== Identidad del nodo, segun convenciones del equipo =====================
const char* NODE_ID = "N5";
const char* NODE_TOPIC = "poza";
const char* SECTOR = "poza";

// ===================== Red y broker MQTT =====================
const char* WIFI_SSID = "Wokwi-GUEST";
const char* WIFI_PASSWORD = "";
const char* MQTT_BROKER = "broker.hivemq.com";
const int MQTT_PORT = 1883;

// ===================== Topicos con el prefijo acordado =====================
String TOPIC_DATOS  = "upc/g3/" + String(NODE_TOPIC) + "/datos";
String TOPIC_ALERTA = "upc/g3/" + String(NODE_TOPIC) + "/alerta";
String TOPIC_ESTADO = "upc/g3/" + String(NODE_TOPIC) + "/estado";
String TOPIC_CMD    = "upc/g3/" + String(NODE_TOPIC) + "/cmd";

// ===================== Calibracion del sensor, PROPUESTA, confirmar con el equipo =====================
const float DISTANCIA_VACIA_CM = 20.0;   // 0 % de nivel
const float DISTANCIA_LLENA_CM = 2.0;    // 100 % de nivel

// ===================== Umbrales de la poza =====================
const float NIVEL_DESCARGA_PCT = 85.0;   // oficial, del documento del equipo
const float NIVEL_CIERRE_PCT = 70.0;     // propuesta mia, para evitar rebote

// ===================== Temporizacion =====================
const unsigned long INTERVALO_LECTURA_MS = 2000;
const unsigned long INTERVALO_LATIDO_MS = 30000;
const unsigned long TIMEOUT_ECHO_US = 30000;
const long TOLERANCIA_TS_SEGUNDOS = 30;

// ===================== Objetos y estado =====================
WiFiClient espClient;
PubSubClient mqtt(espClient);
Servo valvula;

unsigned long ultimaLectura = 0;
unsigned long ultimoLatido = 0;
bool valvulaAbierta = false;
float ultimoNivel = -1.0;
uint32_t ultimoContadorVisto = 0;

// ===================== Prototipos =====================
void conectarWifi();
void sincronizarHora();
void conectarMQTT();
void callbackMQTT(char* topic, byte* payload, unsigned int length);
float leerDistanciaCM();
float distanciaANivelPct(float distancia);
void actualizarValvula(float nivel, bool porComando);
void publicarDatos(float nivel, const char* calidad);
void publicarAlerta(const char* motivo);
void publicarEstado(const char* estado);
String calcularFirmaHMAC(const String& base);

void setup() {
  Serial.begin(115200);
  delay(500);

  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  digitalWrite(TRIG_PIN, LOW);

  valvula.attach(SERVO_PIN);
  valvula.write(0);

  Serial.println();
  Serial.println("========================================");
  Serial.println(" Nodo N5 - Poza de Coleccion (G3 Mineria)");
  Serial.println("========================================");

  conectarWifi();
  sincronizarHora();

  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(callbackMQTT);
  conectarMQTT();
}

void loop() {
  if (!mqtt.connected()) {
    conectarMQTT();
  }
  mqtt.loop();

  unsigned long ahora = millis();

  if (ahora - ultimaLectura >= INTERVALO_LECTURA_MS) {
    ultimaLectura = ahora;

    float distancia = leerDistanciaCM();

    if (distancia >= 0) {
      float nivel = distanciaANivelPct(distancia);
      ultimoNivel = nivel;

      Serial.print("[N5] Distancia: ");
      Serial.print(distancia, 1);
      Serial.print(" cm | Nivel: ");
      Serial.print(nivel, 1);
      Serial.print(" % | Valvula: ");
      Serial.println(valvulaAbierta ? "ABIERTA" : "CERRADA");

      actualizarValvula(nivel, false);
      publicarDatos(nivel, "ok");
    } else {
      Serial.println("[N5] Sin eco del sensor");
      publicarDatos(-1, "falla");
    }
  }

  if (ahora - ultimoLatido >= INTERVALO_LATIDO_MS) {
    ultimoLatido = ahora;
    publicarEstado("online");
  }
}

// ===================== WiFi y hora =====================
void conectarWifi() {
  Serial.print("Conectando a WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print(".");
  }

  Serial.println();
  Serial.print("WiFi conectado, IP: ");
  Serial.println(WiFi.localIP());
}

void sincronizarHora() {
  Serial.print("Sincronizando hora por NTP");
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  time_t ahora = time(nullptr);
  int intentos = 0;

  while (ahora < 100000 && intentos < 20) {
    delay(300);
    Serial.print(".");
    ahora = time(nullptr);
    intentos++;
  }

  Serial.println();
  Serial.print("Hora UTC sincronizada, epoch: ");
  Serial.println((long)ahora);
}

// ===================== Conexion MQTT con LWT =====================
void conectarMQTT() {
  while (!mqtt.connected()) {
    Serial.print("Conectando a broker MQTT...");

    String clientId = String(NODE_ID) + "-" + String(random(0xffff), HEX);
    String lwtPayload = "offline";   // LWT del contrato

    bool conectado = mqtt.connect(
      clientId.c_str(),
      TOPIC_ESTADO.c_str(),
      0,
      true,
      lwtPayload.c_str()
    );

    if (conectado) {
      Serial.println(" conectado");
      mqtt.subscribe(TOPIC_CMD.c_str());
      publicarEstado("online");
    } else {
      Serial.print(" fallo, rc=");
      Serial.print(mqtt.state());
      Serial.println(" reintentando en 2s");
      delay(2000);
    }
  }
}

// ===================== Callback de ordenes del gateway =====================
void callbackMQTT(char* topic, byte* payload, unsigned int length) {
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, payload, length);

  if (error) {
    Serial.println("[N5] Orden con formato invalido, se descarta");
    return;
  }

  // Formato único del grupo: {"orden","contador","ts","firma"}; se acepta "cmd" por compatibilidad
  const char* cmd = doc["orden"].is<const char*>() ? doc["orden"].as<const char*>() : (doc["cmd"] | "");
  uint32_t contador = doc["contador"] | 0;
  long ts = doc["ts"] | 0;
  const char* firmaRecibida = doc["firma"] | "";

  Serial.print("[N5] Orden recibida: cmd=");
  Serial.print(cmd);
  Serial.print(" contador=");
  Serial.println(contador);

  // Verificacion de firma, usando la misma clave compartida con el gateway
  String base = String(NODE_ID) + "|" + String(cmd) + "|" + String(contador) + "|" + String(ts);
  String firmaEsperada = calcularFirmaHMAC(base);

  if (firmaEsperada != String(firmaRecibida)) {
    Serial.println("[N5] Orden RECHAZADA: firma invalida (posible suplantacion)");
    publicarAlerta("orden_rechazada_firma_invalida");
    return;
  }

  // Anti repeticion: contador debe ser mayor al ultimo visto
  if (contador <= ultimoContadorVisto) {
    Serial.println("[N5] Orden RECHAZADA: contador repetido (posible replay)");
    publicarAlerta("orden_rechazada_contador_repetido");
    return;
  }

  // Frescura del mensaje, comparado con la hora UTC sincronizada
  long ahoraEpoch = (long)time(nullptr);
  if (abs(ahoraEpoch - ts) > TOLERANCIA_TS_SEGUNDOS) {
    Serial.println("[N5] Orden RECHAZADA: marca de tiempo vencida (posible replay)");
    publicarAlerta("orden_rechazada_ts_vencido");
    return;
  }

  ultimoContadorVisto = contador;

  // Regla de seguridad de edge: solo se descarga si el nivel real lo justifica,
  // asi la orden falsa de abrir la valvula y vaciar la poza al ambiente no hace nada.
  if (String(cmd) == "abrir_valvula") {
    if (ultimoNivel >= NIVEL_DESCARGA_PCT) {
      actualizarValvula(ultimoNivel, true);
      Serial.println("[N5] Orden aceptada: el nivel justifica la apertura");
    } else {
      Serial.println("[N5] Orden RECHAZADA: el nivel no justifica la apertura");
      publicarAlerta("orden_rechazada_nivel_insuficiente");
    }
  }
}

// ===================== HMAC-SHA256 =====================
String calcularFirmaHMAC(const String& base) {
  byte hmacResult[32];

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)CLAVE_HMAC_N5, strlen(CLAVE_HMAC_N5));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)base.c_str(), base.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String hex = "";
  for (int i = 0; i < 32; i++) {
    char buf[3];
    sprintf(buf, "%02x", hmacResult[i]);
    hex += buf;
  }
  return hex;
}

// ===================== Lectura del sensor =====================
float leerDistanciaCM() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  long duracion = pulseIn(ECHO_PIN, HIGH, TIMEOUT_ECHO_US);

  if (duracion == 0) {
    return -1.0;
  }

  return duracion * 0.0343 / 2.0;
}

float distanciaANivelPct(float distancia) {
  float nivel = (DISTANCIA_VACIA_CM - distancia) / (DISTANCIA_VACIA_CM - DISTANCIA_LLENA_CM) * 100.0;

  if (nivel < 0) nivel = 0;
  if (nivel > 100) nivel = 100;

  return nivel;
}

// ===================== Logica de la valvula =====================
void actualizarValvula(float nivel, bool porComando) {
  if (nivel >= NIVEL_DESCARGA_PCT && !valvulaAbierta) {
    valvula.write(90);
    valvulaAbierta = true;
    Serial.println("  -> Accion: valvula ABIERTA (nivel de descarga alcanzado)");
    publicarAlerta("nivel_descarga_valvula_abierta");
  } else if (nivel <= NIVEL_CIERRE_PCT && valvulaAbierta) {
    valvula.write(0);
    valvulaAbierta = false;
    Serial.println("  -> Accion: valvula CERRADA (nivel seguro)");
  }
}

// ===================== Publicaciones MQTT =====================
// Todas firmadas con el formato del contrato: HMAC(id|sector|ts|valor|unidad|calidad)
void publicarFirmado(const String& topico, const String& valor, bool esTexto, const char* unidad,
                     const char* calidad, const String& extra, bool retener) {
  long ts = (long)time(nullptr);
  String base = String(NODE_ID) + "|" + String(SECTOR) + "|" + String(ts) + "|" + valor + "|" +
                String(unidad) + "|" + String(calidad);
  String firma = calcularFirmaHMAC(base);

  String payload = "{";
  payload += "\"id\":\"" + String(NODE_ID) + "\",";
  payload += "\"sector\":\"" + String(SECTOR) + "\",";
  payload += "\"ts\":" + String(ts) + ",";
  String comillas = esTexto ? "\"" : "";
  payload += "\"valor\":" + comillas + valor + comillas + ",";
  payload += "\"unidad\":\"" + String(unidad) + "\",";
  payload += "\"calidad\":\"" + String(calidad) + "\",";
  payload += "\"firma\":\"" + firma + "\"";
  payload += extra;
  payload += "}";

  mqtt.publish(topico.c_str(), payload.c_str(), retener);
}

void publicarDatos(float nivel, const char* calidad) {
  String extra = ",\"valvula\":\"" + String(valvulaAbierta ? "abierta" : "cerrada") + "\"";
  publicarFirmado(TOPIC_DATOS, String(nivel, 1), false, "%", calidad, extra, false);
}

void publicarAlerta(const char* motivo) {
  String extra = ",\"motivo\":\"" + String(motivo) + "\",\"valvula\":\"" +
                 String(valvulaAbierta ? "abierta" : "cerrada") + "\"";
  publicarFirmado(TOPIC_ALERTA, String(motivo), true, "alerta", "ok", extra, false);
}

void publicarEstado(const char* estado) {
  publicarFirmado(TOPIC_ESTADO, String(estado), true, "estado", "ok", "", true);
}
