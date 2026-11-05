#include <Wire.h>
#include <Adafruit_MPU6050.h>
#include <Adafruit_Sensor.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <math.h>
#include <time.h>
#include "secrets.h"

// COMPONENTES
Adafruit_MPU6050 mpu;
WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);

// PINES - NO CAMBIAR EL CIRCUITO
const int PIN_SDA = 21;
const int PIN_SCL = 22;
const int PIN_BUZZER = 18;

// UMBRALES SOLO PARA SIMULACION
const float ANGULO_AMARILLO = 5.0;
const float ANGULO_ROJO = 12.0;
const float GIRO_AMARILLO = 2.0;
const float GIRO_ROJO = 5.0;

const int MUESTRAS_CRITICAS = 3;
const unsigned long MUESTREO_MS = 200;
const unsigned long RESET_SEGURO_MS = 3000;

// UMBRALES DE CONTEXTO: VALORES DE PRUEBA
// Coordinar unidades y valores con nodos 1 y 6.
const float LLUVIA_ALTA = 10.0;   // mm/h, umbral amarillo del grupo (N1)
const float PRESION_ALTA = 200.0; // kPa, umbral amarillo del grupo (N6)
const unsigned long CONTEXTO_VIGENTE_MS = 15000;

// MQTT

const char* NODE_ID = "N7";
const char* TOP_DATOS = "upc/g3/inclinometro/datos";
const char* TOP_ALERTA = "upc/g3/inclinometro/alerta";
const char* TOP_ESTADO = "upc/g3/inclinometro/estado";
const char* TOP_CMD = "upc/g3/inclinometro/cmd";
const char* TOP_ATAQUE = "upc/g3/inclinometro/ataque";
const char* TOP_LLUVIA = "upc/g3/pluviometro/datos";
const char* TOP_PRESION = "upc/g3/piezometro/datos";

// Velocidad de desplazamiento equivalente (mm/h) para el contrato, calibrada con los
// umbrales del nodo: 12 grados o 5 grados/s = 10 mm/h (rojo, la sirena suena).
const float K_ANGULO = 10.0 / 12.0;
const float K_GIRO = 2.0;

const char* SECTOR = "pared";   // convencion del grupo

// ESTADO DEL INCLINOMETRO
portMUX_TYPE mutexEstado = portMUX_INITIALIZER_UNLOCKED;

float inclinacion = 0;
float velocidadAngular = 0;

bool alarmaRetenida = false;
bool condicionCritica = false;
bool sonidoActivo = false;

int contadorCritico = 0;

unsigned long ultimoCritico = 0;
unsigned long ultimaMuestra = 0;
unsigned long ultimoSerial = 0;

// CONTEXTO EXTERNO VERIFICADO
float lluvia = 0;
float presion = 0;

unsigned long ultimaLluvia = 0;
unsigned long ultimaPresion = 0;

bool lluviaValida = false;
bool presionValida = false;

// PROTECCION CONTRA REPLAY DURANTE LA SESION
uint32_t ultimaSecuenciaGateway = 0;

// EVENTO DE SEGURIDAD PENDIENTE
bool eventoSeguridadPendiente = false;
String motivoSeguridad = "";

// --------------------------------------------------
// HMAC SHA256
// --------------------------------------------------
String generarHMAC(
  const String& mensaje,
  const char* clave
) {
  unsigned char resultado[32];

  const mbedtls_md_info_t* info =
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (info == nullptr) return "";

  int rc = mbedtls_md_hmac(
    info,
    (const unsigned char*)clave,
    strlen(clave),
    (const unsigned char*)mensaje.c_str(),
    mensaje.length(),
    resultado
  );

  if (rc != 0) return "";

  char hexadecimal[65];

  for (int i = 0; i < 32; i++) {
    sprintf(
      hexadecimal + i * 2,
      "%02x",
      resultado[i]
    );
  }

  hexadecimal[64] = '\0';
  return String(hexadecimal);
}

// COMPARACION DE FIRMA
bool verificarHMAC(
  const String& mensaje,
  const char* firma,
  const char* clave
) {
  String esperada = generarHMAC(mensaje, clave);

  if (esperada.length() != 64 ||
      strlen(firma) != 64) {
    return false;
  }

  unsigned char diferencia = 0;

  for (int i = 0; i < 64; i++) {
    diferencia |= esperada[i] ^ firma[i];
  }

  return diferencia == 0;
}

// HORA UTC DEL CONTRATO (NTP); 0 si aun no sincroniza
unsigned long tsUtc() {
  time_t t = time(nullptr);
  return t > 1700000000 ? (unsigned long)t : 0;
}

// --------------------------------------------------
// ESTADO LOCAL PROTEGIDO
// --------------------------------------------------
void obtenerEstado(
  float& angulo,
  float& giro,
  bool& critica,
  bool& alarma
) {
  portENTER_CRITICAL(&mutexEstado);

  angulo = inclinacion;
  giro = velocidadAngular;
  critica = condicionCritica;
  alarma = alarmaRetenida;

  portEXIT_CRITICAL(&mutexEstado);
}

const char* obtenerColor(
  float angulo,
  float giro,
  bool critica,
  bool alarma
) {
  if (critica || alarma) return "ROJO";

  if (angulo >= ANGULO_AMARILLO ||
      giro >= GIRO_AMARILLO) {
    return "AMARILLO";
  }

  return "VERDE";
}

// --------------------------------------------------
// REGISTRO DE ATAQUES
// --------------------------------------------------
void rechazarAtaque(const String& motivo) {
  Serial.println();
  Serial.println("[SEGURIDAD] ATAQUE RECHAZADO");
  Serial.println("[SEGURIDAD] Nodo: 7");
  Serial.println("[SEGURIDAD] Motivo: " + motivo);
  Serial.println("[SEGURIDAD] Alarma local protegida");
  Serial.println();

  motivoSeguridad = motivo;
  eventoSeguridadPendiente = true;
}

// --------------------------------------------------
// VALIDAR DATOS FIRMADOS DE NODOS 1 Y 6 (contrato del grupo)
// firma = HMAC(id|sector|ts|valor|unidad|calidad) con la clave del nodo emisor
// --------------------------------------------------
// Texto crudo de un campo del JSON (para rehacer la firma igual que el emisor, p. ej. "0.0")
String campoCrudo(const char* js, const char* clave) {
  String patron = String("\"") + clave + "\":";
  const char* p = strstr(js, patron.c_str());
  if (!p) return "";
  p += patron.length();
  String out;
  if (*p == '"') { p++; while (*p && *p != '"') out += *p++; }
  else { while (*p && *p != ',' && *p != '}') out += *p++; }
  return out;
}

void procesarContexto(const char* topic, const char* js, JsonDocument& doc) {
  const char* id = doc["id"] | "";
  bool esN1 = strcmp(topic, TOP_LLUVIA) == 0 && strcmp(id, "N1") == 0;
  bool esN6 = strcmp(topic, TOP_PRESION) == 0 && strcmp(id, "N6") == 0;
  if (!esN1 && !esN6) return;

  const char* sector = doc["sector"] | "";
  const char* unidad = doc["unidad"] | "";
  const char* calidad = doc["calidad"] | "";
  const char* firma = doc["firma"] | "";
  if (!doc["valor"].is<float>() && !doc["valor"].is<int>()) return;

  String cadena = String(id) + "|" + sector + "|" + campoCrudo(js, "ts") + "|" + campoCrudo(js, "valor") + "|" +
                  unidad + "|" + calidad;
  if (!verificarHMAC(cadena, firma, esN1 ? CLAVE_NODO1 : CLAVE_NODO6)) return;
  if (strcmp(calidad, "falla") == 0) return;

  float valor = doc["valor"].as<float>();
  if (esN1 && strcmp(unidad, "mm/h") == 0) {
    lluvia = valor; ultimaLluvia = millis(); lluviaValida = true;
  }
  if (esN6 && strcmp(unidad, "kPa") == 0) {
    presion = valor; ultimaPresion = millis(); presionValida = true;
  }
}

// --------------------------------------------------
// DEFENSA CONTRA FALSO "TALUD ESTABLE" (ataque 7)
// Orden del grupo: {"orden","contador","ts","firma"}, firma = HMAC(N7|orden|contador|ts)
// --------------------------------------------------
void procesarComando(JsonDocument& doc) {
  const char* orden = doc["orden"] | "";
  const char* firma = doc["firma"] | "";
  uint32_t contador = doc["contador"] | 0UL;
  unsigned long ts = doc["ts"] | 0UL;

  if (strcmp(orden, "talud_estable") != 0) {
    rechazarAtaque("ORDEN_NO_PERMITIDA");
    return;
  }
  String cadena = String(NODE_ID) + "|" + orden + "|" + String(contador) + "|" + String(ts);
  if (!verificarHMAC(cadena, firma, CLAVE_NODO7)) {
    rechazarAtaque("FIRMA_HMAC_INVALIDA");
    return;
  }
  unsigned long ahoraUtc = tsUtc();
  if (contador <= ultimaSecuenciaGateway ||
      (ahoraUtc != 0 && labs((long)(ahoraUtc - ts)) > 30)) {
    rechazarAtaque("MENSAJE_REPETIDO");
    return;
  }
  ultimaSecuenciaGateway = contador;

  float angulo, giro;
  bool critica, alarma;
  obtenerEstado(angulo, giro, critica, alarma);

  // EL SENSOR LOCAL TIENE PRIORIDAD
  if (critica || alarma) {
    rechazarAtaque("TALUD_LOCALMENTE_INESTABLE");
    return;
  }
  // FALLO SEGURO: EXIGIR DATOS RECIENTES Y FIRMADOS
  unsigned long ahora = millis();
  if (!lluviaValida || !presionValida ||
      ahora - ultimaLluvia > CONTEXTO_VIGENTE_MS ||
      ahora - ultimaPresion > CONTEXTO_VIGENTE_MS) {
    rechazarAtaque("CONTEXTO_INCOMPLETO");
    return;
  }
  // VALIDACION CRUZADA
  if (lluvia >= LLUVIA_ALTA || presion >= PRESION_ALTA) {
    rechazarAtaque("INCOHERENTE_CON_LLUVIA_Y_PRESION");
    return;
  }
  Serial.println("[SEGURIDAD] Estado estable verificado");
  // Una orden remota NUNCA apaga la sirena. El reset sigue siendo local y condicionado.
}

// --------------------------------------------------
// RECEPCION MQTT
// --------------------------------------------------
void recibirMQTT(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, TOP_ATAQUE) == 0) {          // simula el ataque 7 desde el panel HTML
    mqtt.publish(TOP_CMD, "{\"orden\":\"talud_estable\",\"contador\":999999999,\"ts\":0,\"firma\":\"falsa\"}");
    return;
  }
  static char js[700];
  unsigned int n = length < sizeof(js) - 1 ? length : sizeof(js) - 1;
  memcpy(js, payload, n);
  js[n] = 0;
  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, (const char*)js);   // copia: js queda intacto
  if (error) {
    if (strcmp(topic, TOP_CMD) == 0) rechazarAtaque("JSON_INVALIDO");
    return;
  }
  if (strcmp(topic, TOP_CMD) == 0) procesarComando(doc);
  else procesarContexto(topic, js, doc);
}

// --------------------------------------------------
// PUBLICACION MQTT (contrato: id, sector, ts, valor, unidad, calidad, firma)
// --------------------------------------------------
float desplazamientoMmH(float angulo, float giro) {
  return fmaxf(angulo * K_ANGULO, giro * K_GIRO);
}

void publicarFirmado(const char* topic, const char* valor, bool texto, const char* unidad,
                     const char* extra, bool retener) {
  unsigned long ts = tsUtc();
  String cadena = String(NODE_ID) + "|" + SECTOR + "|" + String(ts) + "|" + valor + "|" + unidad + "|ok";
  String firma = generarHMAC(cadena, CLAVE_NODO7);
  char mensaje[480];
  snprintf(mensaje, sizeof(mensaje),
           texto ? "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%lu,\"valor\":\"%s\",\"unidad\":\"%s\",\"calidad\":\"ok\",\"firma\":\"%s\"%s}"
                 : "{\"id\":\"%s\",\"sector\":\"%s\",\"ts\":%lu,\"valor\":%s,\"unidad\":\"%s\",\"calidad\":\"ok\",\"firma\":\"%s\"%s}",
           NODE_ID, SECTOR, ts, valor, unidad, firma.c_str(), extra);
  mqtt.publish(topic, mensaje, retener);
}

void publicarMedicion() {
  float angulo, giro;
  bool critica, alarma;
  obtenerEstado(angulo, giro, critica, alarma);
  char valor[16], extra[160];
  snprintf(valor, sizeof(valor), "%.2f", desplazamientoMmH(angulo, giro));
  snprintf(extra, sizeof(extra), ",\"angulo_deg\":%.2f,\"giro_deg_s\":%.2f,\"estado\":\"%s\",\"sirena\":%s",
           angulo, giro, obtenerColor(angulo, giro, critica, alarma), alarma ? "true" : "false");
  publicarFirmado(TOP_DATOS, valor, false, "mm/h", extra, false);
}

void publicarAlerta(const char* tipo, const char* motivo, int valor) {
  char v[8], extra[160];
  snprintf(v, sizeof(v), "%d", valor);
  snprintf(extra, sizeof(extra), ",\"tipo\":\"%s\",\"motivo\":\"%s\"", tipo, motivo);
  publicarFirmado(TOP_ALERTA, v, false, "bool", extra, false);
}

// --------------------------------------------------
// COMUNICACION EN TAREA INDEPENDIENTE
// --------------------------------------------------
void tareaComunicacion(void* parametro) {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CANAL);

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(recibirMQTT);
  mqtt.setBufferSize(768);
  mqtt.setSocketTimeout(2);

  String cliente = "g3-nodo7-v4-" + String((uint32_t)esp_random(), HEX);

  unsigned long ultimoWifi = millis();
  unsigned long ultimoIntento = 0;
  unsigned long ultimoEnvio = 0;
  unsigned long ultimoLatido = 0;
  bool ultimaAlarmaEnviada = false;
  bool ntpPedido = false;

  for (;;) {
    unsigned long ahora = millis();

    if (WiFi.status() != WL_CONNECTED) {
      if (ahora - ultimoWifi >= 10000) {
        ultimoWifi = ahora;
        WiFi.disconnect();
        WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CANAL);
        Serial.println("[WIFI] Reconectando...");
      }
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    if (!ntpPedido) { configTime(0, 0, "pool.ntp.org", "time.google.com"); ntpPedido = true; }

    if (!mqtt.connected()) {
      if (ultimoIntento == 0 || ahora - ultimoIntento >= 5000) {
        ultimoIntento = ahora;
        if (mqtt.connect(cliente.c_str(), TOP_ESTADO, 0, true, "offline")) {   // LWT retenido
          Serial.println("[MQTT] CONECTADO - VERSION 4 (contrato del grupo)");
          mqtt.subscribe(TOP_CMD);
          mqtt.subscribe(TOP_ATAQUE);
          mqtt.subscribe(TOP_LLUVIA);
          mqtt.subscribe(TOP_PRESION);
          ultimoEnvio = 0;
          ultimoLatido = 0;
          ultimaAlarmaEnviada = false;
        } else {
          Serial.println("[MQTT] Reintentando broker...");
        }
      }
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    mqtt.loop();
    ahora = millis();

    // ENVIO DE MEDICIONES CADA SEGUNDO
    if (ultimoEnvio == 0 || ahora - ultimoEnvio >= 1000) {
      ultimoEnvio = ahora;
      publicarMedicion();
    }

    // ENVIO DE CAMBIO DE ALARMA
    float angulo, giro;
    bool critica, alarma;
    obtenerEstado(angulo, giro, critica, alarma);
    if (alarma != ultimaAlarmaEnviada) {
      publicarAlerta(alarma ? "TALUD_CRITICO" : "ALARMA_RECONOCIDA",
                     alarma ? "MOVIMIENTO_CRITICO" : "RESET_LOCAL_SEGURO", alarma ? 1 : 0);
      ultimaAlarmaEnviada = alarma;
    }

    // PUBLICACION DEL ATAQUE RECHAZADO
    if (eventoSeguridadPendiente) {
      publicarAlerta("ATAQUE_RECHAZADO", motivoSeguridad.c_str(), 1);
      eventoSeguridadPendiente = false;
    }

    // LATIDO CADA 30 SEGUNDOS (retenido)
    if (ultimoLatido == 0 || ahora - ultimoLatido >= 30000) {
      ultimoLatido = ahora;
      publicarFirmado(TOP_ESTADO, "online", true, "estado", alarma ? ",\"sirena\":true" : ",\"sirena\":false", true);
    }

    vTaskDelay(pdMS_TO_TICKS(50));
  }
}
// --------------------------------------------------
// CONTROL LOCAL DEL BUZZER
// --------------------------------------------------
void controlarSirena(unsigned long ahora) {
  bool debeSonar =
    alarmaRetenida &&
    ((ahora / 400) % 2 == 0);

  if (debeSonar != sonidoActivo) {
    sonidoActivo = debeSonar;

    if (debeSonar) {
      tone(PIN_BUZZER, 1200);
    } else {
      noTone(PIN_BUZZER);
    }
  }
}

// --------------------------------------------------
// SETUP
// --------------------------------------------------
void setup() {
  Serial.begin(115200);

  Wire.begin(PIN_SDA, PIN_SCL);
  pinMode(PIN_BUZZER, OUTPUT);

  if (!mpu.begin(0x68)) {
    Serial.println("ERROR: MPU6050 NO DETECTADO");

    while (true) {
      tone(PIN_BUZZER, 1500);
      delay(300);
      noTone(PIN_BUZZER);
      delay(300);
    }
  }

  mpu.setAccelerometerRange(MPU6050_RANGE_2_G);
  mpu.setGyroRange(MPU6050_RANGE_250_DEG);
  mpu.setFilterBandwidth(MPU6050_BAND_21_HZ);

  Serial.println("================================");
  Serial.println("G3 - NODO 7 - VERSION 3");
  Serial.println("MPU6050 + BUZZER + MQTT + HMAC");
  Serial.println("Proteccion contra TALUD_ESTABLE");
  Serial.println("================================");
  Serial.println("Reset local: tecla R");

  xTaskCreatePinnedToCore(
    tareaComunicacion,
    "ComunicacionMQTT",
    12288,
    nullptr,
    1,
    nullptr,
    0
  );
}

// --------------------------------------------------
// LOOP PRINCIPAL - SEGURIDAD LOCAL
// --------------------------------------------------
void loop() {
  unsigned long ahora = millis();

  if (ahora - ultimaMuestra >= MUESTREO_MS) {
    ultimaMuestra = ahora;

    sensors_event_t a, g, temp;
    mpu.getEvent(&a, &g, &temp);

    float ax = a.acceleration.x;
    float ay = a.acceleration.y;
    float az = a.acceleration.z;

    float roll =
      atan2f(ay, az) * 180.0f / PI;

    float pitch =
      atan2f(
        -ax,
        sqrtf(ay * ay + az * az)
      ) * 180.0f / PI;

    float angulo =
      fmaxf(fabsf(roll), fabsf(pitch));

    float giro =
      fmaxf(
        fabsf(g.gyro.x),
        fabsf(g.gyro.y)
      ) * 180.0f / PI;

    bool critica =
      angulo >= ANGULO_ROJO ||
      giro >= GIRO_ROJO;

    if (critica) {
      if (contadorCritico < MUESTRAS_CRITICAS) {
        contadorCritico++;
      }

      ultimoCritico = ahora;

      if (contadorCritico >= MUESTRAS_CRITICAS &&
          !alarmaRetenida) {

        portENTER_CRITICAL(&mutexEstado);
        alarmaRetenida = true;
        portEXIT_CRITICAL(&mutexEstado);

        Serial.println(
          "*** ALERTA ROJA - SIRENA ACTIVADA ***"
        );
      }
    } else {
      contadorCritico = 0;
    }

    portENTER_CRITICAL(&mutexEstado);
    inclinacion = angulo;
    velocidadAngular = giro;
    condicionCritica = critica;
    portEXIT_CRITICAL(&mutexEstado);
  }

  // RESET EXCLUSIVAMENTE LOCAL
  if (Serial.available()) {
    char comando = Serial.read();

    if (comando == 'R' || comando == 'r') {

      if (alarmaRetenida &&
          !condicionCritica &&
          ahora - ultimoCritico >= RESET_SEGURO_MS) {

        portENTER_CRITICAL(&mutexEstado);
        alarmaRetenida = false;
        portEXIT_CRITICAL(&mutexEstado);

        Serial.println(
          "[RESET] Alarma reconocida localmente"
        );

      } else {
        Serial.println(
          "[RESET] RECHAZADO: condiciones inseguras"
        );
      }
    }
  }

  controlarSirena(ahora);

  if (ahora - ultimoSerial >= 500) {
    ultimoSerial = ahora;

    float angulo, giro;
    bool critica, alarma;

    obtenerEstado(angulo, giro, critica, alarma);

    Serial.printf(
      "Nodo=7 | Inclinacion=%.1f | Giro=%.1f | "
      "Estado=%s | Sirena=%s\n",
      angulo,
      giro,
      obtenerColor(angulo, giro, critica, alarma),
      alarma ? "ACTIVA" : "APAGADA"
    );
  }

  delay(10);
}
