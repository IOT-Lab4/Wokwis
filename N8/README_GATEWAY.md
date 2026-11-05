# Nodo 8 – Gateway (fog), integrador · G3 Minería de tajo abierto

## Archivos para Wokwi
`sketch.ino`, `diagram.json`, `libraries.txt`, `secrets.h` (este último va en `.gitignore`).

## Conexiones (ESP32 DevKitC)
| Componente | Señal | Pines |
|---|---|---|
| Pantalla TFT ILI9341 | SPI | CS 15, DC 2, RST 4, MOSI 23, SCK 18, MISO 19, VCC/LED 3V3 |
| Reloj DS1307 | I2C | SDA 21, SCL 22, 5V |
| NeoPixel (anillo de 12) | digital 1 hilo | DIN 13, 5V |
| Pulsador "Reconocer / Confirmar" | digital (INPUT_PULLUP) | GPIO 14 a GND |

## Qué hace
- **Recibe** `upc/g3/+/datos|alerta|estado` y verifica la firma HMAC de cada nodo con su propio formato. Un mensaje sin firma válida se descarta y se registra como suplantación. El tope es de 10 msg/s por nodo.
- **Alerta fog (alternativa B)**: es **roja** con desplazamiento ≥ 10 mm/h, o con ≥ 5 mm/h junto con presión ≥ 300 kPa o lluvia ≥ 25 mm/h. Es **amarilla** si 2 o más variables están en su umbral amarillo. En los demás casos es verde. También calcula la **alternativa A** (solo desplazamiento) y publica las dos para compararlas.
- **Semáforo y TFT**: en rojo, el NeoPixel parpadea en rojo y la pantalla muestra "EVACUAR TAJO". El pulsador reconoce la alerta (el semáforo queda fijo), pero no la apaga.
- **Lazo cerrado**: ordena la bomba 1 cuando el sumidero llega a 60 % (o, si no hay dato del N2, con lluvia ≥ 10 mm/h). Si en 15 s no hay caudal, emite "falla_bomba", apaga la bomba 1 y a los 5 s ordena la bomba 2 (a los 20 s de la primera orden).
- **Nube**: envía a ThingSpeak cada 16 s, desde el otro núcleo. Campos: 1 lluvia, 2 sumidero, 3 poza, 4 presión, 5 desplazamiento, 6 nivel B, 7 nivel A, 8 eventos de seguridad. Son unos 65 MB al mes.
- **Ataque 8 (cambio de configuración no autorizado)**: una solicitud en `upc/g3/gateway/config` necesita firma del gateway, un contador creciente, un ts de máximo 30 s y un valor dentro del rango seguro. Además se confirma con el pulsador en un plazo de 20 s (**doble confirmación**). Cada paso se registra en `upc/g3/gateway/alerta` con hora, nodo, ataque, acción y motivo.

## Tópicos del gateway
- `upc/g3/gateway/datos`: cada 2 s. Envía el nivel actual, las variables, nivel_a y nivel_b, el estado del lazo, las bombas y qué nodos están en línea.
- `upc/g3/gateway/alerta`: cambios de alerta, falla de bomba, reconocimiento y eventos de seguridad.
- `upc/g3/gateway/estado`: latido cada 30 s, retenido. Su LWT es "offline".
- `upc/g3/gateway/config`: solicitudes de cambio de parámetros.
- `upc/g3/gateway/ataque`: el botón del panel HTML publica aquí `config` y se dispara el ataque 8.

## Comandos del monitor serie (para la demo y la visita del docente)
| Comando | Efecto |
|---|---|
| `SIM desp 12` / `SIM presion 320` / `SIM lluvia 30` / `SIM sumidero 85` / `SIM poza 90` | Fija un valor durante 2 min (aparece con `*` en la TFT). |
| `SIM OFF` | Vuelve a los datos reales. |
| `ALT A` / `ALT B` | Elige qué alternativa controla el semáforo. |
| `SET desp_rojo 8` | Cambio de parámetro pedido por el docente. Se aplica al pulsar el botón. |
| `CFG desp_rojo 12` | Simula una solicitud remota legítima (firmada). Luego hay que pulsar el botón. |
| `ATAQUE8` | Publica un cambio de umbral sin firma. Se rechaza y queda registrado. |
| `BOMBA ON/OFF/AUTO` | Fuerza o libera el bombeo para probar el lazo cerrado. |
| `ESTADO` / `PARAMS` | Muestra las lecturas, los nodos, la alerta y los parámetros. |

## Guion del escenario de integración (El Niño con bomba 1 en falla)
1. Corre los 7 nodos y el gateway a la vez. En la TFT, los nodos deben aparecer en verde.
2. Sube la lluvia en N1 (o usa `SIM lluvia 30`). El gateway ordena la bomba 1.
3. Deja el interruptor de caudal del N3 en "sin caudal". A los 15 s aparece "falla_bomba" y a los 20 s arranca la bomba 2. Pon el caudal del N4 en 1 y se confirma "respaldo_en_marcha".
4. Sube la presión en N6 por encima de 300 kPa e inclina el MPU6050 del N7. La alerta pasa a roja y aparece "EVACUAR TAJO".
5. Ataque 8: `ATAQUE8`. En la pantalla y en el registro se ve el rechazo.
