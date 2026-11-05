# G3 Minería de tajo abierto (TMS) · Sistema integrado de 8 nodos

## Contenido
| Carpeta | Nodo | Qué tiene |
|---|---|---|
| `N1` | Pluviómetro | Código original del compañero, solo cambia la clave en `secrets.h`. |
| `N2` | Sumidero | **Nuevo**: HC-SR04, relé de la bomba de respaldo a 80 %, LED de alerta y defensa del ataque 2. |
| `N3` | Bomba 1 | **Corregido**: firma en datos, verificación de órdenes y conexión sin bloqueo. |
| `N4` | Bomba 2 | Código original, solo cambia la clave. |
| `N5` | Poza | **Corregido**: todos los mensajes firmados con el formato del contrato y orden con el campo `orden`. |
| `N6` | Piezómetro | **Corregido**: id N6, sector pared, ts UTC, umbrales 200/300 kPa, 10 msg/s, firma y órdenes del contrato. |
| `N7` | Inclinómetro | **Corregido**: tópicos `inclinometro`, id N7, ts UTC, publica en mm/h, verifica la lluvia de N1 y la presión de N6. |
| `N8` | Gateway (fog) | Integrador: reglas fog A y B, TFT, NeoPixel, lazo cerrado de bombas, ThingSpeak y ataque 8. |
| `G3_Integrado_8_nodos.ckt` | Diagrama Cirkit | Los 8 nodos en un solo diagrama, con entradas, salidas y tipo de señal. |

Cada carpeta trae `sketch.ino`, `diagram.json`, `libraries.txt` y `secrets.h`. En Wokwi se crea un proyecto ESP32 y se pegan los 4 archivos. Para crear `secrets.h` y `libraries.txt`, usa la flecha ▾ y luego "New file...".
Los 8 sketches compilaron y arrancaron en Wokwi.

## Contrato único (todos los nodos)
- **Tópicos**: `upc/g3/<nodo>/datos | alerta | estado | cmd`. Los nombres de nodo son `pluviometro`, `sumidero`, `bomba1`, `bomba2`, `poza`, `piezometro`, `inclinometro` y `gateway`.
- **Mensaje**: `{"id":"Nx","sector":..,"ts":<UTC s>,"valor":..,"unidad":..,"calidad":..,"firma":..}`.
  La firma es `HMAC-SHA256(clave_Nx, id|sector|ts|valor|unidad|calidad)`, con el valor tal como va en el JSON y sin comillas.
- **Órdenes** (solo el gateway las envía): `{"orden":..,"contador":n,"ts":<UTC s>,"firma":HMAC(clave_Nx, Nx|orden|contador|ts)}`.
  Se rechazan sin firma, con un contador menor o igual al último o con un ts de más de 30 s.
- **Latido** cada 30 s en `/estado` (retenido). El **LWT** es `offline`.
- **Límite**: 10 mensajes/s por nodo.

## Claves
Cada `secrets.h` ya tiene su clave. El gateway (`N8/secrets.h`) tiene las 8. Si un compañero cambia su clave, hay que cambiarla también en el gateway.
Para ThingSpeak, pon la **Write API Key** del canal en `N8/secrets.h` (`TS_WRITE_KEY`).
`secrets.h` no se sube a GitHub: agrega `secrets.h` al `.gitignore`.

## Ataques y dónde se disparan
| Nodo | Ataque | Disparo |
|---|---|---|
| N1 | Lectura falsificada | `upc/g3/pluviometro/ataque` con `rango` o `salto`, o tecla `a` o `s` en el serial |
| N2 | Suplantación sin firma | `upc/g3/sumidero/ataque` o tecla `s` |
| N3 | Orden falsa de apagar la bomba 1 | `upc/g3/bomba1/ataque` o tecla `x` |
| N4 | Repetición | Reenviar a `upc/g3/bomba2/cmd` una orden ya usada |
| N5 | Abrir la válvula sin justificación | Orden falsa en `upc/g3/poza/cmd` |
| N6 | Inundación | Comando `FLOOD` en el serial |
| N7 | Falso "talud estable" | `upc/g3/inclinometro/ataque` |
| N8 | Cambio de configuración | `upc/g3/gateway/ataque` con `config`, o `ATAQUE8` en el serial |

## Ensayo de integración
Cada integrante corre su nodo en su propia laptop. Wokwi pausa las simulaciones de las pestañas que no están a la vista. Todos se comunican por HiveMQ.
En la pantalla del gateway, N1 a N7 deben aparecer en verde. El guion de la demo está en `N8/README_GATEWAY.md`.
