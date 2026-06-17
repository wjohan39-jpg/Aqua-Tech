# Brazada Aqua Tech

**Sistema de gestión de calidad de agua en piscinas — Resolución 234/2026 · Colombia**

Aplicación web progresiva (PWA) diseñada para operadores y técnicos de piscinas en Colombia. Permite llevar el control diario de parámetros fisicoquímicos, calcular dosificaciones con productos comerciales colombianos, gestionar protocolos de respuesta ante incidentes de fecalismo, registrar mantenimiento preventivo y correctivo, y generar reportes PDF normativos — todo desde el navegador, sin instalación y con soporte offline completo.

> **Nombre de instalación PWA:** Aquatech  
> **Nombre completo:** Brazada Aqua Tech  
> **by Gonzo**

---

## Módulos

### Dashboard principal
Panel en tiempo real con medidores visuales (gauge) para todos los parámetros del último registro. Muestra el estado de cumplimiento normativo, indicadores IRAPI e ISL de Langelier, alertas de antigüedad de datos (8 h / 24 h), vencimientos documentales y acceso rápido al reporte mensual.

### Calculadora química
Dosificaciones para productos comerciales colombianos con factores estequiométricos verificados. Soporta tres formas de estanque:

| Forma | Fórmula |
|-------|---------|
| Rectangular | `V = Largo × Ancho × Profundidad media` |
| Ovalada (tipo estadio) | `V = Largo × Ancho × Profundidad × 0.89` |
| Circular | `V = (π/4) × Diámetro² × Profundidad` |

Productos disponibles por parámetro:

| Parámetro | Productos disponibles |
|-----------|----------------------|
| **Cloro libre** | Hipoclorito de calcio 70 % · Hipoclorito de sodio 15 % |
| **Cloro combinado** | Cloración de choque (objetivo = 10× el combinado) |
| **pH ↑** | Carbonato de sodio |
| **pH ↓** | HCl 31 % · Bisulfato de sodio |
| **Alcalinidad ↑** | Bicarbonato de sodio |
| **Alcalinidad ↓** | HCl 31 % |
| **CYA exceso** | Dilución parcial con agua fresca |
| **Neutralizar cloro** | Tiosulfato de sodio |

Incluye advertencias normativas Art. 5 y Art. 6 Res. 234/2026. Los resultados pueden transferirse a bitácora con un toque.

### LSI — Índice de Saturación de Langelier
Cálculo del ISL con tablas de coeficientes del Anexo Técnico I, Res. 234/2026:

```
ISL = pH + CT (temperatura) + CD (dureza cálcica) + CA (alcalinidad) − 12.1
Rango aceptable: −0.3 a +0.5 (asimétrico)
```

Interpolación lineal entre puntos de tabla, diagnóstico automático (agua corrosiva / equilibrada / incrustante), y cálculo automático en cada registro de bitácora.

### IRAPI 2026
Índice de Riesgo de Piscinas según Res. 234/2026. Calcula el nivel de riesgo sanitario con pesos normativos:

| Factor | Peso |
|--------|------|
| Microbiológico (laboratorio) | 45 % |
| Alcalinidad / pH | 30 % |
| Cloro residual | 20 % |
| Otros (turbiedad, CYA, ORP) | 5 % |

Requiere mínimo 10 registros en 30 días con al menos 2 fechas distintas. Sin dato microbiológico, el score se normaliza sobre el 55 % medible. Bandas de riesgo: Sin riesgo · Bajo · Medio · Alto.

### Bitácora diaria
Registro de parámetros con validación en tiempo real contra rangos Res. 234/2026:

- Cloro libre, cloro combinado, pH, alcalinidad, dureza cálcica
- Turbiedad, temperatura, CYA, ORP, TDS, conductividad
- ORP con zona de eficacia (< 650 mV = advertencia · > 700 mV = fuera de rango)
- ISL calculado automáticamente en cada guardado
- Gráfico de tendencia histórica por parámetro (7 / 14 / 30 días)
- Fotos adjuntas por registro (compresión automática)
- Edición y eliminación de registros existentes

### Mantenimiento
Registro de trabajos de mantenimiento preventivo y correctivo de la piscina:

- Fecha, técnico responsable, descripción del trabajo y próxima revisión programada
- Foto adjunta por registro
- Edición de registros existentes (modo edición con banner indicador)
- Historial con búsqueda, vista de detalle y eliminación individual

### Protocolo AFR — Accidente con Fecalismo en el agua Recreativa
Gestión de incidentes según Art. 27 Res. 234/2026:

| Tipo | Pasos | Cloro objetivo | CT requerido |
|------|-------|----------------|-------------|
| **Sólido** | 7 pasos | 10 ppm | — |
| **Vómito** | 7 pasos | 2 ppm | — |
| **Diarreico** | 8 pasos (incluye notificación a autoridad sanitaria) | 20 ppm | 15 600 mg·min/L (Cryptosporidium) |

Calcula dosis de hipoclorito según volumen y cloro actual. Registra turbidez final, pH final, cloro final y hora de reapertura. Incluye en el reporte PDF mensual.

### Reporte mensual (PDF)
Reporte generado con jsPDF + AutoTable, con verificación de integridad HMAC antes de exportar:
- Portada con datos del establecimiento y periodo
- Tabla de bitácora completa
- Resumen estadístico (promedio, mín., máx., % en rango por parámetro)
- IRAPI calculado sobre los registros del periodo
- Tabla de incidentes AFR con datos de cierre
- Filtrable por rango de fechas

### Normativa
Referencia en app de parámetros y rangos Res. 234/2026 + Ley 1209/2008. Lista de verificación de documentos legales con perfil Público / Doméstico y seguimiento de vencimientos (certificación salvavidas, concepto sanitario).

---

## Seguridad

La app implementa una capa de seguridad completa del lado del cliente, sin requerir servidor:

| Mecanismo | Detalle |
|-----------|---------|
| **Autenticación PIN** | PBKDF2-SHA256 con 600 000 iteraciones. Salt único por dispositivo almacenado en IndexedDB |
| **Integridad de datos** | HMAC-SHA256 firma cada clave de `localStorage` en cada escritura. Verificación en lectura; datos manipulados desde DevTools son detectados |
| **Rate limiting** | Bloqueo progresivo por intentos de PIN fallidos con cooldown exponencial |
| **Bloqueo de sesión** | La app se bloquea automáticamente al perder el foco (evento `visibilitychange`). Excepción segura para captura de fotos con cámara (`_photoPickerActive`) |
| **CSP + cabeceras HTTP** | Content Security Policy estricta + HSTS + X-Frame-Options DENY aplicados vía `vercel.json` |
| **Sin dependencias externas en runtime** | Cero llamadas CDN en tiempo de ejecución. Solo jsPDF se carga bajo demanda al generar PDF |

> La clave HMAC es de tipo `non-extractable` almacenada en IndexedDB. No puede ser exportada ni clonada fuera del navegador.

---

## Almacenamiento y gestión de datos

Todos los datos se almacenan exclusivamente en el dispositivo mediante `localStorage`. La app no envía información a ningún servidor externo.

### Claves de almacenamiento

| Clave | Contenido |
|-------|-----------|
| `aqua_bitacora` | Registros diarios de calidad del agua |
| `aqua_afr` | Incidentes de fecalismo y su resolución |
| `aqua_mantenimiento` | Registros de mantenimiento |
| `aqua_config` | Configuración del establecimiento |

### Límite y rotación automática

El `localStorage` tiene un límite de ~5 MB. La app monitorea el uso en cada guardado:

- **> 70 %** (~3.5 MB): alerta de advertencia
- **> 90 %** (~4.5 MB): alerta crítica + oferta de limpieza automática

Al ejecutar la rotación (manual desde el sidebar o automática al confirmar):

| Antigüedad del registro | Acción |
|------------------------|--------|
| Más de 6 meses | Eliminado completamente |
| Entre 3 y 6 meses (con foto) | Se elimina la foto; el texto y datos del análisis se conservan |
| Menos de 3 meses | Sin cambios |

La rotación aplica a bitácora, AFR y mantenimiento. Siempre pide confirmación y muestra un resumen de cuántos registros y fotos se procesaron.

### Persistencia real del localStorage

El `localStorage` **no es una memoria temporal**. Los datos sobreviven a:
- Cierre del navegador o la app
- Apagado o reinicio del dispositivo
- Pantalla de PIN bloqueado
- Cualquier navegación dentro de la app
- Salidas accidentales

Los únicos 3 casos en que se borran los datos:
1. **Restablecer PIN** — borra todo, requiere confirmación explícita con advertencia previa
2. **Eliminar un registro individual** — solo ese registro, requiere confirmación
3. **Borrado manual desde el sistema** — Ajustes → Privacidad → Borrar datos del sitio

---

## Rangos normativos — Resolución 234/2026

| Parámetro | Rango permitido | Nota |
|-----------|----------------|------|
| Cloro libre residual | 2.0 – 4.0 ppm | |
| Cloro combinado | máx. 0.3 ppm | |
| pH | 6.8 – 7.3 | |
| Alcalinidad total | 20 – 150 ppm | |
| Dureza cálcica | 200 – 700 ppm | |
| CYA (ácido cianúrico) | máx. 75 ppm | |
| Turbiedad | máx. 0.5 UNT | |
| Temperatura | máx. 40 °C | |
| ORP | 0 – 700 mV | Eficacia óptima: 650–700 mV |
| ISL (Langelier) | −0.3 a +0.5 | |

---

## Tecnologías

| Capa | Detalle |
|------|---------|
| Frontend | HTML5, CSS3, JavaScript ES2020+ (sin frameworks) |
| Persistencia | `localStorage` (~5 MB) + `IndexedDB` (clave HMAC non-extractable) |
| Offline | Service Worker — network-first para app shell, cache-first para imágenes |
| PDF | jsPDF 2.5 + jsPDF-AutoTable 3.8 (carga bajo demanda al generar reporte) |
| PWA | Web App Manifest, instalable en Android / iOS / Desktop |
| Seguridad | PBKDF2-SHA256 (600k iter.) · HMAC-SHA256 · SubtleCrypto API |
| Código | ~4 600 líneas JS · ~4 400 líneas CSS · ~1 700 líneas HTML |

---

## Uso local

```bash
# Clona el repositorio
git clone https://github.com/wjohan39-jpg/SplashLab.git
cd SplashLab

# Sirve con cualquier servidor HTTP estático
npx serve .
# o
python -m http.server 8080
```

Abre `http://localhost:8080/Aquatech.html` en el navegador.

> El Service Worker requiere HTTPS o `localhost`. No funciona abriendo el archivo directamente con `file://`.

### Instalación como PWA
En Chrome / Edge: abre la app → menú → *Instalar aplicación*.  
En Android: *Agregar a pantalla de inicio* desde el navegador.

### Cabeceras HTTP requeridas en producción

La app requiere las siguientes cabeceras HTTP para que las protecciones de seguridad funcionen correctamente. En Vercel se aplican automáticamente vía `vercel.json`. Para otros servidores, configura el equivalente:

| Cabecera | Valor mínimo requerido |
|----------|----------------------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none';` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(self), geolocation=(), microphone=()` |

> Sin `X-Content-Type-Options: nosniff`, el navegador puede interpretar recursos como HTML, abriendo vectores de XSS. Sin CSP, inyecciones de scripts de terceros no son bloqueadas.

Para desarrollo local con `python -m http.server`, las cabeceras no se aplican — aceptable únicamente en entornos de desarrollo.

---

## Estructura del proyecto

```
SplashLab/
├── Aquatech.html       # App shell — estructura, plantillas y overlays
├── Aquatech.css        # Estilos — diseño responsivo mobile-first (~4 400 líneas)
├── Aquatech.js         # Lógica completa (~4 600 líneas)
├── sw.js              # Service Worker (cache brazada-v5)
├── manifest.json      # Manifiesto PWA (nombre: Aquatech)
└── Multimedia/        # Íconos y recursos gráficos (WebP + PNG)
```

---

**Brazada Aqua Tech** · by Gonzo · Gestión técnica de piscinas · Colombia · Res. 234/2026 · Ley 1209/2008
