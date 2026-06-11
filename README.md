# Brazada Aqua Tech

**Sistema de gestión de calidad de agua en piscinas — Resolución 234/2026 · Colombia**

Aplicación web progresiva (PWA) diseñada para operadores y técnicos de piscinas en Colombia. Permite llevar el control diario de parámetros fisicoquímicos, calcular dosificaciones con productos comerciales colombianos, gestionar protocolos de respuesta ante incidentes de fecalismo, y generar reportes PDF normativos — todo desde el navegador, sin instalación y con soporte offline completo.

---

## Módulos

### Dashboard principal
Panel en tiempo real con medidores visuales (gauge) para todos los parámetros del último registro. Muestra el estado de cumplimiento normativo, indicadores IRAPI e ISL de Langelier, alertas de antigüedad de datos (8 h / 24 h), vencimientos documentales y acceso rápido al reporte mensual.

### Calculadora química
Dosificaciones para productos comerciales colombianos con factores estequiométricos verificados:

| Parámetro | Productos disponibles |
|-----------|----------------------|
| **Cloro libre** | Hipoclorito de calcio 70 % · Hipoclorito de sodio 15 % |
| **Cloro combinado** | Cloración de choque (target = 10× el combinado) |
| **pH** | HCl 31 % · Bisulfato de sodio (subir) · Carbonato de sodio (bajar) |
| **Alcalinidad total** | Bicarbonato de sodio (subir) · HCl 31 % (bajar) |
| **CYA** | Dilución con agua fresca |
| **Neutralizar cloro** | Tiosulfato de sodio |

Incluye cálculo de volumen por forma de piscina (rectangular, cilíndrica, oval, irregular) y advertencias normativas Art. 5 Res. 234/2026.

### LSI — Índice de Saturación de Langelier
Cálculo del ISL con tablas de coeficientes del Anexo Técnico I, Res. 234/2026:

```
ISL = pH + CT (temperatura) + CD (dureza cálcica) + CA (alcalinidad) − 12.1
Rango aceptable: −0.3 a +0.5 (asimétrico)
```

Interpolación lineal entre puntos de tabla, diagnóstico automático de compensación (agua corrosiva / equilibrada / incrustante), y cálculo automático en cada registro de bitácora.

### IRAPI 2026
Índice de Riesgo de Piscinas según Res. 234/2026. Calcula el nivel de riesgo sanitario con pesos normativos:

| Factor | Peso |
|--------|------|
| Microbiológico (laboratorio) | 45 % |
| Alcalinidad / pH | 30 % |
| Cloro residual | 20 % |
| Otros (turbiedad, CYA, ORP) | 5 % |

Cálculo automático desde la bitácora (mínimo 10 registros en 30 días). Sin dato microbiológico, el score se normaliza sobre el 55 % medible. Bandas de riesgo: Sin riesgo · Bajo · Medio · Alto.

### Bitácora diaria
Registro de parámetros con validación en tiempo real contra rangos Res. 234/2026:

- Cloro libre, cloro combinado, pH, alcalinidad, dureza cálcica
- Turbiedad, temperatura, CYA, ORP, TDS, conductividad
- ORP con zona de eficacia (< 650 mV = advertencia · > 700 mV = fuera de rango)
- ISL calculado automáticamente en cada guardado
- Gráfico de tendencia histórica por parámetro (7 / 14 / 30 días)
- Fotos adjuntas por registro (compresión automática)

### Protocolo AFR — Accidente con Fecalismo en el agua Recreativa
Gestión de incidentes según Art. 27 Res. 234/2026:

| Tipo | Pasos | Cloro objetivo | CT requerido |
|------|-------|----------------|-------------|
| **Sólido** | 7 pasos | 10 ppm | — |
| **Vómito** | 7 pasos | 2 ppm | — |
| **Diarreico** | 8 pasos (incluye notificación a autoridad sanitaria) | 20 ppm | 15 600 mg·min/L (Cryptosporidium) |

Calcula dosis de hipoclorito según volumen y cloro actual. Registra turbidez final, pH final, cloro final y hora de reapertura. Incluye en el reporte PDF mensual.

### Reporte mensual (PDF)
Reporte generado con jsPDF + AutoTable:
- Portada con datos del establecimiento y periodo
- Tabla de bitácora completa
- Resumen estadístico (promedio, mín., máx., % en rango por parámetro)
- IRAPI calculado sobre los registros del periodo
- Tabla de incidentes AFR con datos de cierre
- Filtrable por rango de fechas

### Normativa
Referencia en app de parámetros y rangos Res. 234/2026 + Ley 1209/2008. Lista de verificación de documentos legales con perfil Público / Doméstico y seguimiento de vencimientos (certificación salvavidas, concepto sanitario).

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
| Persistencia | `localStorage` — sin base de datos ni backend |
| Offline | Service Worker — network-first para app shell, cache-first para imágenes |
| PDF | jsPDF 2.5 + jsPDF-AutoTable 3.8 (carga bajo demanda) |
| PWA | Web App Manifest, instalable en Android / iOS / Desktop |

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

Abre `http://localhost:8080/Brazada.html` en el navegador.

> El Service Worker requiere HTTPS o `localhost`. No funciona abriendo el archivo directamente con `file://`.

### Instalación como PWA
En Chrome / Edge: abre la app → menú → *Instalar aplicación*.
En Android: *Agregar a pantalla de inicio* desde el navegador.

---

## Estructura del proyecto

```
SplashLab/
├── Brazada.html       # App shell — estructura, plantillas y overlays
├── Brazada.css        # Estilos — diseño responsivo mobile-first
├── Brazada.js         # Lógica completa (~3 500 líneas)
├── sw.js              # Service Worker (cache brazada-v5)
├── manifest.json      # Manifiesto PWA
└── Multimedia/        # Íconos y recursos gráficos (WebP + PNG)
```

---

## Datos y privacidad

Todos los datos se almacenan exclusivamente en el dispositivo del usuario mediante `localStorage`. La aplicación no envía información a ningún servidor externo ni requiere conexión a internet después de la primera carga.

---

**Brazada Aqua Tech** · Gestión técnica de piscinas · Colombia · Res. 234/2026 · Ley 1209/2008
