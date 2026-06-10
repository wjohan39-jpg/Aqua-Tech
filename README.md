# Aqua Tech

**Sistema de gestión de piscinas — Resolución 234 de 2026**

Aplicación web progresiva (PWA) diseñada para operadores y técnicos de piscinas en Colombia. Permite llevar el control diario de parámetros fisicoquímicos, calcular dosificaciones de productos químicos, gestionar acciones de formación y respuesta, y generar reportes PDF normativos — todo desde el navegador, sin instalación y con soporte offline.

---

## Módulos

### Bitácora
Registro diario de parámetros: cloro libre, pH, alcalinidad total, CYA, turbiedad, ORP y temperatura. Cada registro incluye hora AM/PM, operador y notas. Filtrado por fecha y operador. Exportación PDF con tabla completa.

### Calculadora química
Cálculo de dosificaciones para:
- **Cloro** — hipoclorito de calcio 70 %, hipoclorito de sodio 12 %
- **pH** — ácido clorhídrico 33 %, carbonato de sodio
- **Alcalinidad total** — bicarbonato de sodio
- **CYA** — dilución con agua fresca

Incluye cálculo de volumen por forma de piscina (rectangular, circular, elíptica, irregular) y transferencia automática de valores a la bitácora.

### LSI — Índice de Langelier
Cálculo del Índice de Saturación de Langelier con tablas de corrección por temperatura, calcio, alcalinidad y TDS. Indica si el agua es corrosiva, agresiva o en equilibrio.

### IRAPI
Índice de Riesgo Aqua Pool Integral. Calcula el nivel de riesgo sanitario de la piscina a partir de los últimos registros de bitácora (cloro, microorganismos, alcalinidad y otros parámetros). Genera reporte PDF con semáforo de riesgo y recomendaciones.

### AFR — Acciones de Formación y Respuesta
Gestión de incidentes: diarreico, vómito, sangre, sólido, lesión. Registro con fecha, hora y operador. Calcula cierre de piscina y dosis de choque según tipo de incidente conforme a la Res. 234/2026. Exportación PDF por incidente.

### Reportes
Reporte mensual PDF con resumen estadístico de la bitácora: promedios, rangos normativos, número de registros conformes e inconformes.

### Establecimientos y equipos
Ficha del establecimiento (nombre, dirección, NIT, representante legal) y registro de equipos con fechas de mantenimiento y vencimientos. Alertas de vencimiento en el dashboard.

---

## Rangos normativos — Resolución 234 de 2026

| Parámetro | Rango permitido |
|-----------|----------------|
| Cloro libre | 2.0 – 4.0 ppm |
| pH | 6.8 – 7.3 |
| Alcalinidad total | 20 – 150 ppm |
| CYA (ácido cianúrico) | máx. 75 ppm |
| Turbiedad | máx. 0.5 UNT |
| ORP | máx. 700 mV |

---

## Tecnologías

| Capa | Detalle |
|------|---------|
| Frontend | HTML5, CSS3, JavaScript (ES2020+) |
| Persistencia | `localStorage` — sin base de datos externa |
| Offline | Service Worker (estrategia stale-while-revalidate) |
| PDF | jsPDF + jsPDF-AutoTable |
| PWA | Web App Manifest, instalable en Android / iOS / Desktop |

---

## Uso local

```bash
# Clona el repositorio
git clone https://github.com/<tu-usuario>/SplashLab.git
cd SplashLab

# Sirve con cualquier servidor HTTP estático
npx serve .
# o
python -m http.server 8080
```

Abre `http://localhost:8080/Brazada.html` en el navegador.

> El Service Worker requiere HTTPS o `localhost`. No funciona abriendo el archivo directamente con `file://`.

### Instalación como PWA
En Chrome/Edge: abre la app en el navegador → menú → *Instalar aplicación*. En móvil Android: *Agregar a pantalla de inicio*.

---

## Estructura del proyecto

```
SplashLab/
├── Brazada.html       # App shell — estructura y plantillas
├── Brazada.css        # Estilos — diseño responsivo mobile-first
├── Brazada.js         # Lógica completa de la aplicación
├── sw.js              # Service Worker
├── manifest.json      # Manifiesto PWA
└── Multimedia/        # Íconos y recursos gráficos
```

---

## Datos y privacidad

Todos los datos se almacenan exclusivamente en el dispositivo del usuario mediante `localStorage`. La aplicación no envía información a ningún servidor externo.

---

**Aqua Tech** · Gestión técnica de piscinas · Colombia
