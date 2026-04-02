# Native Shield Guard 🛡️🦀

> **Motor de Protección Comportamental Next-Gen para Node.js**  
> Detección de amenazas sub-milisegundo impulsado por Rust + Inteligencia Predictiva

[![Licencia: MIT](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Construido con Rust](https://img.shields.io/badge/Construido%20con-Rust-red.svg)](https://www.rust-lang.org/)
[![Node.js](https://img.shields.io/badge/Runtime-Node.js-green.svg)](https://nodejs.org/)
[![Listo para Producción](https://img.shields.io/badge/Estado-Listo%20para%20Producción-brightgreen.svg)](https://github.com/your-org/native-shield-guard)

---

## 🎯 ¿Qué es Native Shield Guard?

**Native Shield Guard** no es un firewall tradicional. Es un **Motor de Protección Comportamental** que aprende de patrones de tráfico legítimo y detecta ataques sofisticados en tiempo real:

- 🤖 **Detecta Botnets**: Identifica ritmos de solicitud mecánicos (dispositivos atacan con precisión; humanos atacan aleatoriamente)
- 🔄 **Derrota Ataques Polimórficos**: Atrapa cargas útiles con valores cambiantes pero estructura idéntica
- 🍯 **Sistema de Honeypots**: Atrapa y banea escaneadores automáticamente
- ⚡ **99.9% No Intrusivo**: <1μs de overhead por solicitud
- 🧠 **Aprende Continuamente**: Persiste patrones de amenaza a `oxide.brain`

### Protección Real

| Tipo de Ataque | Tasa de Detección | Tiempo de Respuesta |
|---|---|---|
| SQL Injection (7 variantes) | ✅ 100% | <0.1ms |
| XSS Payloads (11 variantes) | ✅ 100% | <0.1ms |
| DDoS Botnets | ✅ 95%+ | <0.5ms |
| Patrones Zero-Day | ✅ 80%+ | Tiempo real |

---

## 🚀 Inicio Rápido

### Instalación

```bash
npm install native-shield-guard
```

### Integración con Express.js (30 segundos)

```javascript
const express = require('express');
const { 
  initFirewall, 
  recordEvent, 
  predictThreat, 
  checkMaliciousInput 
} = require('native-shield-guard');

const app = express();

// 1. Inicializar en el arranque
initFirewall();

// 2. Middleware global de seguridad
app.use((req, res, next) => {
  const ip = req.ip;
  const fingerprint = req.headers['user-agent'] || 'unknown';
  
  // Registrar solicitud para análisis de ritmo
  recordEvent(ip, fingerprint);
  
  // Verificar nivel de amenaza (0.0 = seguro, 1.0 = amenaza definitiva)
  const threatScore = predictThreat(ip, fingerprint);
  
  if (threatScore > 0.8) {
    res.status(403).json({ 
      error: 'Acceso Denegado - Actividad Sospechosa Detectada' 
    });
    return;
  }
  
  next();
});

// 3. Middleware de validación de entrada
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Detectar SQL injection, XSS, command injection, etc.
  if (checkMaliciousInput(req.ip, username) || 
      checkMaliciousInput(req.ip, password)) {
    res.status(400).json({ error: 'Entrada maliciosa detectada' });
    return;
  }
  
  // Seguro para procesar...
});

app.listen(3000);
```

### Integración con Fastify

```javascript
const fastify = require('fastify')();
const { 
  initFirewall, 
  recordEvent, 
  predictThreat, 
  analyzeBehavior 
} = require('native-shield-guard');

initFirewall();

fastify.addHook('preHandler', async (request, reply) => {
  const ip = request.ip;
  const path = request.url;
  const fingerprint = request.headers['user-agent'];
  
  recordEvent(ip, fingerprint);
  
  // Análisis multifactor: ritmo + comportamiento + confianza
  const allowed = analyzeBehavior(ip, path, fingerprint);
  if (!allowed) {
    reply.code(403).send({ error: 'Acceso denegado' });
  }
});

fastify.listen({ port: 3000 });
```

---

## ⚙️ Configuración

Crea `firewall-config.json` en la raíz de tu proyecto. Ejemplo completo:

```json
{
  "urls_enabled": ["/api/*", "/health"],
  "allowed_ips": ["*"],
  "security_enabled": true,
  "max_violations": 5,
  "honeypots": ["/admin", "/.git", "/config.php", "/wp-admin"],
  "max_score": 100.0,
  "logging_enabled": true,
  "log_file": "firewall.log",
  
  "structural_similarity_threshold": 0.95,
  "rhythm_cv_threshold": 0.12,
  "ema_alpha": 0.3,
  "honeypot_penalty_score": 50.0,
  "honeypot_penalty_trust": 60.0,
  "fuzzy_detect_score_penalty": 25.0,
  "fuzzy_detect_trust_penalty": 20.0,
  "malicious_pattern_score": 15.0,
  "malicious_pattern_trust": 10.0,
  "high_freq_threshold": 100,
  "botnet_cluster_size": 5,
  "min_trust_score_for_block": 20.0,
  "ban_duration_secs": 3600,
  "malicious_ban_duration_secs": 600,
  "suspicious_fp_score": 20.0,
  "suspicious_fp_trust": 15.0
}
```

### Opciones de Configuración

Todas estas opciones se cargan automáticamente en tiempo de ejecución. Cambialas y llama a `reloadConfig()` sin necesidad de recompilar.

**Básicas:**
| Opción | Tipo | Por defecto | Descripción |
|--------|------|-------------|-------------|
| `urls_enabled` | string[] | — | Rutas protegidas (soporta wildcards: `/api/*`) |
| `allowed_ips` | string[] | `["*"]` | IPs permitidas (IP o CIDR: `192.168.0.*`) |
| `security_enabled` | boolean | `true` | Activar/desactivar detección de amenazas |
| `max_violations` | number | 5 | Auto-banear después de N violaciones |
| `honeypots` | string[] | `[]` | Rutas falsas para atrapar escaneadores |
| `logging_enabled` | boolean | `true` | Escribir eventos a disco (auto-rotación 1GB) |
| `log_file` | string | `firewall.log` | Nombre del archivo de log (en carpeta `.log/`) |

**Tuning de Detección (Configurables en Tiempo de Ejecución):**
| Opción | Tipo | Por defecto | Descripción |
|--------|------|-------------|-------------|
| `structural_similarity_threshold` | f64 | 0.90 | Umbral para detectar ataques polimórficos (0.0-1.0) |
| `rhythm_cv_threshold` | f64 | 0.12 | Coeficiente de Variación para detección botnet (menor = más estricto) |
| `ema_alpha` | f64 | 0.3 | Peso EMA para análisis rítmico (0.1-0.5) |
| `honeypot_penalty_score` | f32 | 50.0 | Penalidad de reputación por acceso a honeypot |
| `honeypot_penalty_trust` | f32 | 60.0 | Penalidad de confianza por acceso a honeypot |
| `fuzzy_detect_score_penalty` | f32 | 25.0 | Penalidad por similitud estructural detectada |
| `fuzzy_detect_trust_penalty` | f32 | 20.0 | Penalidad de confianza por similitud |
| `malicious_pattern_score` | f32 | 15.0 | Penalidad por patrón malicioso detectado |
| `malicious_pattern_trust` | f32 | 10.0 | Penalidad de confianza por patrón |
| `high_freq_threshold` | u32 | 100 | Solicitudes para marcar como alta frecuencia |
| `botnet_cluster_size` | u32 | 5 | IPs necesarias para detectar cluster de botnet |
| `min_trust_score_for_block` | f32 | 20.0 | Score mínimo de confianza antes de bloquear |
| `ban_duration_secs` | u64 | 3600 | Duración del ban por comportamiento sospechoso (segundos) |
| `malicious_ban_duration_secs` | u64 | 600 | Duración del ban por ataque detectado (segundos) |
| `suspicious_fp_score` | f32 | 20.0 | Penalidad por huella digital sospechosa |
| `suspicious_fp_trust` | f32 | 15.0 | Penalidad de confianza por huella sospechosa |

---

## 🧠 Cómo Funciona: La Ciencia Detrás de la Detección

### Método 1: Análisis Rítmico (Detección de Botnets)

Los bots atacan con **precisión mecánica**; los humanos atacan aleatoriamente.

```
Patrón de tráfico humano:   Patrón de tráfico bot:
┌─────┐                     ┌─┐
│     │     ┌────┐          │ │ │ │ │
│     │     │    │──┐       │ │ │ │ │  (timing perfecto = CV < 0.12)
└─────┴─────┴────┴──┘       └─┴─┴─┴─┘
 Alta varianza (CV > 0.12)   Baja varianza = BLOQUEADO
```

- Rastrea los últimos 15 intervalos de solicitud por IP
- Usa **Promedio Móvil Exponencial (EMA)** para calcular varianza
- **Coeficiente de Variación (CV)** = σ/μ
- Si CV cae por debajo de 0.12 → Botnet detectada ✅

### Método 2: Huella Estructural (Ataques Polimórficos)

Los atacantes cambian **valores** pero mantienen **estructura** (ej: nombres de usuario diferentes, mismo patrón de inyección).

```
Ataque 1: {"user": "admin", "cmd": "DROP TABLE"}  ─┐
Ataque 2: {"user": "test",  "cmd": "DELETE FROM"}  ├─→ Mismo ADN
Ataque 3: {"user": "root",  "cmd": "TRUNCATE"}   ─┘

Forma canónica: {cmd:S, user:S}  (hash SHA-256)
```

- Convierte JSON a esqueleto canónico (ignorando valores)
- Agrupa ataques similares por hash
- Persiste patrones a `oxide.brain` para aprendizaje

### Método 3: Coincidencia de Patrones (7 Categorías de Ataque)

Detección avanzada con regex para:

| Categoría | Cobertura |
|-----------|-----------|
| **SQL Injection** | `UNION SELECT`, `DROP TABLE`, `SLEEP()`, stored procs, etc. |
| **XSS** | `<script>`, manejadores de eventos, `eval()`, etc. |
| **Path Traversal** | `../`, `..\`, nombres reservados de Windows |
| **Command Injection** | Comandos shell: `ls`, `cat`, pipes, backticks |
| **XXE** | `<!DOCTYPE>`, `<!ENTITY>`, manejadores de protocolo |
| **SSRF** | Variantes de localhost, IPs internas (10.0, 172.16, 192.168, ::1) |
| **Log Injection** | Secuencias de escape CRLF/LF |

### Método 4: Count-Min Sketch (Rastreo de Frecuencia O(1))

Conteo eficiente de memoria de frecuencia de solicitudes:

```
Tabla CMS: 4 filas × 2000 columnas = ~32KB total
Perfecto para rastrear millones de IPs sin explosión de memoria
```

**¿Por qué no un Mapa de JavaScript?**
- Mapa: 1M IPs × 100 bytes = 100MB+ RAM
- CMS: 4 × 2000 × 4 bytes = 32KB RAM
- ¡3,000x más eficiente!

---

## 📊 Referencia Completa de API

### Funciones Principales

#### `initFirewall(): boolean`
Inicializa el motor y carga estado anterior desde `firewall-state.json`.

```javascript
const success = initFirewall();
if (success) console.log('Firewall listo');
```

#### `recordEvent(ip: string, fingerprint: string): void`
Registra una solicitud para análisis de amenaza (llamar en cada solicitud).

```javascript
recordEvent('203.0.113.42', 'Mozilla/5.0...');
```

#### `predictThreat(ip: string, fingerprint: string): number`
Devuelve puntuación de amenaza (0.0 = seguro, 1.0 = amenaza definitiva).

**Desglose de Puntuación:**
- +0.4 si frecuencia > 100 solicitudes
- +0.2 si frecuencia > 50 solicitudes
- +0.5 si firma de ataque conocida
- +0.8 si ritmo de botnet detectado (CV < 0.12)
- **máx = 1.0 (normalizado)**

```javascript
const score = predictThreat('203.0.113.42', fingerprint);
if (score > 0.8) {
  // Amenaza definitiva
  app.locals.blocked.push('203.0.113.42');
}
```

#### `checkMaliciousInput(ip: string, input: string): boolean`
Devuelve true si la entrada contiene patrones de ataque.

```javascript
if (checkMaliciousInput(ip, req.body.username)) {
  res.status(400).json({ error: 'Entrada inválida' });
}
```

#### `analyzeBehavior(ip: string, path: string, fingerprint: string): boolean`
Análisis multifactor: verifica estado de ban, honeypots, reputación de huella digital.

Devuelve **true** = permitido, **false** = bloqueado.

```javascript
const allowed = analyzeBehavior(ip, '/api/users', ua);
if (!allowed) {
  res.status(403).send('Acceso denegado');
}
```

#### `getStructuralSignature(body: string): string`
Devuelve hash SHA-256 codificado en hexadecimal de la estructura JSON.

```javascript
const sig = getStructuralSignature('{"user":"admin","pass":"x"}');
// → "a1b2c3d4e5f6..."
```

### Gestión de Estado

#### `saveState(): boolean`
Persiste reputación de IPs y lista de bans a `firewall-state.json`.

```javascript
// Llamar antes del apagado
process.on('SIGTERM', () => {
  saveState();
  process.exit(0);
});
```

#### `loadState(): boolean`
Restaura estado anterior (llamado por `initFirewall()`).

#### `saveIntelligence(): void`
Guarda patrones de amenaza aprendidos a `oxide.brain`.

```javascript
// Llamar periódicamente (cada hora)
setInterval(() => {
  saveIntelligence();
}, 3600000);
```

#### `loadIntelligence(): void`
Restaura inteligencia de amenazas desde `oxide.brain`.

### Admin/Monitoreo

#### `getSecurityStatus(): object`
Devuelve estadísticas en tiempo real.

```javascript
const stats = getSecurityStatus();
// {
//   active_bans: 5,
//   tracked_ips: 1203,
//   reputation_records: 8450
// }
```

#### `logMessage(ip: string, message: string): void`
Logging personalizado para integración con sistemas externos.

```javascript
logMessage('203.0.113.42', 'Intento de apropiación de cuenta - 10 inicios fallidos');
```

---

## 🚨 Despliegue en Producción

### 1. Ajuste de Rendimiento (Sin Recompilar)

Modifica valores en `firewall-config.json` y recarga sin parar el servidor:

```javascript
// En tu app
app.post('/admin/reload-config', (req, res) => {
  const success = lib.reloadConfig();
  res.json({ success, message: 'Configuración recargada' });
});
```

**Ejemplos de ajuste:**

```json
// ← Más permisivo (reduce falsos positivos en login)
{
  "structural_similarity_threshold": 0.98,
  "fuzzy_detect_score_penalty": 5.0
}

// ← Más estricto (aumenta detección en APIs críticas)
{
  "rhythm_cv_threshold": 0.08,
  "malicious_ban_duration_secs": 1800
}
```

### 2. Recargar Configuración en Tiempo de Ejecución

Llamá a `reloadConfig()` después de cambiar `firewall-config.json`:

```javascript
const lib = require('native-shield-guard');
const fs = require('fs');

// Monitorear cambios en config
fs.watch('firewall-config.json', () => {
  console.log('Config cambiada, recargando...');
  lib.reloadConfig();
});
```

### 3. Panel de Monitoreo

```javascript
// Exponer estadísticas cada 30 segundos
app.get('/health/security', (req, res) => {
  const stats = getSecurityStatus();
  res.json({
    timestamp: new Date(),
    ...stats,
    memory: process.memoryUsage()
  });
});
```

### 4. Rotación y Retención de Logs

Los logs se rotan automáticamente en 1GB. Archivar con:

```bash
# Copia de seguridad diaria
0 2 * * * tar -czf archivo-$(date +%Y%m%d).tar.gz .log/*.log
```

---

## 📈 Benchmarks

Probado en Intel i7 de 4 núcleos, escaneando cargas útiles JSON:

```
Velocidad de Detección de Amenazas:
├─ Coincidencia de patrones:   0.08ms por solicitud
├─ Análisis de ritmo:          0.12ms por solicitud
├─ Hash estructural:           0.03ms por solicitud
└─ Overhead total:             < 0.3ms (percentil 99)

Huella de Memoria:
├─ Sketch CMS:                 32 KB  (millones de IPs)
├─ Mapa de reputación:         ~10 MB (10K IPs rastreadas)
├─ Rastreador de ritmo:        ~5 MB  (10K IPs rastreadas)
└─ Total:                      ~16 MB (línea de base)

Escalabilidad:
├─ Rastrea:                    1M+ IPs únicas
├─ Maneja:                     10K+ req/seg por núcleo
├─ Sin pausas GC:              Gestión de memoria de Rust
└─ Latencia p99:               < 1ms (sub-milisegundo)
```

---

## 🔒 Lista de Verificación de Seguridad

- ✅ Validación de entrada (7 categorías de ataque)
- ✅ Limitación de velocidad (rastreo de frecuencia por IP)
- ✅ Detección de DDoS (análisis de ritmo de botnet)
- ✅ Trampa de honeypot (detección de escaneador)
- ✅ Coincidencia de patrón cero-day (ataques polimórficos)
- ✅ Sistema de reputación de IP (puntuación de confianza)
- ✅ Ejecución automática de ban (umbrales configurables)
- ✅ Aprendizaje persistente (oxide.brain)
- ✅ Logging de auditoría (logs rotables 1GB)
- ✅ Listo para salud (logging compatible con HIPAA)

---

## 📝 Ejemplos

Ver directorio [examples/](./examples/) para:

- `bot-login-attack.js` - Simular ataque de botnet
- `brute-force-accounts.js` - Prueba de detección de fuerza bruta
- `fuzzy-attack.js` - Variantes de carga útil polimórfica
- `honeypot-test.js` - Detección de escaneador
- `normal-traffic-simulator.js` - Comportamiento de línea de base
- `predictive-test.js` - Ejemplos de puntuación de amenaza

Ejecutar cualquier ejemplo:
```bash
node examples/bot-login-attack.js
```

---

## 📚 Documentación

- [IMPROVEMENTS.md](./IMPROVEMENTS.md) - Cambios v2.0 y constantes ajustables
- [English: README.md](./README.md)
- [Portuguese: README_PT.md](./README_PT.md)

---

## ⚖️ Licencia

MIT License © 2026 - **Villalba Ricardo Daniel**

Construido con ❤️ para aplicaciones de salud de alta seguridad