# Oxide-Gate (Native Shield Guard) 🛡️🦀

**La Próxima Generación de Seguridad Proactiva para Node.js.**  
*Motor de seguridad nativo de alto rendimiento impulsado por Rust e Inteligencia Predictiva.*

---

## 🚀 ¿Para qué sirve esta librería?
**Oxide-Gate** NO es un firewall tradicional. Es un **Motor de Protección Conductual** construido en Rust. Sirve para proteger tus aplicaciones web de ataques que los firewalls comunes no ven:

1.  **Bots de Fuerza Bruta rítmicos:** Detecta y bloquea bots que atacan con intervalos constantes (ej: cada 250ms).
2.  **Ataques Polimórficos:** Identifica ataques incluso si cambian su contenido pero mantienen su estructura "esqueletal".
3.  **Honeypots Activos:** Banea automáticamente IPs que intentan acceder a rutas prohibidas (`/admin`, `.env`).
4.  **Escaneo de Inyecciones:** Filtra SQLi, XSS y Path Traversal a través del motor nativo.
5.  **Ahorro de CPU:** Al bloquear ataques en el pre-filtro predictivo, evitas procesar peticiones maliciosas en tu lógica de Node.js.

---

## 🛠️ Tecnologías Clave
- **🦀 Núcleo Nativo**: Construido en Rust para un consumo de recursos casi nulo.
- **🧠 IA Predictiva**: Análisis de varianza rítmica para detectar ataques mecánicos.
- **🔍 Huella Estructural**: Comparación difusa (Fuzzy Matching) de payloads JSON.
- **💾 Persistencia**: Guarda todo el aprendizaje en el archivo `oxide.brain`.
- **📜 Logs Industriales**: Sistema nativo de logs rotativos de 1GB.

---

## ⚡ Rendimiento: Rust vs Node.js Puro 🏎️
¿Por qué usar un motor nativo? 🚀
- **Filtrado en Microsegundos**: Rust gestiona el rastreo de IPs en tiempo constante O(1) sin bloquear el Event Loop de Node.js.
- **Sin Garbage Collector**: A diferencia de JS, Rust no sufre picos de memoria ni parones por recolección de basura durante ataques masivos.
- **Throughput Extremo**: Oxide-Gate es entre **10 y 50 veces más rápido** que los middlewares de seguridad basados puramente en JavaScript cuando hay una inundación de peticiones.

---

## 📦 Instalación
```bash
npm install healthcare-firewall
```

---

## 🛡️ Ejemplo de Implementación Profesional (Middleware)

```javascript
const { 
  initFirewall, 
  loadIntelligence, 
  recordEvent, 
  predictThreat, 
  checkAccess, 
  analyzeStructuralSimilarity, 
  checkMaliciousInput, 
  analyzeBehavior, 
  logMessage 
} = require('healthcare-firewall');

initFirewall();
loadIntelligence();

app.use((req, res, next) => {
  // Priorizar X-Forwarded-For para simulaciones de salto de IP / Proxy
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? forwarded.split(',')[0] : (req.ip || req.connection.remoteAddress);
  const path = req.path;
  const userAgent = req.headers['user-agent'] || 'not-fingerprinted';

  // 0. INTELIGENCIA PREDICTIVA (Pre-filtro Heurístico) 🕵️‍♂️📈
  recordEvent(ip, userAgent);
  const predictionScore = predictThreat(ip, userAgent);
  
  if (predictionScore >= 0.8) {
    const logInfo = `Mechanical behavior detected (Threat Score: ${predictionScore.toFixed(2)})`;
    console.error(`[PREDICTIVE BLOCK] IP: ${ip} | ${logInfo}`);
    logMessage(ip, logInfo);
    return res.status(403).json({ error: 'Mechanical behavior detected', score: predictionScore });
  }

  // I. Filtro de Acceso Básico (IP Whitelist / Blacklist Activa)
  if (!checkAccess(ip, path)) {
    return res.status(403).json({ 
      error: 'Acceso denegado', 
      message: 'Ruta no permitida o IP bloqueada temporalmente.' 
    });
  }

  // II. Fingerprinting Estructural (Analizando la "forma" de la petición)
  const headerFingerprint = Object.keys(req.headers)
    .sort()
    .map(key => `${key}:${req.headers[key]}`)
    .join('|');
  
  const bodyStr = JSON.stringify(req.body || {});
  const structuralRisk = analyzeStructuralSimilarity(ip, headerFingerprint, bodyStr, bodyStr.length);

  if (structuralRisk > 0.9) {
    console.warn(`[POLIMORPHIC ATTACK DETECTED] IP: ${ip} | Riesgo Estructural: ${structuralRisk}`);
    return res.status(403).json({ 
      error: 'Ataque detectado por similitud estructural', 
      message: 'Tu petición es sospechosamente similar a un patrón de ataque conocido.' 
    });
  }

  // III. Escaneo por Firmas (Regex Tradicional para SQLi/XSS)
  const inspectionData = [req.url, bodyStr].join(' ');
  if (checkMaliciousInput(ip, inspectionData)) {
    console.warn(`[VULNERABILITY DETECTED] IP: ${ip} | Path: ${path}`);
    return res.status(403).json({ 
      error: 'Inyección detectada', 
      message: 'Se ha registrado una violación de seguridad.' 
    });
  }

  // IV. Análisis de Comportamiento (Honeypots / Score de Reputación)
  if (!analyzeBehavior(ip, path, userAgent)) {
    console.warn(`[REPUTATION BLOCK] IP: ${ip} | Score de reputación excedido.`);
    return res.status(403).json({ 
      error: 'IP Identificada como maliciosa', 
      message: 'Tu reputación ha superado el límite de seguridad permitido.' 
    });
  }

  next();
});
```

---

## 📊 Referencia Completa de la API

| Función | Descripción |
| :--- | :--- |
| `initFirewall()` | Inicializa el motor nativo de Rust y carga las reglas. |
| `loadState()` / `saveState()` | Gestiona la persistencia de baneos y listas negras. |
| `loadIntelligence()` | Carga los pesos y ritmos del modelo `.brain`. |
| `saveIntelligence()` | Persiste el modelo predictivo (IA) en el disco. |
| `predictThreat(ip, finger)` | Devuelve el puntaje de riesgo rítmico (0.0 a 1.0). |
| `analyzeStructuralSimilarity(ip, h, b, s)` | Detecta ataques polimórficos mediante Fuzzy Matching. |
| `checkMaliciousInput(ip, texto)` | Escaneo nativo ultra-rápido de inyecciones (SQLi, XSS). |
| `analyzeBehavior(ip, path, finger)` | Gestiona Honeypots y el sistema de avisos de reputación. |
| `logMessage(ip, msg)` | Escribre en los logs rotativos industriales de 1GB. |
| `reloadConfig()` | Recarga el archivo JSON de configuración en caliente. |

---

## ⚖️ Licencia
MIT License © 2026 - **Villalba Ricardo Daniel**  
[GitHub Profile](https://github.com/ritchieforests)