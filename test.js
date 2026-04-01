const { 
  checkAccess, 
  checkMaliciousInput, 
  getSecurityStatus, 
  reloadConfig,
  analyzeBehavior,
  analyzeStructuralSimilarity,
  getSecurityInsights,
  saveState,
  initFirewall,
  cleanupRecords,
  recordEvent,
  predictThreat,
  logMessage,
  saveIntelligence,
  loadIntelligence
} = require('./index.js');
const express = require('express');
const os = require('os');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. Inicialización: Cargar estado y cerebro predictivo
console.log('[OXIDE-GATE] Cargando estado y modelo predictivo...');
initFirewall();
loadIntelligence();

// 2. Persistencia automática: Guardar estado y cerebro cada 30 segundos
setInterval(() => {
  saveState();
  saveIntelligence();
  console.log('[OXIDE-GATE] Estado y modelo .brain persistidos.');
}, 30000);

// 3. Mantenimiento: Limpiar registros de IP de más de 24 horas cada hora
setInterval(() => {
  const cleaned = cleanupRecords(86400);
  if (cleaned > 0) console.log(`[OXIDE-GATE] Limpieza: Se eliminaron ${cleaned} registros antiguos.`);
}, 3600000);

// MONITOR DE RECURSOS (CPU/RAM) 📊
setInterval(() => {
    const usage = process.cpuUsage();
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;
    const cpuTotal = (usage.user + usage.system) / 1000000; // Segundos totales
    
    console.log(`\n[RECURSOS] CPU: ${cpuTotal.toFixed(2)}s acumulados | RAM: ${(usedMemory / 1024 / 1024 / 1024).toFixed(2)} GB`);
}, 5000);

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
    
    // Registrar el bloqueo en el log oficial de Rust
    logMessage(ip, logInfo);

    return res.status(403).json({ 
        error: 'Mechanical behavior detected', 
        score: predictionScore 
    });
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
  const fingerprint = req.headers['user-agent'] || 'not-fingerprinted';
  if (!analyzeBehavior(ip, path, fingerprint)) {
    console.warn(`[REPUTATION BLOCK] IP: ${ip} | Score de reputación excedido.`);
    return res.status(403).json({ 
      error: 'IP Identificada como maliciosa', 
      message: 'Tu reputación ha superado el límite de seguridad permitido.' 
    });
  }

  next();
});

// MONITOR DE INSIGHTS (NUEVO)
app.get('/api/shield/insights', (req, res) => {
  res.json(getSecurityInsights());
});

app.get('/api/v1/public-stats-by-element', (req, res) => {
  res.json({ data: 'Estadísticas públicas' });
});

app.post('/api/shield/reload', (req, res) => {
  if (reloadConfig()) res.json({ message: 'Configuración recargada' });
  else res.status(500).json({ error: 'Fallo al recargar' });
});

// NUEVO: Endpoint de Login Protegido para Simular Ataques 🛡️🔑
app.post('/api/secure-login', (req, res) => {
  const { user, pass } = req.body;
  
  if (user === 'admin' && pass === '1234') {
    return res.json({ status: 'success', message: 'Bienvenido, administrador.' });
  }

  res.status(401).json({ status: 'fail', message: 'Credenciales inválidas.' });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`[OXIDE-GATE] Activo con Inteligencia Estructural en puerto ${PORT}`);
  console.log(`- Insights: GET /api/shield/insights`);
  console.log(`- Status: GET /api/shield/status`);
});
