# Oxide-Gate (Native Shield Guard) 🛡️🦀

**The Next Generation of Proactive Security for Node.js.**  
*High-performance native firewall powered by Rust and Predictive Intelligence.*

## 🚀 What is Oxide-Gate?
**Oxide-Gate** is NOT a traditional firewall. It is a **Behavioral Protection Engine** built in Rust. It serves to protect your web applications (Express, Fastify, etc.) from:
1.  **DDoS & Bruteforce**: Detecting mechanical request rhythms.
2.  **Polymorphic Attacks**: Identifying malicious payloads even if they change their content but keep their structure.
3.  **Scanners & Crawlers**: Automatically banning IPs that touch forbidden routes (Honeypots).

---

## 🛠️ Key Features
- **🦀 Rust-Native Core**: Sub-millisecond overhead.
- **🧠 Predictive AI**: Rhythmic Variance Analysis for bot detection.
- **🔍 Structural Fingerprinting**: Fuzzy similarity detection for payloads.
- **💾 Brain Persistence**: Saves its learning in `oxide.brain`.
- **📜 Industrial Logs**: 1GB auto-rotating log system.

## 📦 Installation
```bash
npm install healthcare-firewall
```

## 🛡️ Quick Start
```javascript
const { recordEvent, predictThreat, initFirewall } = require('healthcare-firewall');

initFirewall();

app.use((req, res, next) => {
  recordEvent(req.ip, req.headers['user-agent']);
  if (predictThreat(req.ip, req.headers['user-agent']) > 0.8) {
    return res.status(403).send("Blocked by Oxide-Gate");
  }
  next();
});
```

---

## 🏳️ Other Languages
- [Leer en Español (README_ES.md)](./README_ES.md)
- [Ler em Português (README_PT.md)](./README_PT.md)

## 📊 API Reference

| Function | Description |
| :--- | :--- |
| `initFirewall()` | Initializes the native Rust engine. |
| `loadIntelligence()` | Loads the `.brain` model weights. |
| `saveIntelligence()` | Persists the predictive model to disk. |
| `predictThreat(ip, finger)` | Returns a threat score (0.0 to 1.0) based on rhythm. |
| `analyzeStructuralSimilarity(ip, h, b, s)` | Detects polymorphic attacks via Fuzzy Matching. |
| `checkMaliciousInput(ip, text)` | Scans for SQLi, XSS, and Path Traversal. |
| `analyzeBehavior(ip, path, finger)` | Handles Honeypots and violation counting. |
| `logMessage(ip, msg)` | Writes a custom message to the 1GB rotating log. |
| `reloadConfig()` | Hot-reloads the JSON configuration. |

## ⚖️ License
MIT
