# Native Shield Guard 🛡️🦀

**The Next Generation of Proactive Security for Node.js.**  
*High-performance native firewall powered by Rust and Predictive Intelligence.*

## 🚀 What is Native Shield Guard?
**Native Shield Guard** is NOT a traditional firewall. It is a **Behavioral Protection Engine** built in Rust. It serves to protect your web applications (Express, Fastify, etc.) from:
1.  **DDoS & Bruteforce**: Detecting mechanical request rhythms.
2.  **Polymorphic Attacks**: Identifying malicious payloads even if they change their content but keep their structure.
3.  **Scanners & Crawlers**: Automatically banning IPs that touch forbidden routes (Honeypots).

---

## 🛠️ Key Features
- **🦀 Rust-Native Core**: Sub-millisecond overhead ($<1\mu s$ per check).
- **🧠 Predictive AI**: **EMA (Exponential Moving Average)** Rhythmic Analysis.
- **🔍 Structural Fingerprinting**: Canonization of JSON bodies to detect attack DNA.
- **💾 Brain Persistence**: Saves its learning in `oxide.brain`.
- **📜 Industrial Logs**: 1GB auto-rotating log system.

---

## 🧠 Deep Tech: Engineering Behind the Shield
### 1. EMA Predictive AI (Rhythmic Variance)
Most firewalls use simple counters. **Native Shield Guard** tracks a sliding window of **15 request intervals** and calculates:
- **Variance Analysis**: Uses the **Exponential Moving Average (EMA)** to calculate a weighted variance.
- **CV Detection**: If the **Coefficient of Variation (CV)** drops below 0.12, the motor detects a mechanical pattern (bot). Legitimate humans produce a high "jitter" (variance), while scripts emit a perfect, mechanical "beat".

### 2. Structural Fingerprinting (DNA Canonization)
Polymorphic attacks change values (emails, IDs) to evade simple similarity checks. Our engine performs **Structural Shearing**:
- **Algorithm**: The JSON is stripped of values, keys are recursively sorted, and primitive types are mapped (S for String, N for Number).
- **Hashing**: A deterministic hash is generated from the "Skeleton". If two different payloads share the same skeleton and high suspicious scores, the entire **Attack Pattern** is blacklisted globally.

### 3. The Performance Gap: Rust vs Pure Node.js 🏎️
Why is a native engine mandatory for this?
- **No Garbage Collector (GC)**: In a massive attack, Node.js spends half its time cleaning up Memory Heap. Rust manages memory manually, processing **10x to 50x** more requests without CPU spikes.
- **Bitwise CMS**: Our **Count-Min Sketch** is implemented with bitwise hashing in O(1) time. Trying to track 1 million IPs with a JavaScript `Map` would consume gigabytes of RAM and eventually crash the event loop.
- **SIMD Optimized**: Rust uses CPU instructions (where available) to speed up JSON scanning and similarity checks.

---

## ⚡ Quick Start
```javascript
const { recordEvent, predictThreat, initFirewall } = require('native-shield-guard');

initFirewall();

app.use((req, res, next) => {
  recordEvent(req.ip, req.headers['user-agent']);
  if (predictThreat(req.ip, req.headers['user-agent']) > 0.8) {
    return res.status(403).send("Blocked by Native Shield Guard");
  }
  next();
});
```

## 📊 API Reference

| Function | Description |
| :--- | :--- |
| `initFirewall()` | Initializes the native Rust engine. |
| `loadIntelligence()` | Loads the `.brain` model weights. |
| `getStructuralSignature(body)` | Returns the DNA hash of a JSON body structure. |
| `predictThreat(ip, finger)` | Returns a threat score (0.0 to 1.0) using EMA logic. |
| `analyzeBehavior(ip, path, finger)` | Handles Honeypots and Reputation Score. |
| `logMessage(ip, msg)` | Writes a custom message to the 1GB rotating log. |

---

## ⚖️ License
MIT License © 2026 - **Villalba Ricardo Daniel**
