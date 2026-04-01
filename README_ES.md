# Native Shield Guard 🛡️🦀

**La Próxima Generación de Seguridad Proactiva para Node.js.**  
*Motor de seguridad nativo de alto rendimiento impulsado por Rust e Inteligencia Predictiva.*

---

## 🚀 ¿Para qué sirve esta librería?
**Native Shield Guard** NO es un firewall tradicional. Es un **Motor de Protección Conductual** construido en Rust. Sirve para proteger tus aplicaciones web de ataques que los firewalls comunes no ven:

1.  **Bots de Fuerza Bruta rítmicos:** Detecta y bloquea bots que atacan con intervalos constantes (ej: cada 250ms).
2.  **Ataques Polimórficos:** Identifica ataques incluso si cambian su contenido pero mantienen su estructura "esqueletal".
3.  **Honeypots Activos:** Banea automáticamente IPs que intentan acceder a rutas prohibidas (`/admin`, `.env`).
4.  **Escaneo de Inyecciones:** Filtra SQLi, XSS y Path Traversal a través del motor nativo.

---

## 🔬 Ciencia Profunda: Ingeniería Tras el Escudo

### 1. IA Predictiva: Análisis EMA (Rhythmic Variance) 📈
La mayoría de los firewalls usan contadores simples. **Native Shield Guard** rastrea una ventana deslizante de **15 intervalos de tiempo** entre peticiones y calcula:
- **Análisis de Varianza**: Utiliza el **Promedio Móvil Exponencial (EMA)** para calcular una varianza ponderada en tiempo real.
- **Detección CV**: Si el **Coeficiente de Variación (CV)** cae por debajo de 0.12, el motor detecta un patrón mecánico (bot). Los humanos legítimos producen una varianza alta ("jitter"), mientras que los scripts emiten un "latido" mecánico perfecto.

### 2. Huella Estructural: Canonización de ADN JSON 🧬
Los ataques polimórficos cambian valores (correos, IDs) para evadir las firmas tradicionales. Nuestro motor realiza el **Esquematizado Estructural**:
- **Algoritmo**: El JSON es despojado de sus valores, las llaves se ordenan recursivamente y los tipos primitivos se mapean (S para String, N para Number, etc).
- **Hashing**: Se genera un hash determinante del "Esqueleto". Si dos payloads comparten el mismo esqueleto sospechoso, el **Patrón de Ataque** completo es bloqueado desde cualquier IP.

### 3. La Brecha de Rendimiento: Rust vs Node.js Puro 🏎️
¿Por qué es obligatorio un motor nativo para esto?
- **Sin Garbage Collector (GC)**: En un ataque masivo, Node.js consume la mitad de su tiempo limpiando el Heap de Memoria. Rust gestiona la memoria manualmente, procesando entre **10 y 50 veces más peticiones** sin picos de CPU.
- **Bitwise CMS**: Nuestro **Count-Min Sketch** está implementado con hashing a nivel de bits en tiempo O(1). Intentar rastrear 1 millón de IPs con un `Map` de JavaScript consumiría gigabytes de RAM y colapsaría el event-loop.
- **Optimizado para SIMD**: Rust utiliza instrucciones especiales del procesador para acelerar el escaneo de JSON y el cálculo de similitudes.

---

## ⚡ Implementación Rápida
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

## 📊 Referencia Completa de la API

| Función | Descripción |
| :--- | :--- |
| `initFirewall()` | Inicializa el motor nativo de Rust. |
| `loadIntelligence()` / `saveIntelligence()` | Gestiona el aprendizaje persistente del modelo `.brain`. |
| `getStructuralSignature(body)` | Devuelve el hash de ADN de la estructura de un JSON. |
| `predictThreat(ip, finger)` | Devuelve un puntaje de riesgo (0.0 a 1.0) usando lógica EMA. |
| `analyzeBehavior(ip, path, finger)` | Gestiona Honeypots y Score de Reputación. |
| `logMessage(ip, msg)` | Escribe logs industriales de 1GB en formato rotativo. |

---

## ⚖️ Licencia
MIT License © 2026 - **Villalba Ricardo Daniel**  
[GitHub Profile](https://github.com/ritchieforests)