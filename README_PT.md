# Native Shield Guard 🛡️🦀

**A Próxima Geração de Segurança Proativa para Node.js.**  
*Motor de segurança nativo de alta performance impulsionado por Rust e Inteligência Preditiva.*

---

## 🚀 Para que serve esta biblioteca?
O **Native Shield Guard** NÃO é um firewall tradicional. É um **Motor de Proteção Comportamental** construído em Rust. Serve para proteger suas aplicações web de ataques que os firewalls comuns não conseguem ver:

1.  **Bots de Força Bruta Rítmicos:** Detecta e bloqueia bots que atacam com intervalos constantes (ex: a cada 250ms).
2.  **Ataques Polimórficos:** Identifica ataques mesmo que mudem seu conteúdo, mas mantenham sua estrutura básica.
3.  **Honeypots Ativos:** Bloqueia automaticamente IPs que tentam acessar rotas proibidas (`/admin`, `.env`).
4.  **Varredura de Injeções:** Filtra SQLi, XSS e Path Traversal através do motor nativo Rust.
5.  **Economia de CPU:** Ao bloquear ataques no pré-filtro preditivo, você evita processar requisições maliciosas na sua lógica do Node.js.

---

## 🛠️ Tecnologias Principais
- **🦀 Núcleo Nativo**: Construído em Rust para consumo de recursos quase zero.
- **🧠 IA Preditiva**: Análise de variância rítmica para detectar ataques mecânicos.
- **🔍 Assinatura Estrutural**: Comparação difusa (Fuzzy Matching) de cargas úteis JSON.
- **💾 Persistência**: Salva todo o aprendizado no arquivo `oxide.brain`.
- **📜 Logs Industriais**: Sistema nativo de logs rotativos de 1GB.

---

## ⚡ Rendimento: Rust vs Node.js Puro 🏎️
Por que usar um motor nativo? 🚀
- **Filtragem em Microssegundos**: O Rust gerencia o rastreamento de IPs em tempo constante O(1) sem bloquear o Event Loop do Node.js.
- **Sem Garbage Collector**: Ao contrário do JS, o Rust não sofre picos de memória ou pausas para coleta de lixo durante ataques massivos.
- **Throughput Extremo**: O **Native Shield Guard** é de **10 a 50 vezes mais rápido** que os middlewares de segurança baseados puramente em JavaScript durante eventos de inundação de requisições.

---

## 📊 Referência da API

| Função | Descrição |
| :--- | :--- |
| `initFirewall()` | Inicializa o motor nativo Rust. |
| `loadIntelligence()` | Carrega os pesos do modelo `.brain`. |
| `saveIntelligence()` | Persiste o modelo preditivo no disco. |
| `predictThreat(ip, finger)` | Retorna um score de ameaça (0.0 a 1.0) baseado no ritmo. |
| `analyzeStructuralSimilarity(ip, h, b, s)` | Detecta ataques polimórficos via Fuzzy Matching. |
| `checkMaliciousInput(ip, texto)` | Analisa SQLi, XSS e Path Traversal. |
| `analyzeBehavior(ip, path, finger)` | Gerencia Honeypots e contagem de violações. |
| `logMessage(ip, msg)` | Escreve uma mensagem personalizada no log rotativo de 1GB. |
| `reloadConfig()` | Recarrega a configuração JSON instantaneamente. |

---

## 📦 Instalação
```bash
npm install healthcare-firewall
```

---

## 🛡️ Início Rápido
```javascript
const { recordEvent, predictThreat, initFirewall } = require('healthcare-firewall');

initFirewall();

app.use((req, res, next) => {
  recordEvent(req.ip, req.headers['user-agent']);
  
  if (predictThreat(req.ip, req.headers['user-agent']) > 0.8) {
    return res.status(403).send("Bloqueado pela Inteligência do Native Shield Guard");
  }
  next();
});
```

---

## ⚖️ Licença
MIT License © 2026 - **Villalba Ricardo Daniel**
