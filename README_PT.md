# Oxide-Gate (Native Shield Guard) 🛡️🦀

**A Próxima Geração de Segurança Proativa para Node.js.**  
*Motor de segurança nativo de alta performance impulsionado por Rust e Inteligência Preditiva.*

---

## 🚀 Para que serve esta biblioteca?
O **Oxide-Gate** NÃO é um firewall tradicional. É um **Motor de Proteção Comportamental** construído em Rust. Serve para proteger suas aplicações web de ataques que os firewalls comuns não conseguem ver:

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

## ⚖️ Licença
MIT
