const { Worker, isMainThread, workerData } = require('worker_threads');

/**
 * Este script simula ataques polimórficos desde 2 hilos paralelos.
 * Los ataques son ligeramente diferentes para intentar evadir Regex tradicionales,
 * pero Oxide-Gate los detectará por similitud estructural (Jaro-Winkler).
 */

async function runAttack() {
    const payloads = [
        { query: "SELECT * FROM users WHERE id = 1 OR 1=1" },
        { query: "SELECT * FROM users WHERE id = 1 OR 1 = 1" }, // Nota el espacio extra
        { query: "SELECT * FROM users WHERE id = 1 OR 'a'='a'" },
        { query: "SELECT * FROM users WHERE id = 1 -- comment" }
    ];

    for (let i = 0; i < 20; i++) {
        const payload = payloads[Math.floor(Math.random() * payloads.length)];
        try {
            const res = await fetch('http://localhost:3000/api/v1/public-stats-by-element', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Bot-Header': 'OxideBot-1.0'
                },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            console.log(`[Thread ${workerData.id}] Status: ${res.status} | Data: ${JSON.stringify(data)}`);
        } catch (e) {
            console.error(`[Thread ${workerData.id}] Error: El firewall probablemente te bloqueó.`);
        }
        // Pequeño delay para no saturar
        await new Promise(r => setTimeout(r, 100));
    }
}

if (isMainThread) {
    console.log('[SIMULADOR] Iniciando ataques concurrentes en 2 hilos...');
    // Crear 2 hilos (Workers)
    const w1 = new Worker(__filename, { workerData: { id: 1 } });
    const w2 = new Worker(__filename, { workerData: { id: 2 } });
    
    w1.on('exit', () => console.log('Hilo 1 terminó.'));
    w2.on('exit', () => console.log('Hilo 2 terminó.'));
} else {
    runAttack();
}
