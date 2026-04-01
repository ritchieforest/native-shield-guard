const { Worker, isMainThread, workerData } = require('worker_threads');

/**
 * Este script simula el tráfico coordinado de una Botnet.
 * Inyectamos exactamente los mismos headers en el mismo orden para crear un clúster.
 * Oxide-Gate los Detectará por Fingerprinting de Clúster.
 */

async function attack() {
    for (let i = 0; i < 30; i++) {
        try {
            const res = await fetch('http://localhost:3000/api/v1/public-stats-by-element', {
                method: 'POST',
                headers: { 
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Botnet-Engine/1.0',
                    'Accept-Language': 'es-ES,es;q=0.9',
                    'X-Bot-Fingerprint': 'BOTNET-SHA256-CLUSTER-1'
                },
                body: JSON.stringify({ action: 'brute-force', attempt: i })
            });

            console.log(`[Bot ${workerData.id}] Res: ${res.status}`);
        } catch (e) {
            console.warn(`[Bot ${workerData.id}] Bloqueado o error.`);
        }
    }
}

if (isMainThread) {
    console.log('[OXIDE-GATE] Simulando Botnet de 3 nodos...');
    new Worker(__filename, { workerData: { id: 1 } });
    new Worker(__filename, { workerData: { id: 2 } });
    new Worker(__filename, { workerData: { id: 3 } });
} else {
    attack();
}
