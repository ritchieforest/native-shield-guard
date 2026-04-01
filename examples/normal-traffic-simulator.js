const { Worker, isMainThread, workerData } = require('worker_threads');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Cargar el banco de peticiones normales desde el JSON
const normalRequests = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'normal-requests.json'), 'utf8'));

/**
 * Simulador de Usuarios Legítimos con Datos Dinámicos.
 * Selecciona una petición al azar de nuestro dataset para cada paso.
 */
async function normalUserFlow() {
    console.log(`[USER ${workerData.id}] Sesión iniciada: Usando datos dinámicos de examples/data/`);

    for (let i = 0; i < 20; i++) {
        // Seleccionamos un payload base al azar de nuestro JSON
        const basePayload = normalRequests[Math.floor(Math.random() * normalRequests.length)];
        
        // Creamos una "instancia única" de esa petición (añadiendo variabilidad)
        const finalPayload = {
            ...basePayload,
            _request_id: crypto.randomUUID(),
            _sent_at: new Date().toISOString()
        };

        try {
            const res = await fetch('http://localhost:3000/api/v1/public-stats-by-element', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'User-Agent': `Mozilla/5.0 (Windows NT 10.0) User-Worker-${workerData.id}`
                },
                body: JSON.stringify(finalPayload)
            });
            
            if (res.status === 200) {
              console.log(`[USER ${workerData.id}] Paso ${i}: 200 OK (${finalPayload.action})`);
            } else {
              console.error(`[USER ${workerData.id}] Paso ${i}: Bloqueo Injustificado (${res.status})`);
            }
        } catch (e) {
            console.error(`Error de red en User ${workerData.id}`);
        }
        
        await new Promise(r => setTimeout(r, 1000 + Math.random() * 2000));
    }
}

if (isMainThread) {
    console.log('[OXIDE-GATE] Iniciando simulación de tráfico realista basada en dataset...');
    for (let i = 1; i <= 4; i++) {
        new Worker(__filename, { workerData: { id: i } });
    }
} else {
    normalUserFlow();
}
