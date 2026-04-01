const { Worker, isMainThread, workerData } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Cargar Configuración del Firewall
const config = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'firewall-config.json'), 'utf8'));

/**
 * Función para generar una IP aleatoria global (Simulación de Proxy/Botnet)
 */
function randomIp() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

/**
 * Simulador de Ataque por Sesiones con Rotación de IP (X-Forwarded-For).
 */
async function sessionAttackFlow() {
    const { id, sessionTimeMs } = workerData;
    const startTime = Date.now();
    let attempts = 0;

    console.log(`[WORKER ${id}] Sesión iniciada con Rotación de IP (Proxy Inverso)...`);

    while (Date.now() - startTime < sessionTimeMs) {
        attempts++;
        
        const user = `user_${crypto.randomInt(0, 1000)}`;
        const pass = `pass_${crypto.randomInt(0, 1000)}`;
        const fakeIp = randomIp(); // Generamos una IP única para cada intento

        try {
            const targetUrl = `http://localhost:3000${config.urls_enabled[0]}`;
            
            const res = await fetch(targetUrl, {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'User-Agent': 'Oxide-Botnet-Distribuida/4.0',
                  'X-Forwarded-For': fakeIp, // El truco de la IP falsa
                  'X-Session-ID': crypto.randomUUID()
                },
                body: JSON.stringify({ 
                    user, 
                    pass, 
                    request_num: attempts,
                    is_bot: false // Intentando engañar
                })
            });

            if (res.status === 403) {
              console.warn(`[WORKER ${id}] ¡TODO EL CLÚSTER BANEADO! (Status: 403 por IP: ${fakeIp})`);
              break;
            } else {
              console.log(`[WORKER ${id}] Intento ${attempts} desde IP: ${fakeIp} (200 OK)`);
            }
        } catch (e) {
            break;
        }

        // Ataque agresivo (mínimo delay)
        await new Promise(r => setTimeout(r, 50));
    }
}

if (isMainThread) {
    const NUM_WORKERS = 7;
    const SESSION_LIFE_MS = 60000;

    console.log(`[OXIDE-GATE] Iniciando Fase 4: ATAQUE GLOBAL DISTRIBUIDO (7 Workers)...`);

    for (let i = 0; i < NUM_WORKERS; i++) {
        new Worker(__filename, { 
            workerData: { id: i + 1, sessionTimeMs: SESSION_LIFE_MS } 
        });
    }
} else {
    sessionAttackFlow();
}
