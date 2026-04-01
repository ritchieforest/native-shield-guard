const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// LÓGICA DEL TRABAJADOR (EL QUE ATACA) 🤖🔨
if (!isMainThread) {
    const { workerId, interval } = workerData;
    let attempts = 0;
    
    console.log(`[WORKER ${workerId}] Iniciado y listo para atacar...`);

    setInterval(async () => {
        attempts++;
        const simulatedIP = `10.0.0.${workerId}`; // Cada worker simula una IP distinta
        try {
            const res = await fetch('http://localhost:3000/api/secure-login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': `Oxide-Bot/Worker-${workerId}`,
                    'X-Forwarded-For': simulatedIP
                },
                body: JSON.stringify({ user: 'admin', pass: 'hacking-attempt' })
            });

            if (res.status === 403) {
                // Silenciamos un poco los logs de éxito de baneo para no saturar la consola
                if (attempts % 10 === 0) {
                   console.log(`[WORKER ${workerId}] BANNED exitosamente (Intento ${attempts})`);
                }
            }
        } catch (e) {
            // Silencio si el servidor cae
        }
    }, interval);
} 

// LÓGICA PRINCIPAL (EL QUE LANZA LOS WORKERS) 👩‍🔬📈
else {
    const NUM_WORKERS = 10;
    console.log(`\n[OXIDE-GATE BENCHMARK] Lanzando ${NUM_WORKERS} atacantes paralelos...`);
    console.log('Monitoriza tu CPU en la terminal del Servidor.');

    for (let i = 0; i < NUM_WORKERS; i++) {
        new Worker(__filename, {
            workerData: { workerId: i, interval: 200 }
        });
    }
}
