/**
 * Simulador de Bot Scanner de vulnerabilidades.
 * Intenta acceder a rutas marcadas como Honeypot en firewall-config.json.
 */
async function honeypotAttack() {
    const traps = ['/.env', '/wp-login.php', '/phpmyadmin'];
    
    for (let path of traps) {
        console.log(`[BOT] Intentando acceder a ruta sensible: ${path}`);
        try {
            const res = await fetch(`http://localhost:3000${path}`, { 
                method: 'GET',
                headers: { 'X-Bot-Sim': 'True' }
            });
            const data = await res.json();
            console.log(`Respuesta: ${res.status} | ${JSON.stringify(data)}`);
            
            // Ver si ya nos bloquearon el acceso
            const statusRes = await fetch('http://localhost:3000/api/shield/status');
            const stats = await statusRes.json();
            console.log(`Estado Global del Firewall:`, stats);
        } catch (e) {
            console.error(`¡IP probablemente bloqueada con éxito! Detalle: ${e.message}`);
        }
    }
}

honeypotAttack();
