/**
 * Ataque de Fuerza Bruta Estructural.
 * Intenta loguearse en 50 cuentas distintas.
 * Oxide-Gate detectará que el "cuerpo" de la petición es casi idéntico.
 */
async function bruteForce() {
    const users = ['admin', 'user1', 'root', 'guest', 'api_service', 'tester'];
    console.log('[OXIDE-GATE] Iniciando Fuerza Bruta Estructural...');

    for (let i = 0; i < 50; i++) {
        const user = users[i % users.length] + i;
        try {
            const res = await fetch('http://localhost:3000/api/v1/public-stats-by-element', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'User-Agent': 'BruteForce-Tool/1.0'
                },
                body: JSON.stringify({ 
                    username: user, 
                    password: 'password123',
                    source: 'login_page'
                })
            });
            
            if (res.status === 403) {
              console.warn(`[!] BLOQUEADO en el intento ${i} para el usuario: ${user}`);
              break;
            } else {
              console.log(`[OK] Intento ${i} enviado para: ${user}`);
            }
        } catch (e) {
            console.warn('¡Conexión cerrada por el firewall!');
            break;
        }
        await new Promise(r => setTimeout(r, 50));
    }
}
bruteForce();
