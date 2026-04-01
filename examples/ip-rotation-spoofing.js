/**
 * Simulación de Salto de IP (Spoofing).
 * Atacante sofisticado que intenta evadir baneo por IP rotando X-Forwarded-For.
 * Oxide-Gate detectará que el Header Fingerprint es el mismo para todas.
 */
async function rotationAttack() {
    console.log('[OXIDE-GATE] Iniciando ataque de rotación de IP (Clúster Hashing)...');

    for (let i = 0; i < 30; i++) {
        // Simulamos IPs aleatorias para tratar de engañar al firewall
        const fakeIp = `190.15.${Math.floor(Math.random() * 255)}.${i + 1}`;
        
        try {
            const res = await fetch('http://localhost:3000/api/v1/public-stats-by-element', {
                method: 'POST',
                headers: { 
                    'X-Forwarded-For': fakeIp, // Engaño de IP
                    'User-Agent': 'Mozilla/5.0 (Vulnerable-Browser) Oxide-Test',
                    'Accept-Language': 'es-ES,es;q=0.9',
                    'X-Bot-Cluster-Id': 'OXIDE-CLUSTER-99' // Este header es constante
                },
                body: JSON.stringify({ action: 'bypass-attempt', id: i })
            });

            if (res.status === 403) {
              console.warn(`[!] BLOQUEADO en la IP falsificada: ${fakeIp}`);
            } else {
              console.log(`[?] IP aceptada (temporalmente): ${fakeIp}`);
            }
        } catch (e) {
            console.error(`¡Fallo crítico en IP ${fakeIp}!`);
            break;
        }
        await new Promise(r => setTimeout(r, 80));
    }
}

rotationAttack();
