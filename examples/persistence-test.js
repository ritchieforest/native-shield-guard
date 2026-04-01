/**
 * Prueba de Persistencia de Estado.
 * Este script genera un ataque para ser bloqueado y permitir ver 
 * cómo se guarda el estado en disco (firewall-state.json).
 */
async function testPersistence() {
    console.log('[OXIDE-GATE] Forzando ataques para persistencia...');
    
    for (let i = 0; i < 25; i++) {
        try {
            await fetch('http://localhost:3000/api/v1/public-stats-by-element', {
                method: 'POST',
                body: JSON.stringify({ attack: "polymorphic-persistence-test-" + Math.random() })
            });
        } catch (e) {
            console.log(`[BLOQUEADO] El servidor ha cerrado la conexión.`);
            break;
        }
    }
    
    console.log('--- TEST TERMINADO ---');
    console.log('Ahora revisa en la raíz de tu proyecto el archivo: firewall-state.json');
}

testPersistence();
