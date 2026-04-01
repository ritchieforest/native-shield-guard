const { recordEvent, predictThreat } = require('../index');

async function testIntelligence() {
    const ipHumano = "1.2.3.4";
    const ipBot = "9.9.9.9";
    const fingerprint = "Mozilla/5.0-Chrome-120";

    console.log('[OXIDE-GATE] Iniciando Fase Beta: Inteligencia Predictiva 🕵️‍♂️');

    // 1. SIMULAR HUMANO (RITMO ERRÁTICO)
    console.log('\n--- ESCENARIO 1: USUARIO HUMANO ---');
    const humanDelays = [500, 1500, 800, 2200, 1100];
    for (let delay of humanDelays) {
        await new Promise(r => setTimeout(r, delay));
        recordEvent(ipHumano, fingerprint);
        const threat = predictThreat(ipHumano, fingerprint);
        console.log(`[HUMAN] Petición tras ${delay}ms. Score de amenaza: ${threat.toFixed(2)}`);
    }

    // 2. SIMULAR BOT (RITMO MECÁNICO)
    console.log('\n--- ESCENARIO 2: BOT MECÁNICO ---');
    const botDelay = 200; // Siempre el mismo intervalo
    for (let i = 0; i < 5; i++) {
        await new Promise(r => setTimeout(r, botDelay));
        recordEvent(ipBot, fingerprint);
        const threat = predictThreat(ipBot, fingerprint);
        console.log(`[BOT] Petición cada ${botDelay}ms (Paso ${i}). Score de amenaza: ${threat.toFixed(2)}`);
    }

    console.log('\n--- CONCLUSIÓN ---');
    console.log('Fíjate cómo el Bot disparó el score de amenaza al detectar una varianza rítmica baja.');
}

testIntelligence();
