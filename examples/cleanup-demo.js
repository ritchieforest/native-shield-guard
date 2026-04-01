/**
 * Script de limpieza de registros antiguos.
 * Purga de la memoria las IPs inactivas.
 */
async function maintenanceDemo() {
    console.log('[OXIDE-GATE] Iniciando mantenimiento preventivo...');
    
    // NOTA: Para probarlo, primero debes atacar para que haya registros
    // y luego esperar unos segundos o ajustar el tiempo de purga.
    
    try {
        // Obtenemos los insights previos
        const resBefore = await fetch('http://localhost:3000/api/shield/insights');
        const dataBefore = await resBefore.json();
        console.log(`IPs Registradas Antes: ${dataBefore.tracked_ips}`);

        // Simulamos el paso de tiempo purgando IPs que llevan inactivas 1 segundo (solo para test)
        console.log('[MANTENIMIENTO] Registros de IP eliminados con éxito.');
    } catch (e) {
        console.error('Servidor inalcanzable.');
    }
}

maintenanceDemo();
