const fs = require('fs');
const path = require('path');

/**
 * Generador automático de 1000 credenciales comunes para pruebas de seguridad.
 */
function generateCredentials() {
    const users = ['admin', 'root', 'webmaster', 'support', 'test', 'guest', 'user', 'developer', 'api_user', 'ops'];
    const passes = ['123456', 'password', '12345678', 'qwerty', '12345', 'admin123', 'root123', 'secret', 'welcome', 'login'];
    
    let credentials = [];
    
    // Generar 1000 registros mezclando comunes y variaciones
    for (let i = 0; i < 1000; i++) {
        const u = users[Math.floor(Math.random() * users.length)];
        const p = passes[Math.floor(Math.random() * passes.length)];
        credentials.push({
            user: `${u}_${i}`,
            pass: `${p}_${Math.floor(Math.random() * 1000)}`
        });
    }

    const targetPath = path.join(__dirname, 'examples', 'data', 'common-credentials.json');
    fs.mkdirSync(path.join(__dirname, 'examples', 'data'), { recursive: true });
    fs.writeFileSync(targetPath, JSON.stringify(credentials, null, 2));
    console.log(`[GENERATOR] Se han creado 1000 credenciales en ${targetPath}`);
}

generateCredentials();
