const fs = require('fs');
const path = require('path');

/**
 * Generador masivo de 1000 credenciales con 100 usuarios y 100 contraseñas reales.
 */
function generateRealCredentials() {
    const commonUsers = [
        'admin', 'root', 'user', 'guest', 'test', 'webmaster', 'support', 'developer', 'sysadmin', 'api',
        'tester', 'manager', 'editor', 'billing', 'cloud', 'operator', 'backend', 'postmaster', 'backup', 'staff',
        'security', 'hr', 'it', 'marketing', 'sales', 'salesforce', 'jira', 'confluence', 'gitlab', 'docker',
        'jenkins', 'ansible', 'vault', 'consul', 'proxy', 'worker', 'production', 'staging', 'qa', 'audit',
        'superadmin', 'administrator', 'root_admin', 'devops', 'sysops', 'netadmin', 'dbadmin', 'infra', 'sre', 'noc',
        'monitor', 'status', 'bot', 'crawler', 'scanner', 'vpn', 'remote', 'access', 'service', 'app_user',
        'client', 'customer', 'partner', 'vendor', 'integrator', 'webhook', 'delivery', 'logistics', 'warehouse', 'store',
        'shop', 'pos', 'terminal', 'device', 'printer', 'scanner_fix', 'iot', 'gateway', 'sensor', 'router',
        'switch', 'modem', 'wifi', 'hotspot', 'guest_wifi', 'conference', 'meeting', 'zoom', 'teams', 'slack',
        'discord', 'telegram', 'whatsapp', 'skype', 'outlook', 'gmail', 'yahoo', 'icloud', 'protonmail', 'tutanota'
    ];

    const commonPasses = [
        '123456', 'password', '12345678', 'qwerty', '12345', '123456789', 'admin123', 'admin', 'root', 'secret',
        'welcome', 'login', 'access', 'default', 'pass123', 'abc123', 'monkey', 'dragon', 'football', 'soccer',
        'baseball', 'basketball', 'hockey', 'tennis', 'golf', 'swimming', 'running', 'coding', 'hacking', 'cracking',
        'phishing', 'sniffing', 'spoofing', 'scanning', 'pwned', 'leaked', 'breach', 'compromised', 'owned', 'hacked',
        'letmein', 'openup', 'knockknock', 'helloword', 'goodbye', 'seeyou', 'nothing', 'everything', 'something', 'random',
        'secure', 'safety', 'protected', 'encrypted', 'decrypted', 'firewall', 'shield', 'armor', 'sword', 'shield123',
        'thor', 'odin', 'zeus', 'ares', 'athena', 'poseidon', 'hades', 'hermes', 'apollo', 'artemis',
        'batman', 'superman', 'spiderman', 'ironman', 'hulk', 'thor', 'flash', 'wonderwoman', 'aquaman', 'cyborg',
        'starwars', 'startrek', 'matrix', 'avengers', 'justiceleague', 'xmen', 'guardians', 'eternals', 'dune', 'foundation',
        'pizza', 'burger', 'sushi', 'taco', 'pasta', 'steak', 'salad', 'coffee', 'teatime', 'beer'
    ];

    let credentials = [];
    for (let i = 0; i < 1000; i++) {
        const u = commonUsers[i % commonUsers.length];
        const p = commonPasses[Math.floor(Math.random() * commonPasses.length)];
        credentials.push({
            user: `${u}_${i}`,
            pass: p
        });
    }

    const targetPath = path.join(__dirname, 'examples', 'data', 'common-credentials.json');
    fs.mkdirSync(path.join(__dirname, 'examples', 'data'), { recursive: true });
    fs.writeFileSync(targetPath, JSON.stringify(credentials, null, 2));
    console.log(`[OXIDE-GATE] Dataset de 1000 credenciales reales generado en ${targetPath}`);
}

generateRealCredentials();
