const native = require('./native-shield-guard.node');

/**
 * Oxide-Gate: Native Security Library
 * High-performance firewall with Structural Intelligence.
 */

module.exports.initFirewall = () => native.initFirewall();
module.exports.loadState = () => native.loadState();
module.exports.saveState = () => native.saveState();
module.exports.checkAccess = (ip, path) => native.checkAccess(ip, path);
module.exports.checkMaliciousInput = (ip, input) => native.checkMaliciousInput(ip, input);
module.exports.analyzeStructuralSimilarity = (ip, headers, body, size) => {
  return native.analyzeStructuralSimilarity(ip, headers, body, size);
};

module.exports.analyzeBehavior = (ip, path, fingerprint) => {
  return native.analyzeBehavior(ip, path, fingerprint);
};

// --- MÓDULO BETA (INTELIGENCIA PREDICTIVA) ---
module.exports.recordEvent = (ip, fingerprint) => {
  return native.recordEvent(ip, String(fingerprint));
};

module.exports.predictThreat = (ip, fingerprint) => {
  return native.predictThreat(ip, String(fingerprint));
};

module.exports.logMessage = (ip, message) => {
  return native.logMessage(ip, message);
};

module.exports.saveIntelligence = () => {
  return native.saveIntelligence();
};

module.exports.loadIntelligence = () => {
  return native.loadIntelligence();
};

module.exports.getSecurityStatus = () => {
  return native.getSecurityStatus();
};

module.exports.getSecurityInsights = () => {
  return native.getSecurityInsights();
};

module.exports.reloadConfig = () => native.reloadConfig();
module.exports.cleanupRecords = (maxAge) => native.cleanupRecords(maxAge);
