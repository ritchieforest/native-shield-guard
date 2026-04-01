use napi_derive::napi;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use regex::RegexSet;
use once_cell::sync::Lazy;
use std::io::{BufReader, Write};
use std::fs::{File, OpenOptions, metadata, rename, create_dir_all};
use std::sync::{Mutex, RwLock};
use std::collections::{HashSet, HashMap, VecDeque};
use std::hash::{Hash, Hasher, DefaultHasher};
use strsim::jaro_winkler;
use chrono::Local;

// --- ESTRUCTURA PROBABILÍSTICA MANUAL (Count-Min Sketch) ---
struct SimpleCMS {
    table: [[u32; 2000]; 4],
}

impl SimpleCMS {
    fn new() -> Self {
        Self { table: [[0; 2000]; 4] }
    }

    fn insert(&mut self, item: &u64) {
        for i in 0..4 {
            let mut h = DefaultHasher::new();
            i.hash(&mut h); // Semilla por fila
            item.hash(&mut h);
            let col = (h.finish() % 2000) as usize;
            self.table[i][col] = self.table[i][col].saturating_add(1);
        }
    }

    fn count(&self, item: &u64) -> u32 {
        let mut min_val = u32::MAX;
        for i in 0..4 {
            let mut h = DefaultHasher::new();
            i.hash(&mut h);
            item.hash(&mut h);
            let col = (h.finish() % 2000) as usize;
            min_val = min_val.min(self.table[i][col]);
        }
        min_val
    }
}

static CMS_SKETCH: Lazy<Mutex<SimpleCMS>> = Lazy::new(|| Mutex::new(SimpleCMS::new()));
static ATTACK_BLOOM: Lazy<Mutex<HashSet<u64>>> = Lazy::new(|| Mutex::new(HashSet::new())); // Bloom sim para Beta
static RHYTHM_TRACKER: Lazy<Mutex<HashMap<String, VecDeque<u128>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

static CURRENT_LOG_START: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(Local::now().format("%Y%m%d_%H%M%S").to_string()));

#[derive(Deserialize, Clone, Debug)]
struct FirewallConfig {
    urls_enabled: HashSet<String>,
    allowed_ips: Vec<String>,
    security_enabled: bool,
    max_violations: u8,
    honeypots: HashSet<String>,
    max_score: f32,
    logging_enabled: bool,
    log_file: String,
}

// Usamos RwLock para permitir múltiples lectores pero bloquear al escribir (Hot-Reload)
static CONFIG: Lazy<RwLock<Option<FirewallConfig>>> = Lazy::new(|| RwLock::new(load_config_from_file()));

#[derive(Deserialize, Serialize, Clone, Debug)]
struct RequestSnapshot {
    header_hash: u64,
    body_preview: String,
    size: usize,
    timestamp: u64,
}

static HISTORY: Lazy<Mutex<Vec<RequestSnapshot>>> = Lazy::new(|| Mutex::new(Vec::with_capacity(50)));
static BOTNET_CLUSTERS: Lazy<Mutex<HashMap<u64, HashSet<String>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static TOTAL_FUZZY_DETECTS: Lazy<Mutex<u32>> = Lazy::new(|| Mutex::new(0));

#[derive(Deserialize, Serialize, Clone, Debug)]
struct ViolationRecord {
    count: u8,
    last_violation: u64,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct IpReputation {
    score: f32,
    last_seen: u64,
    fingerprint: String,
}

#[derive(Deserialize, Serialize)]
struct FirewallState {
    violations: HashMap<String, ViolationRecord>,
    reputation: HashMap<String, IpReputation>,
    blocked: HashMap<String, u64>,
}

static VIOLATIONS: Lazy<Mutex<HashMap<String, ViolationRecord>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static REPUTATION_MAP: Lazy<Mutex<HashMap<String, IpReputation>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static BLOCKED_IPS: Lazy<Mutex<HashMap<String, SystemTime>>> = Lazy::new(|| Mutex::new(HashMap::new()));

static MALICIOUS_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(&[
        r"(?i)(union.*select|drop.*table|truncate.*table|insert.*into|sleep\(|or.*1=1|--|;|\/\*|\*\/)", // SQLi
        r"(?i)(<script|javascript:|onclick|onerror|onload|onmouseover|eval\(|alert\()",              // XSS
        r"(\.\./|\.\.\\|%2e%2e%2f)",                                                                  // Path Traversal
        r"(\$\(|`|\||&|;|&&|\|\|)",                                                                   // Command Injection
    ]).unwrap()
});

fn log_event(ip: &str, message: &str) {
    let config_guard = CONFIG.read().unwrap();
    if let Some(ref config) = *config_guard {
        if config.logging_enabled {
            let _ = create_dir_all(".log"); // Asegurar carpeta .log
            let log_dir = ".log/";
            let base_path = format!("{}{}", log_dir, config.log_file);
            
            // 1. Chequeo de rotación (Demo: 5KB = 5120 bytes)
            if let Ok(meta) = metadata(&base_path) {
                if meta.len() > 1_073_741_824 { // 🚀 1 GB de capacidad por archivo
                    let mut start_time = CURRENT_LOG_START.lock().unwrap();
                    let end_time = Local::now().format("%Y%m%d_%H%M%S").to_string();
                    let rotated_path = format!("{}/firewall_{}_{}.log", log_dir, *start_time, end_time);
                    
                    let _ = rename(&base_path, rotated_path);
                    *start_time = end_time; // Nuevo inicio
                }
            }

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let log_msg = format!("[{}] [IP: {}] {}\n", timestamp, ip, message);
            
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&base_path);
                
            if let Ok(mut f) = file {
                let _ = f.write_all(log_msg.as_bytes());
            }
        }
    }
}

fn load_config_from_file() -> Option<FirewallConfig> {
    let file = File::open("firewall-config.json").ok()?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).ok()
}

#[napi(js_name = "reloadConfig")]
pub fn reload_config() -> bool {
    let new_config = load_config_from_file();
    if let Ok(mut config_guard) = CONFIG.write() {
        *config_guard = new_config;
        true
    } else {
        false
    }
}

fn get_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

#[napi(js_name = "saveState")]
pub fn save_state() -> bool {
    let state = FirewallState {
        violations: VIOLATIONS.lock().unwrap().clone(),
        reputation: REPUTATION_MAP.lock().unwrap().clone(),
        blocked: BLOCKED_IPS.lock().unwrap().iter().map(|(ip, time)| {
            (ip.clone(), time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs())
        }).collect(),
    };

    if let Ok(file) = File::create("firewall-state.json") {
        serde_json::to_writer(file, &state).is_ok()
    } else {
        false
    }
}

#[napi(js_name = "loadState")]
pub fn load_state() -> bool {
    if let Ok(file) = File::open("firewall-state.json") {
        let reader = BufReader::new(file);
        if let Ok(state) = serde_json::from_reader::<_, FirewallState>(reader) {
            *VIOLATIONS.lock().unwrap() = state.violations;
            *REPUTATION_MAP.lock().unwrap() = state.reputation;
            let mut blocked = BLOCKED_IPS.lock().unwrap();
            blocked.clear();
            for (ip, secs) in state.blocked {
                blocked.insert(ip, UNIX_EPOCH + Duration::from_secs(secs));
            }
            return true;
        }
    }
    false
}

#[napi(js_name = "initFirewall")]
pub fn init_firewall() -> bool {
    load_state()
}

#[napi(js_name = "cleanupRecords")]
pub fn cleanup_records(max_age_secs: u32) -> u32 {
    let now = get_now_secs();
    let mut reputation = REPUTATION_MAP.lock().unwrap();
    let initial_count = reputation.len();
    reputation.retain(|_, entry| (now - entry.last_seen) < max_age_secs as u64);
    (initial_count - reputation.len()) as u32
}

#[napi(js_name = "analyzeStructuralSimilarity")]
pub fn analyze_structural_similarity(ip: String, headers: String, body: String, size: u32) -> f64 {
    // 1. Fingerprinting de headers
    let mut hasher = DefaultHasher::new();
    headers.hash(&mut hasher);
    let header_hash = hasher.finish();
    let now = get_now_secs();

    // 2. Detección de Botnet (Cluster Hashing)
    {
        let mut clusters = BOTNET_CLUSTERS.lock().unwrap();
        let ips = clusters.entry(header_hash).or_insert(HashSet::new());
        ips.insert(ip.clone());
        
        if ips.len() > 5 {
            log_event(&ip, "DETECTADO CLUSTER DE BOTNET: Bloqueando huella digital de headers");
            let mut blocked = BLOCKED_IPS.lock().unwrap();
            blocked.insert(ip.clone(), UNIX_EPOCH + Duration::from_secs(now + 3600)); 
            return 1.0; 
        }
    }

    // 3. Poda y Fuzzy Matching
    let mut max_similarity = 0.0;
    let history = HISTORY.lock().unwrap();
    let size_usize = size as usize;

    for prev in history.iter() {
        // Poda por tamaño (si difiere > 15%, no comparamos body)
        let size_diff = if prev.size > size_usize { prev.size - size_usize } else { size_usize - prev.size };
        if size_diff > (prev.size / 7) { continue; }

        let sim = jaro_winkler(&body, &prev.body_preview);
        if sim > max_similarity { max_similarity = sim; }
    }

    drop(history); // Liberar lock antes de mutar el historial

    // 4. Guardar en el historial (mantener solo las últimas 50)
    {
        let mut history = HISTORY.lock().unwrap();
        if history.len() >= 50 { history.remove(0); }
        history.push(RequestSnapshot {
            header_hash,
            body_preview: body.chars().take(200).collect(), // Guardamos solo un preview para ahorrar memoria
            size: size_usize,
            timestamp: now,
        });
    }

    // 5. Elevar sospecha si es muy similar (> 90%)
    if max_similarity > 0.90 {
        let mut stats = TOTAL_FUZZY_DETECTS.lock().unwrap();
        *stats += 1;
        
        let mut reputation = REPUTATION_MAP.lock().unwrap();
        let entry = reputation.entry(ip).or_insert(IpReputation {
            score: 0.0,
            last_seen: now,
            fingerprint: header_hash.to_string(),
        });
        entry.score += 25.0; // Penalización estructural
    }

    max_similarity
}

#[napi(js_name = "logMessage")]
pub fn log_message(ip: String, message: String) {
    // Usamos la función log_event que ya tiene la lógica de rotación de archivos
    log_event(&ip, &message);
}

#[napi(js_name = "saveIntelligence")]
pub fn save_intelligence() {
    let cms = CMS_SKETCH.lock().unwrap();
    let tracker = RHYTHM_TRACKER.lock().unwrap();
    
    // Convertimos el array fijo a Vec para que Serde pueda serializarlo
    let table_as_vec: Vec<Vec<u32>> = cms.table.iter()
        .map(|row| row.to_vec())
        .collect();

    let model_data = serde_json::json!({
        "cms_table": table_as_vec,
        "rhythm_map": *tracker
    });

    if let Ok(content) = serde_json::to_string(&model_data) {
        let _ = std::fs::write("oxide.brain", content);
    }
}

#[napi(js_name = "loadIntelligence")]
pub fn load_intelligence() {
    if let Ok(content) = std::fs::read_to_string("oxide.brain") {
        if let Ok(model_data) = serde_json::from_str::<serde_json::Value>(&content) {
            // Cargar CMS
            if let Some(table_arr) = model_data["cms_table"].as_array() {
                let mut cms = CMS_SKETCH.lock().unwrap();
                for (i, row) in table_arr.iter().enumerate().take(4) {
                    if let Some(cols) = row.as_array() {
                        for (j, val) in cols.iter().enumerate().take(2000) {
                            cms.table[i][j] = val.as_u64().unwrap_or(0) as u32;
                        }
                    }
                }
            }
            // Cargar Ritmos
            if let Some(map) = model_data["rhythm_map"].as_object() {
                let mut tracker = RHYTHM_TRACKER.lock().unwrap();
                for (ip, times_val) in map {
                    if let Some(times_arr) = times_val.as_array() {
                        let mut deq = VecDeque::new();
                        for t in times_arr {
                            if let Some(val) = t.as_u64() {
                                deq.push_back(val as u128);
                            }
                        }
                        tracker.insert(ip.clone(), deq);
                    }
                }
            }
        }
    }
}

#[napi(js_name = "getSecurityInsights")]
pub fn get_security_insights() -> HashMap<String, u32> {
    let mut insights = HashMap::new();
    insights.insert("fuzzy_matches_identified".to_string(), *TOTAL_FUZZY_DETECTS.lock().unwrap());
    insights.insert("botnet_clusters_active".to_string(), BOTNET_CLUSTERS.lock().unwrap().len() as u32);
    
    let stats = get_security_status();
    for (k, v) in stats { insights.insert(k, v); }
    
    insights
}

#[napi(js_name = "checkAccess")]
pub fn check_access(ip: String, path: String) -> bool {
    // 1. Verificar si la IP está en el "congelador" (Ban activo)
    {
        let mut blocked = BLOCKED_IPS.lock().unwrap();
        if let Some(exp) = blocked.get(&ip) {
            if SystemTime::now() < *exp {
                return false;
            } else {
                blocked.remove(&ip);
            }
        }
    }

    let config_guard = CONFIG.read().unwrap();
    let config = match *config_guard {
        Some(ref c) => c,
        None => return false,
    };

    // 2. White-list de URLs
    if !config.urls_enabled.contains(&path) {
        return false;
    }

    // 3. Verificación de IP (Exacta, Wildcard o All)
    config.allowed_ips.iter().any(|allowed| {
        allowed == "*" || 
        allowed == &ip || 
        (allowed.ends_with(".*") && ip.starts_with(&allowed[..allowed.len() - 1]))
    })
}

#[napi(js_name = "checkMaliciousInput")]
pub fn check_malicious_input(ip: String, input: String) -> bool {
    let config_guard = CONFIG.read().unwrap();
    let config = match *config_guard {
        Some(ref c) => c,
        None => return false,
    };

    if !config.security_enabled {
        return false;
    }

    let is_malicious = MALICIOUS_PATTERNS.is_match(&input);

    if is_malicious {
        log_event(&ip, &format!("Ataque detectado: {}", input));
        let mut violations = VIOLATIONS.lock().unwrap();
        let record = violations.entry(ip.clone()).or_insert(ViolationRecord {
            count: 0,
            last_violation: get_now_secs(),
        });

        record.count += 1;
        record.last_violation = get_now_secs();

        // Si tenemos un registro de reputación, también lo penalizamos
        {
            let mut reputation = REPUTATION_MAP.lock().unwrap();
            let entry = reputation.entry(ip.clone()).or_insert(IpReputation {
                score: 0.0,
                last_seen: get_now_secs(),
                fingerprint: String::new(),
            });
            entry.score += 15.0; // Penalización por patrón malicioso individual
        }

        // Si supera el límite de faltas del JSON, ban de 10 min
        if record.count >= config.max_violations {
            log_event(&ip, "IP bloqueada por 10 minutos (Exceso de violaciones)");
            let mut blocked = BLOCKED_IPS.lock().unwrap();
            blocked.insert(ip, SystemTime::now() + Duration::from_secs(600));
            record.count = 0; // Reset tras el ban
        }
        return true;
    }
    false
}

#[napi(js_name = "analyzeBehavior")]
pub fn analyze_behavior(ip: String, path: String, fingerprint: String) -> bool {
    // 1. Verificar si ya está bloqueado
    {
        let mut blocked = BLOCKED_IPS.lock().unwrap();
        if let Some(exp) = blocked.get(&ip) {
            if SystemTime::now() < *exp {
                return false;
            } else {
                blocked.remove(&ip);
            }
        }
    }

    let config_guard = CONFIG.read().unwrap();
    let config = match *config_guard {
        Some(ref c) => c,
        None => return true,
    };

    if !config.security_enabled {
        return true;
    }

    let mut reputation = REPUTATION_MAP.lock().unwrap();

    // Insertar si no existe
    reputation.entry(ip.clone()).or_insert(IpReputation {
        score: 0.0,
        last_seen: get_now_secs(),
        fingerprint: fingerprint.clone(),
    });

    // Actualizar last_seen y fingerprint (entry terminó aquí)
    if let Some(e) = reputation.get_mut(&ip) {
        e.last_seen = get_now_secs();
        e.fingerprint = fingerprint.clone();

        // 2. Detección de Honeypot (Trampa)
        if config.honeypots.contains(&path) {
            log_event(&ip, &format!("Honeypot detectado en ruta: {}", path));
            e.score += 50.0;
        }
    }

    // 3. Evasión: Buscar otras IPs con el mismo fingerprint ya sospechosas (> 30 score)
    // Lo evaluamos después de cerrar el borrow mutable del entry
    let suspicious_fingerprint = reputation.iter().any(|(other_ip, other_entry)| {
        other_ip != &ip && other_entry.fingerprint == fingerprint && other_entry.score > 30.0
    });

    if suspicious_fingerprint {
        if let Some(e) = reputation.get_mut(&ip) {
            e.score += 20.0; // Penalización por usar una huella "quemada"
        }
    }

    // 4. Decisión basada en Score
    let current_score = reputation.get(&ip).map(|e| e.score).unwrap_or(0.0);
    if current_score >= config.max_score {
        log_event(&ip, &format!("IP bloqueada por 1 hora (Score superado: {})", current_score));
        let mut blocked = BLOCKED_IPS.lock().unwrap();
        blocked.insert(ip, SystemTime::now() + Duration::from_secs(3600)); // Ban de 1 hora
        return false;
    }

    true
}

#[napi(js_name = "getSecurityStatus")]
pub fn get_security_status() -> HashMap<String, u32> {
    let blocked = BLOCKED_IPS.lock().unwrap();
    let violations = VIOLATIONS.lock().unwrap();
    let reputation = REPUTATION_MAP.lock().unwrap();
    
    let mut stats = HashMap::new();
    stats.insert("active_bans".to_string(), blocked.len() as u32);
    stats.insert("tracked_ips".to_string(), violations.len() as u32);
    stats.insert("reputation_records".to_string(), reputation.len() as u32);
    stats
}
// --- MÓDULO DE INTELIGENCIA BETA (HEURÍSTICA PROBABILÍSTICA) ---

#[napi(js_name = "recordEvent")]
pub fn record_event(ip: String, _fingerprint: String) {
    // Hashear IP para el CMS (más eficiente que usar String)
    let mut ip_hasher = DefaultHasher::new();
    ip.hash(&mut ip_hasher);
    let ip_hash = ip_hasher.finish();

    // 1. Alimentar Count-Min Sketch
    {
        if let Ok(mut cms) = CMS_SKETCH.lock() {
            cms.insert(&ip_hash);
        }
    }

    // 2. Rastrear Ritmo (Deltas de tiempo)
    {
        if let Ok(mut tracker) = RHYTHM_TRACKER.lock() {
            let times = tracker.entry(ip.clone()).or_insert_with(|| VecDeque::with_capacity(5));
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
            if times.len() >= 5 { times.pop_front(); }
            times.push_back(now);
        }
    }
}

#[napi(js_name = "predictThreat")]
pub fn predict_threat_level(ip: String, fingerprint: String) -> f64 {
    let mut score: f64 = 0.0;
    
    let mut s = DefaultHasher::new();
    fingerprint.hash(&mut s);
    let fp_hash = s.finish();

    // A. CMS (Frecuencia Estimada)
    let freq = {
        let mut ip_hasher = DefaultHasher::new();
        ip.hash(&mut ip_hasher);
        let ip_hash = ip_hasher.finish();

        if let Ok(cms) = CMS_SKETCH.lock() {
            cms.count(&ip_hash)
        } else { 0 }
    };
    if freq > 100 { score += 0.4; } 
    else if freq > 50 { score += 0.2; }

    // B. Filtro de Ataques Confirmados (Simulando Bloom)
    {
        if let Ok(bloom) = ATTACK_BLOOM.lock() {
            if bloom.contains(&fp_hash) {
                score += 0.5; 
            }
        }
    }

    // C. Varianza Rítmica (Mechanical Presence)
    {
        if let Ok(tracker) = RHYTHM_TRACKER.lock() {
            if let Some(times) = tracker.get(&ip) {
                if times.len() >= 4 {
                    let mut deltas = Vec::new();
                    for i in 1..times.len() {
                        deltas.push((times[i] - times[i-1]) as f64);
                    }
                    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
                    let variance = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
                    if variance < 2000.0 { score += 0.5; }
                }
            }
        }
    }

    score.min(1.0)
}
