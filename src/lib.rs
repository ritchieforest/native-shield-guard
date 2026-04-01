use napi_derive::napi;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use regex::RegexSet;
use once_cell::sync::Lazy;
use std::io::{BufReader, Write};
use std::fs::{File, OpenOptions, metadata, rename, create_dir_all};
use std::sync::{Mutex, RwLock};
use std::collections::{HashSet, HashMap, VecDeque};
use std::hash::{Hash, Hasher, DefaultHasher};
use strsim::jaro_winkler;
use chrono::Local;

// ============================================================================
// PERFORMANCE TUNING CONSTANTS - Production-Ready Configuration
// ============================================================================
// These constants can be moved to firewall-config.json for runtime tuning

/// Coefficient of Variation (CV) threshold for detecting botnet rhythmic patterns
/// Lower values = more strict. Range: 0.01 - 0.30 (0.12 is optimal for most cases)
const RHYTHM_CV_THRESHOLD: f64 = 0.12;

/// EMA smoothing factor for rhythmic analysis (exponential weight)
/// Higher = more recent requests weighted. Range: 0.1 - 0.5
const EMA_ALPHA: f64 = 0.3;

/// Honeypot hit reputation penalty
const HONEYPOT_PENALTY_SCORE: f32 = 50.0;
const HONEYPOT_PENALTY_TRUST: f32 = 60.0;

/// Fuzzy detection penalties (structural similarity > 0.90)
const FUZZY_DETECT_SCORE_PENALTY: f32 = 25.0;
const FUZZY_DETECT_TRUST_PENALTY: f32 = 20.0;

/// Malicious pattern detection penalties
const MALICIOUS_PATTERN_SCORE: f32 = 15.0;
const MALICIOUS_PATTERN_TRUST: f32 = 10.0;

/// Suspicious fingerprint detected across IPs
const SUSPICIOUS_FP_SCORE: f32 = 20.0;
const SUSPICIOUS_FP_TRUST: f32 = 15.0;

/// Request frequency thresholds for CMS sketch analysis
const HIGH_FREQ_THRESHOLD: u32 = 100;  // score += 0.4
const MID_FREQ_THRESHOLD: u32 = 50;    // score += 0.2

/// Botnet cluster detection (if N+ IPs share same header hash)
const BOTNET_CLUSTER_SIZE_THRESHOLD: usize = 5;
const BOTNET_CLUSTER_SCORE: f64 = 1.0;  // definitive block

/// Trust score thresholds
const MIN_TRUST_SCORE_FOR_BLOCK: f32 = 20.0;
const BAN_DURATION_SECS: u64 = 3600;   // 1 hour
const MALICIOUS_BAN_DURATION_SECS: u64 = 600;  // 10 minutes

/// Structural similarity threshold
const STRUCTURAL_SIMILARITY_THRESHOLD: f64 = 0.90;

/// Bloom filter collision penalty
const BLOOM_ATTACK_SCORE: f64 = 0.5;

// ============================================================================
// COUNT-MIN SKETCH: Probabilistic frequency tracking (O(1) memory)
// Detects IP request frequency without storing massive data structures
// ============================================================================
struct SimpleCMS {
    table: [[u32; 2000]; 4],
}

impl SimpleCMS {
    /// Create new CMS with 4 rows and 2000 columns (~32KB total)
    fn new() -> Self {
        Self { table: [[0; 2000]; 4] }
    }

    /// Insert an item (IP hash). Uses 4 different hash functions for collision resistance
    /// Time: O(1), Space: constant (only 4 updates)
    fn insert(&mut self, item: &u64) {
        for i in 0..4 {
            let mut h = DefaultHasher::new();
            i.hash(&mut h);
            item.hash(&mut h);
            let col = (h.finish() % 2000) as usize;
            self.table[i][col] = self.table[i][col].saturating_add(1);
        }
    }

    /// Get minimum count across all hash functions (CMS guarantee: true value ≤ result)
    /// Time: O(1), returns conservative estimate of item frequency
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
static ATTACK_BLOOM: Lazy<Mutex<HashSet<u64>>> = Lazy::new(|| Mutex::new(HashSet::new()));
static RHYTHM_TRACKER: Lazy<Mutex<HashMap<String, VecDeque<u128>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static CURRENT_LOG_START: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(Local::now().format("%Y%m%d_%H%M%S").to_string()));

/// Main firewall configuration loaded from firewall-config.json
/// All settings are loaded at startup and can be reloaded via reloadConfig()
#[derive(Deserialize, Clone, Debug)]
struct FirewallConfig {
    /// Whitelisted URL paths for this firewall instance
    urls_enabled: HashSet<String>,
    /// Allowed source IPs (supports wildcard: "192.168.*")
    allowed_ips: Vec<String>,
    /// Enable/disable all security checks
    security_enabled: bool,
    /// Max violations before automatic IP ban
    max_violations: u8,
    /// Honeypot paths for deception (higher score = more suspicious)
    honeypots: HashSet<String>,
    /// Max reputation score before forced ban
    max_score: f32,
    /// Enable/disable logging to disk
    logging_enabled: bool,
    /// Log file name (stored in .log/ directory with 1GB auto-rotation)
    log_file: String,
}

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
    trust_score: f32,
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

/// Comprehensive malicious pattern detection using RegexSet (compiled once at startup)
/// Covers: SQL Injection, XSS, Path Traversal, Command Injection, XXE, SSRF, Log Injection
static MALICIOUS_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(&[
        // SQL Injection patterns
        r"(?i)(union.*select|drop.*table|truncate.*table|insert.*into|delete.*from|sleep\(|benchmark\(|or.*1=1|or.*true|--|;|\/\*|\*\/|xp_|sp_)",
        
        // XSS patterns
        r"(?i)(<script|javascript:|on\w*=|eval\(|expression\(|alert\(|confirm\(|prompt\(|onerror|onload|onmouseover|onmouseenter|onclick|ondblclick|onchange|<iframe|<object|<embed|<img.*on)",
        
        // Path Traversal patterns
        r"(\.\./|\.\.|%2e%2e|\.\\\.|\.\\\.|%2e%2e%2f|..\\|NUL|CON|PRN|AUX|COM|LPT)",
        
        // Command Injection patterns
        r"(\$\(|`|\||&|;|&&|\|\||\n|\r|\t|cmd\.exe|bash|sh|powershell)",
        
        // XXE (XML External Entity) patterns
        r"(?i)(<!ENTITY|SYSTEM|PUBLIC|DOCTYPE|xml.*encoding|[<]?\?xml|\.dtd|jar:|file://|php://|expect://|zlib://)",
        
        // SSRF patterns
        r"(?i)(localhost|127\.0|169\.254|10\.\d|172\.(1[6-9]|2[0-9]|3[01])|192\.168|::1|\[::\]|file://|gopher://|dict://|ldap://)",
        
        // Log Injection patterns  
        r"(\r\n|\n\r|\x0d\x0a|%0d%0a|%0a|%0d|\\r\\n|\\n|LogFormatted|\[CRITICAL\]|\[ALERT\])",
    ]).unwrap()
});

/// Centralized logging with automatic 1GB rotation
/// Thread-safe, appends to .log/firewall-<timestamp>.log
/// Auto-rotates old logs with timestamp suffix
fn log_event(ip: &str, message: &str) {
    let config_guard = CONFIG.read().unwrap();
    if let Some(ref config) = *config_guard {
        if config.logging_enabled {
            let _ = create_dir_all(".log");
            let log_dir = ".log/";
            let base_path = format!("{}{}", log_dir, config.log_file);
            
            if let Ok(meta) = metadata(&base_path) {
                if meta.len() > 1_073_741_824 {
                    let mut start_time = CURRENT_LOG_START.lock().unwrap();
                    let end_time = Local::now().format("%Y%m%d_%H%M%S").to_string();
                    let rotated_path = format!("{}/firewall_{}_{}.log", log_dir, *start_time, end_time);
                    let _ = rename(&base_path, rotated_path);
                    *start_time = end_time;
                }
            }

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let log_msg = format!("[{}] [IP: {}] {}\n", timestamp, ip, message);
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&base_path) {
                let _ = f.write_all(log_msg.as_bytes());
            }
        }
    }
}

/// Load firewall configuration from JSON file
/// Returns None if file not found or JSON invalid (firewall runs with defaults)
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

/// Structural fingerprinting for polymorphic attack detection
/// Converts JSON to canonical form ignoring values: {email: "x@x.com", id: 123} → {email:S,id:N}
/// This detects when attacker changes VALUES but keeps STRUCTURE (same attack DNA)
///
/// Example: SQLi payloads with different usernames but same structure all match
fn canonize_structure(val: &Value) -> String {
    match val {
        Value::Object(map) => {
            // Sort keys for consistent ordering
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut s = String::from("{");
            for k in keys {
                s.push_str(&format!("{}:{},", k, canonize_structure(&map[&k])));
            }
            s.push('}');
            s
        }
        Value::Array(arr) => {
            // Only examine first element type (assumes homogeneous arrays)
            if let Some(first) = arr.get(0) {
                format!("[{}]", canonize_structure(first))
            } else {
                "[]".to_string()
            }
        }
        Value::String(_) => "S".to_string(),
        Value::Number(_) => "N".to_string(),
        Value::Bool(_) => "B".to_string(),
        Value::Null => "L".to_string(),
    }
}

/// Get the structural DNA hash of a request body
/// Returns hex-encoded hash of canonized JSON structure
/// Used to group similar attacks regardless of payload values
#[napi(js_name = "getStructuralSignature")]
pub fn get_structural_signature(body: String) -> String {
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let structure = canonize_structure(&v);
    let mut hasher = DefaultHasher::new();
    structure.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Analyze request similarity using Jaro-Winkler string matching
/// Detects polymorphic attacks by comparing recent request bodies
/// Returns similarity score 0.0-1.0; >0.90 triggers reputation penalty
/// Also detects botnet clusters via shared header fingerprints (>5 IPs same headers)
#[napi(js_name = "analyzeStructuralSimilarity")]
pub fn analyze_structural_similarity(ip: String, headers: String, body: String, size: u32) -> f64 {
    let mut hasher = DefaultHasher::new();
    headers.hash(&mut hasher);
    let header_hash = hasher.finish();
    let now = get_now_secs();

    {
        let mut clusters = BOTNET_CLUSTERS.lock().unwrap();
        let ips = clusters.entry(header_hash).or_insert(HashSet::new());
        ips.insert(ip.clone());
        if ips.len() > BOTNET_CLUSTER_SIZE_THRESHOLD {
            log_event(&ip, "DETECTADO CLUSTER DE BOTNET: Bloqueando huella digital de headers");
            return BOTNET_CLUSTER_SCORE; 
        }
    }

    let mut max_similarity = 0.0;
    let history = HISTORY.lock().unwrap();
    let size_usize = size as usize;

    for prev in history.iter() {
        let size_diff = if prev.size > size_usize { prev.size - size_usize } else { size_usize - prev.size };
        if size_diff > (prev.size / 7) { continue; }
        let sim = jaro_winkler(&body, &prev.body_preview);
        if sim > max_similarity { max_similarity = sim; }
    }
    drop(history);

    {
        let mut history = HISTORY.lock().unwrap();
        if history.len() >= 50 { history.remove(0); }
        history.push(RequestSnapshot {
            header_hash,
            body_preview: body.chars().take(200).collect(),
            size: size_usize,
            timestamp: now,
        });
    }

    if max_similarity > STRUCTURAL_SIMILARITY_THRESHOLD {
        let mut stats = TOTAL_FUZZY_DETECTS.lock().unwrap();
        *stats += 1;
        let mut reputation = REPUTATION_MAP.lock().unwrap();
        let entry = reputation.entry(ip).or_insert(IpReputation {
            score: 0.0,
            trust_score: 100.0,
            last_seen: now,
            fingerprint: header_hash.to_string(),
        });
        entry.score += FUZZY_DETECT_SCORE_PENALTY;
        entry.trust_score -= FUZZY_DETECT_TRUST_PENALTY;
    }

    max_similarity
}

/// Manually log a custom message for an IP (for integration with external systems)
#[napi(js_name = "logMessage")]
pub fn log_message(ip: String, message: String) {
    log_event(&ip, &message);
}

/// Persist learned threat intelligence: CMS frequency table + rhythm history → oxide.brain
/// Call this periodically (e.g., before shutdown) to preserve learning across restarts
#[napi(js_name = "saveIntelligence")]
pub fn save_intelligence() {
    let cms = CMS_SKETCH.lock().unwrap();
    let tracker = RHYTHM_TRACKER.lock().unwrap();
    let table_as_vec: Vec<Vec<u32>> = cms.table.iter().map(|row| row.to_vec()).collect();
    let model_data = serde_json::json!({
        "cms_table": table_as_vec,
        "rhythm_map": *tracker
    });
    if let Ok(content) = serde_json::to_string(&model_data) {
        let _ = std::fs::write("oxide.brain", content);
    }
}

/// Restore previously learned threat intelligence from oxide.brain
/// Automatically called on init, but can be called manually for hot-reload
#[napi(js_name = "loadIntelligence")]
pub fn load_intelligence() {
    if let Ok(content) = std::fs::read_to_string("oxide.brain") {
        if let Ok(model_data) = serde_json::from_str::<serde_json::Value>(&content) {
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

/// Check if IP:path combination is allowed (whitelist + active bans)
/// Returns false if: IP is currently banned OR path not in urls_enabled OR IP not in allowed_ips
#[napi(js_name = "checkAccess")]
pub fn check_access(ip: String, path: String) -> bool {
    {
        let mut blocked = BLOCKED_IPS.lock().unwrap();
        if let Some(exp) = blocked.get(&ip) {
            if SystemTime::now() < *exp { return false; }
            else { blocked.remove(&ip); }
        }
    }

    let config_guard = CONFIG.read().unwrap();
    let config = match *config_guard { Some(ref c) => c, None => return false };
    if !config.urls_enabled.contains(&path) { return false; }

    config.allowed_ips.iter().any(|allowed| {
        allowed == "*" || allowed == &ip || (allowed.ends_with(".*") && ip.starts_with(&allowed[..allowed.len() - 1]))
    })
}

/// Check input against malicious pattern detection (SQL, XSS, RCE, etc.)
/// Returns true if malicious pattern found. Increments violations and reputation penalties.
/// Auto-bans IP after max_violations reached.
#[napi(js_name = "checkMaliciousInput")]
pub fn check_malicious_input(ip: String, input: String) -> bool {
    let config_guard = CONFIG.read().unwrap();
    let config = match *config_guard { Some(ref c) => c, None => return false };
    if !config.security_enabled { return false; }

    if MALICIOUS_PATTERNS.is_match(&input) {
        log_event(&ip, &format!("Ataque detectado: {}", input));
        let mut violations = VIOLATIONS.lock().unwrap();
        let record = violations.entry(ip.clone()).or_insert(ViolationRecord { count: 0, last_violation: get_now_secs() });
        record.count += 1;

        {
            let mut reputation = REPUTATION_MAP.lock().unwrap();
            let entry = reputation.entry(ip.clone()).or_insert(IpReputation {
                score: 0.0, trust_score: 100.0, last_seen: get_now_secs(), fingerprint: String::new()
            });
            entry.score += MALICIOUS_PATTERN_SCORE;
            entry.trust_score -= MALICIOUS_PATTERN_TRUST;
        }

        if record.count >= config.max_violations {
            let mut blocked = BLOCKED_IPS.lock().unwrap();
            blocked.insert(ip, SystemTime::now() + Duration::from_secs(MALICIOUS_BAN_DURATION_SECS));
            record.count = 0;
        }
        return true;
    }
    false
}

/// Multi-factor behavior analysis: honeypots + fingerprint matching + trust scoring
/// Returns true if IP allowed, false if banned/suspicious
///
/// Detection logic:
/// 1. Check if IP is currently banned (with expiry cleanup)
/// 2. Penalize honeypot hits (deception path access)
/// 3. Penalize suspicious fingerprints shared with other high-score IPs
/// 4. Force ban if trust_score drops below MIN_TRUST_SCORE_FOR_BLOCK
#[napi(js_name = "analyzeBehavior")]
pub fn analyze_behavior(ip: String, path: String, fingerprint: String) -> bool {
    // Check if IP is already banned
    {
        let mut blocked = BLOCKED_IPS.lock().unwrap();
        if let Some(exp) = blocked.get(&ip) {
            if SystemTime::now() < *exp { return false; }
            else { blocked.remove(&ip); }
        }
    }

    let config_guard = CONFIG.read().unwrap();
    let config = match *config_guard { Some(ref c) => c, None => return true };
    if !config.security_enabled { return true; }

    let mut reputation = REPUTATION_MAP.lock().unwrap();
    
    // Get or create reputation entry for this IP
    let entry = reputation.entry(ip.clone()).or_insert(IpReputation {
        score: 0.0, 
        trust_score: 100.0, 
        last_seen: get_now_secs(), 
        fingerprint: fingerprint.clone()
    });

    // Update basic tracking
    entry.last_seen = get_now_secs();
    entry.fingerprint = fingerprint.clone();
    
    let current_fingerprint = fingerprint.clone();
    
    // Detect honeypot hits (deception paths)
    let is_honeypot = config.honeypots.contains(&path);
    if is_honeypot {
        entry.score += HONEYPOT_PENALTY_SCORE;
        entry.trust_score -= HONEYPOT_PENALTY_TRUST;
        log_event(&ip, &format!("Honeypot detectado en ruta: {}", path));
    }

    // Check for suspicious fingerprint reuse across IPs
    let suspicious_fp = reputation.iter().any(|(other_ip, other_entry)| {
        other_ip != &ip && other_entry.fingerprint == current_fingerprint && other_entry.score > 30.0
    });

    if suspicious_fp {
        if let Some(e) = reputation.get_mut(&ip) {
            e.score += SUSPICIOUS_FP_SCORE;
            e.trust_score -= SUSPICIOUS_FP_TRUST;
        }
    }

    // Force ban if trust falls below threshold
    let final_trust = reputation.get(&ip).map(|e| e.trust_score).unwrap_or(100.0);
    if final_trust <= MIN_TRUST_SCORE_FOR_BLOCK {
        log_event(&ip, &format!("IP bloqueada por baja confianza (TrustScore: {})", final_trust));
        let mut blocked = BLOCKED_IPS.lock().unwrap();
        blocked.insert(ip, SystemTime::now() + Duration::from_secs(BAN_DURATION_SECS));
        return false;
    }

    true
}

/// Record a request event for this IP
/// Maintains: CMS frequency counter + rhythm inter-arrival time history (last 15 timestamps)
/// Used by predictThreat for botnet detection via request timing analysis
#[napi(js_name = "recordEvent")]
pub fn record_event(ip: String, _fingerprint: String) {
    let mut ip_hasher = DefaultHasher::new();
    ip.hash(&mut ip_hasher);
    let ip_hash = ip_hasher.finish();
    if let Ok(mut cms) = CMS_SKETCH.lock() { cms.insert(&ip_hash); }
    if let Ok(mut tracker) = RHYTHM_TRACKER.lock() {
        let times = tracker.entry(ip).or_insert_with(|| VecDeque::with_capacity(15));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        if times.len() >= 15 { times.pop_front(); }
        times.push_back(now);
    }
}

/// Composite threat scoring combining 3 detection methods:
///   1. Request frequency (CMS): HIGH_FREQ_THRESHOLD → +0.4, MID_FREQ_THRESHOLD → +0.2
///   2. Bloom filter (known attack fingerprint): +0.5
///   3. Rhythmic analysis (botnet timing): CV < RHYTHM_CV_THRESHOLD → +0.8
///
/// Returns normalized score: 0.0 (safe) to 1.0 (definitive threat)
/// Uses Exponential Moving Average (alpha=EMA_ALPHA) for robust statistical analysis
#[napi(js_name = "predictThreat")]
pub fn predict_threat_level(ip: String, fingerprint: String) -> f64 {
    let mut score: f64 = 0.0;
    let mut s = DefaultHasher::new();
    fingerprint.hash(&mut s);
    let fp_hash = s.finish();

    // Method 1: Frequency analysis via Count-Min Sketch
    let freq = {
        let mut ip_hasher = DefaultHasher::new();
        ip.hash(&mut ip_hasher);
        if let Ok(cms) = CMS_SKETCH.lock() { cms.count(&ip_hasher.finish()) } else { 0 }
    };
    if freq > HIGH_FREQ_THRESHOLD { score += 0.4; } else if freq > MID_FREQ_THRESHOLD { score += 0.2; }

    // Method 2: Bloom filter attack signature lookup
    if let Ok(bloom) = ATTACK_BLOOM.lock() {
        if bloom.contains(&fp_hash) { score += BLOOM_ATTACK_SCORE; }
    }

    // Method 3: Rhythmic analysis (botnet detection)
    if let Ok(tracker) = RHYTHM_TRACKER.lock() {
        if let Some(times) = tracker.get(&ip) {
            if times.len() >= 10 {
                let mut deltas = Vec::new();
                for i in 1..times.len() { deltas.push((times[i] - times[i-1]) as f64); }
                
                // Exponential Moving Average for variance calculation
                let mut ema_mean = deltas[0];
                let mut ema_m2 = 0.0;
                for d in &deltas {
                    let delta = d - ema_mean;
                    ema_mean += EMA_ALPHA * delta;
                    ema_m2 = (1.0 - EMA_ALPHA) * (ema_m2 + EMA_ALPHA * delta * delta);
                }
                
                // Coefficient of Variation: σ/μ (lower = more mechanical/bot-like)
                let std_dev = ema_m2.sqrt();
                if std_dev / (ema_mean + 1.0) < RHYTHM_CV_THRESHOLD { score += 0.8; }
            }
        }
    }
    
    score.min(1.0)
}

/// Get real-time security statistics for monitoring and dashboards
/// Returns counts: active_bans, tracked_ips, reputation_records
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
