<?php
/**
 * send.php - TCP/IP GPS Packet Sender & Vehicle Database Backend
 * Database: MySQL (with JSON file fallback if MySQL not available)
 *
 * GET  send.php?action=token          -> {csrf, default_ip, default_port}
 * GET  send.php?action=vehicles       -> {ok, vehicles:[...]}
 * GET  send.php?action=logs           -> {ok, logs:[...]}
 * GET  send.php?action=logs&imei=X    -> {ok, logs:[...]} (filtered)
 * GET  send.php?action=maintenance    -> {ok, maintenance: bool}
 * POST send.php?action=maintenance    -> toggle maintenance mode
 * POST send.php?action=vehicle_add
 * POST send.php?action=vehicle_edit
 * POST send.php?action=vehicle_delete
 * POST send.php?action=imei_auto_add  -> auto-add IMEI if not exists
 * POST send.php                       -> send TCP packet
 */

declare(strict_types=1);

// ───────────────────────── CORS & HEADERS ─────────────────────────
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT');
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, Authorization, X-Requested-With');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ───────────────────────── CONFIG ─────────────────────────
const DEFAULT_IP        = '154.210.168.75';
const DEFAULT_PORT      = 4002;
const DEFAULT_LAT       = 24.57649030;
const DEFAULT_LON       = 84.95734820;

// Allow connecting to any target IP or Hostname
const ALLOW_ANY_TARGET  = true;
const ALLOWED_TARGETS   = [];

const MAX_PACKET_BYTES  = 4096;
const MAX_TIMEOUT_SEC   = 15;
const READ_TIMEOUT_SEC  = 3;
const HISTORY_FILE      = __DIR__ . '/logs/history.json';
const HISTORY_KEEP      = 500;

// ── Maintenance mode file ──
const MAINTENANCE_FILE  = __DIR__ . '/logs/maintenance.txt';

// ── MySQL Config (edit these to match your server) ──
const DB_HOST     = 'localhost';
const DB_PORT     = 3306;
const DB_NAME     = 'uptcp';
const DB_USER     = 'root';
const DB_PASS     = '';

// ───────────────────────── AUTH CONFIG ─────────────────────────
const AUTH_USERNAME       = 'uptcp';
const AUTH_PASSWORD       = 'uptcp';
const ADMIN_USERNAME      = 'admin';
const ADMIN_PASSWORD      = 'admin123';
const ACTIVE_SESSION_FILE = __DIR__ . '/logs/active_session.txt';

// Cross-Server Admin Hosting Sync Config
const ADMIN_SERVER_URL    = 'https://orbitgps.in/tcp/admin_server.php'; // Live Admin Server receiver URL
const ADMIN_SYNC_KEY      = 'uptcp_secret_admin_sync_key_99'; // Secret security key for server-to-server sync

function syncToAdminServer($entryData) {
    if (empty(ADMIN_SERVER_URL)) return;
    $payload = json_encode([
        'sync_key'    => ADMIN_SYNC_KEY,
        'client_host' => $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'client-server',
        'entry'       => $entryData
    ]);

    $sent = false;
    if (function_exists('curl_init')) {
        $ch = curl_init(ADMIN_SERVER_URL);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        $res = @curl_exec($ch);
        if ($res !== false) $sent = true;
        @curl_close($ch);
    }
    
    if (!$sent) {
        $opts = [
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/json\r\n",
                'content' => $payload,
                'timeout' => 5
            ],
            'ssl' => [
                'verify_peer'      => false,
                'verify_peer_name' => false
            ]
        ];
        @file_get_contents(ADMIN_SERVER_URL, false, stream_context_create($opts));
    }
}

// ───────────────────────── HELPERS ─────────────────────────
function respond($data, $status = 200)
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fail($msg, $status = 200, $extra = array())
{
    respond(array_merge([
        'ok'         => false,
        'sent_bytes' => 0,
        'reply'      => '',
        'error'      => $msg,
        'latency_ms' => 0,
        'timestamp'  => gmdate('c'),
    ], $extra), $status);
}

function is_valid_target_host($host)
{
    if (filter_var($host, FILTER_VALIDATE_IP)) return true;
    if ($host === 'localhost') return true;
    return (bool) preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $host);
}

function explain_socket_error($errno, $errstr)
{
    if (in_array($errno, [110, 10060], true)) {
        return 'Connection timed out (Server unreachable or port closed)';
    }
    if (in_array($errno, [111, 10061], true)) {
        return 'Connection refused (Target port is closed or server app is down)';
    }
    if (in_array($errno, [101, 113, 10065, 10051], true)) {
        return 'Host unreachable';
    }
    return $errstr !== '' ? $errstr : "Socket error ($errno)";
}

function append_history($entry)
{
    $dir = dirname(HISTORY_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);

    $fp = @fopen(HISTORY_FILE, 'c+');
    if (!$fp) return;
    if (flock($fp, LOCK_EX)) {
        $raw  = stream_get_contents($fp);
        $list = $raw ? json_decode($raw, true) : [];
        if (!is_array($list)) $list = [];
        $list[] = $entry;
        $list   = array_slice($list, -HISTORY_KEEP);
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($list, JSON_UNESCAPED_SLASHES));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    syncToAdminServer($entry);
}

function read_history()
{
    if (!file_exists(HISTORY_FILE)) return [];
    $raw = @file_get_contents(HISTORY_FILE);
    $data = $raw ? json_decode($raw, true) : [];
    return is_array($data) ? $data : [];
}

// ───────────────────────── MAINTENANCE MODE ─────────────────────────
function isMaintenanceMode()
{
    $dir = dirname(MAINTENANCE_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    if (file_exists(MAINTENANCE_FILE) && trim((string)@file_get_contents(MAINTENANCE_FILE)) === '1') {
        return true;
    }
    // Check central Admin Server global maintenance
    if (!empty(ADMIN_SERVER_URL)) {
        $opts = [
            'http' => ['method' => 'GET', 'timeout' => 2],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]
        ];
        $raw = @file_get_contents(ADMIN_SERVER_URL . '?action=maintenance', false, stream_context_create($opts));
        if ($raw) {
            $d = json_decode($raw, true);
            if ($d && !empty($d['maintenance'])) return true;
        }
    }
    return false;
}

function setMaintenanceMode($on)
{
    $dir = dirname(MAINTENANCE_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    if ($on) {
        file_put_contents(MAINTENANCE_FILE, '1');
    } else {
        if (file_exists(MAINTENANCE_FILE)) @unlink(MAINTENANCE_FILE);
    }
}

// ───────────────────────── DATABASE CLASS (MySQL + JSON Fallback) ─────────────────────────
class VehicleDB
{
    private $pdo = null;
    private $jsonFile;

    public function __construct()
    {
        $this->jsonFile = __DIR__ . '/vehicles.json';

        // Try MySQL first
        if (class_exists('PDO') && in_array('mysql', PDO::getAvailableDrivers(), true)) {
            try {
                $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME . ';charset=utf8mb4';
                $this->pdo = new PDO($dsn, DB_USER, DB_PASS, [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ]);
                $this->pdo->exec("CREATE TABLE IF NOT EXISTS vehicles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) DEFAULT 'uptcp',
                    vehicle_no VARCHAR(20) DEFAULT '0000',
                    imei VARCHAR(20) NOT NULL,
                    packet_count INT DEFAULT 0,
                    lat DOUBLE DEFAULT 30.0098235,
                    lon DOUBLE DEFAULT 77.5719748,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

                @$this->pdo->exec("ALTER TABLE vehicles ADD COLUMN username VARCHAR(50) DEFAULT 'uptcp'");

                $stmt = $this->pdo->query("SELECT COUNT(*) FROM vehicles");
                if ($stmt && (int)$stmt->fetchColumn() === 0) {
                    $this->seed();
                }
                return;
            } catch (Throwable $e) {
                $this->pdo = null;
            }
        }

        // JSON fallback
        if (!file_exists($this->jsonFile)) {
            $initial = [
                ['id' => 1, 'username' => 'uptcp', 'vehicle_no' => '0000', 'imei' => '869742088976045', 'packet_count' => 0, 'lat' => 30.0098235, 'lon' => 77.5719748, 'created_at' => date('Y-m-d H:i:s')],
                ['id' => 2, 'username' => 'uptcp', 'vehicle_no' => '0000', 'imei' => '866192078002423', 'packet_count' => 0, 'lat' => 24.0969703, 'lon' => 72.7455459, 'created_at' => date('Y-m-d H:i:s')]
            ];
            file_put_contents($this->jsonFile, json_encode($initial, JSON_PRETTY_PRINT));
        }
    }

    public function isMySQL() { return $this->pdo !== null; }

    private function seed()
    {
        if ($this->pdo) {
            $stmt = $this->pdo->prepare("INSERT IGNORE INTO vehicles (username, vehicle_no, imei, packet_count, lat, lon) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute(['uptcp', '0000', '869742088976045', 0, 30.0098235, 77.5719748]);
            $stmt->execute(['uptcp', '0000', '866192078002423', 0, 24.0969703, 72.7455459]);
        }
    }

    private function readJson()
    {
        $raw = @file_get_contents($this->jsonFile);
        $data = $raw ? json_decode($raw, true) : [];
        return is_array($data) ? $data : [];
    }

    private function writeJson($data)
    {
        file_put_contents($this->jsonFile, json_encode(array_values($data), JSON_PRETTY_PRINT));
    }

    public function getAll($username = '')
    {
        if ($this->pdo) {
            if ($username !== '') {
                $stmt = $this->pdo->prepare("SELECT * FROM vehicles WHERE username = ? ORDER BY id ASC");
                $stmt->execute([$username]);
                $rows = $stmt->fetchAll();
            } else {
                $stmt = $this->pdo->query("SELECT * FROM vehicles ORDER BY id ASC");
                $rows = $stmt->fetchAll();
            }
            $serial = 1;
            foreach ($rows as &$row) {
                $row['serial_no']    = $serial++;
                $row['vehicle_no']   = '0000';
                $row['packet_count'] = (int)$row['packet_count'];
                $row['lat']          = (float)$row['lat'];
                $row['lon']          = (float)$row['lon'];
            }
            return $rows;
        }

        $data = $this->readJson();
        if ($username !== '') {
            $data = array_values(array_filter($data, function($item) use ($username) {
                return ($item['username'] ?? 'uptcp') === $username;
            }));
        }
        $serial = 1;
        foreach ($data as &$row) {
            $row['serial_no']    = $serial++;
            $row['vehicle_no']   = '0000';
            $row['packet_count'] = (int)($row['packet_count'] ?? 0);
        }
        return $data;
    }

    public function findByImei($imei, $username = '')
    {
        if ($this->pdo) {
            if ($username !== '') {
                $stmt = $this->pdo->prepare("SELECT * FROM vehicles WHERE imei = ? AND username = ?");
                $stmt->execute([$imei, $username]);
            } else {
                $stmt = $this->pdo->prepare("SELECT * FROM vehicles WHERE imei = ?");
                $stmt->execute([$imei]);
            }
            $row = $stmt->fetch();
            return $row ?: null;
        }
        $data = $this->readJson();
        foreach ($data as $row) {
            if ($row['imei'] === $imei && ($username === '' || ($row['username'] ?? 'uptcp') === $username)) {
                return $row;
            }
        }
        return null;
    }

    public function add($vehicleNo, $imei, $lat = 30.0098235, $lon = 77.5719748, $username = 'uptcp')
    {
        $imei = trim($imei);

        if ($this->pdo) {
            $stmt = $this->pdo->prepare("INSERT INTO vehicles (username, vehicle_no, imei, packet_count, lat, lon) VALUES (?, '0000', ?, 0, ?, ?)");
            $stmt->execute([$username, $imei, $lat, $lon]);
            $id = (int)$this->pdo->lastInsertId();
            return ['id' => $id, 'username' => $username, 'vehicle_no' => '0000', 'imei' => $imei, 'packet_count' => 0, 'lat' => $lat, 'lon' => $lon];
        }

        $list = $this->readJson();
        foreach ($list as $item) {
            if ($item['imei'] === $imei && ($item['username'] ?? 'uptcp') === $username) {
                throw new Exception("IMEI already exists in your vehicle database");
            }
        }
        $maxId = 0;
        foreach ($list as $item) if ((int)$item['id'] > $maxId) $maxId = (int)$item['id'];
        $newItem = [
            'id' => $maxId + 1,
            'username' => $username,
            'vehicle_no' => '0000',
            'imei' => $imei,
            'packet_count' => 0,
            'lat' => $lat,
            'lon' => $lon,
            'created_at' => date('Y-m-d H:i:s')
        ];
        $list[] = $newItem;
        $this->writeJson($list);
        return $newItem;
    }

    public function update($id, $vehicleNo, $imei, $lat = null, $lon = null, $username = '')
    {
        $imei = trim($imei);

        if ($this->pdo) {
            $sql = "UPDATE vehicles SET vehicle_no='0000', imei=?";
            $params = [$imei];
            if ($lat !== null && $lon !== null) {
                $sql .= ", lat=?, lon=?";
                $params[] = $lat;
                $params[] = $lon;
            }
            $sql .= " WHERE id=?";
            $params[] = $id;
            if ($username !== '') {
                $sql .= " AND username=?";
                $params[] = $username;
            }
            $stmt = $this->pdo->prepare($sql);
            return $stmt->execute($params);
        }

        $list = $this->readJson();
        $updated = false;
        foreach ($list as &$item) {
            if ((int)$item['id'] === $id && ($username === '' || ($item['username'] ?? 'uptcp') === $username)) {
                $item['vehicle_no'] = '0000';
                $item['imei'] = $imei;
                if ($lat !== null) $item['lat'] = $lat;
                if ($lon !== null) $item['lon'] = $lon;
                $updated = true;
                break;
            }
        }
        if ($updated) $this->writeJson($list);
        return $updated;
    }

    public function delete($id, $username = '')
    {
        if ($this->pdo) {
            if ($username !== '') {
                $stmt = $this->pdo->prepare("DELETE FROM vehicles WHERE id=? AND username=?");
                return $stmt->execute([$id, $username]);
            } else {
                $stmt = $this->pdo->prepare("DELETE FROM vehicles WHERE id=?");
                return $stmt->execute([$id]);
            }
        }

        $list = $this->readJson();
        $newList = array_values(array_filter($list, function($item) use ($id, $username) {
            if ((int)$item['id'] === $id) {
                if ($username === '' || ($item['username'] ?? 'uptcp') === $username) {
                    return false;
                }
            }
            return true;
        }));
        $this->writeJson($newList);
        return true;
    }

    public function incrementCount($imei, $id = 0, $username = '')
    {
        if ($this->pdo) {
            if ($id > 0) {
                $this->pdo->prepare("UPDATE vehicles SET packet_count = packet_count + 1 WHERE id=?")->execute([$id]);
                $stmt = $this->pdo->prepare("SELECT packet_count FROM vehicles WHERE id=?");
                $stmt->execute([$id]);
            } else {
                if ($username !== '') {
                    $this->pdo->prepare("UPDATE vehicles SET packet_count = packet_count + 1 WHERE imei=? AND username=?")->execute([$imei, $username]);
                    $stmt = $this->pdo->prepare("SELECT packet_count FROM vehicles WHERE imei=? AND username=?");
                    $stmt->execute([$imei, $username]);
                } else {
                    $this->pdo->prepare("UPDATE vehicles SET packet_count = packet_count + 1 WHERE imei=?")->execute([$imei]);
                    $stmt = $this->pdo->prepare("SELECT packet_count FROM vehicles WHERE imei=?");
                    $stmt->execute([$imei]);
                }
            }
            return (int)$stmt->fetchColumn();
        }

        $list = $this->readJson();
        $newCount = 0;
        foreach ($list as &$item) {
            if (($id > 0 && (int)$item['id'] === $id) || ($imei !== '' && $item['imei'] === $imei && ($username === '' || ($item['username'] ?? 'uptcp') === $username))) {
                $item['packet_count'] = ((int)($item['packet_count'] ?? 0)) + 1;
                $newCount = $item['packet_count'];
                break;
            }
        }
        $this->writeJson($list);
        return $newCount;
    }
}

$db = new VehicleDB();

// ───────────────────────── SESSION / CSRF ─────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    if (defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 70300) {
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
    } else {
        session_set_cookie_params(0, '/; samesite=Lax', '', false, true);
    }
    session_start();
}
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = $_GET['action'] ?? '';

// ───────────────────────── AUTH HELPERS ─────────────────────────
function getActiveSessionId() {
    $dir = dirname(ACTIVE_SESSION_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    return file_exists(ACTIVE_SESSION_FILE) ? trim((string)@file_get_contents(ACTIVE_SESSION_FILE)) : '';
}

function setActiveSessionId($sid) {
    $dir = dirname(ACTIVE_SESSION_FILE);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    file_put_contents(ACTIVE_SESSION_FILE, $sid);
}

function clearActiveSessionId() {
    if (file_exists(ACTIVE_SESSION_FILE)) @unlink(ACTIVE_SESSION_FILE);
}

function isAuthenticated() {
    if (empty($_SESSION['logged_in'])) return false;
    $activeId = getActiveSessionId();
    return $activeId === session_id();
}

// ───────────────────────── PUBLIC: MAINTENANCE CHECK ─────────────────────────
// Allow public check of maintenance mode (before auth guard)
if ($action === 'maintenance' && $method === 'GET') {
    respond(['ok' => true, 'maintenance' => isMaintenanceMode()]);
}

// ───────────────────────── AUTH ROUTES ─────────────────────────
if ($action === 'login' && $method === 'POST') {
    $rawInput = (string) file_get_contents('php://input');
    $body = json_decode($rawInput, true) ?? [];
    $user = trim((string)($body['username'] ?? ''));
    $pass = trim((string)($body['password'] ?? ''));

    if ($user === ADMIN_USERNAME && $pass === ADMIN_PASSWORD) {
        setActiveSessionId(session_id());
        $_SESSION['logged_in'] = true;
        $_SESSION['username']  = $user;
        $_SESSION['is_admin']  = true;
        respond(['ok' => true, 'csrf' => $_SESSION['csrf'], 'is_admin' => true, 'username' => $user]);
    } elseif ($user === AUTH_USERNAME && $pass === AUTH_PASSWORD) {
        setActiveSessionId(session_id());
        $_SESSION['logged_in'] = true;
        $_SESSION['username']  = $user;
        $_SESSION['is_admin']  = false;
        respond(['ok' => true, 'csrf' => $_SESSION['csrf'], 'is_admin' => false, 'username' => $user]);
    } else {
        // Fallback: Check central Admin Server for managed users
        if (!empty(ADMIN_SERVER_URL)) {
            $opts = [
                'http' => [
                    'method'  => 'POST',
                    'header'  => "Content-Type: application/json\r\n",
                    'content' => json_encode(['username' => $user, 'password' => $pass]),
                    'timeout' => 4
                ],
                'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
            ];
            $raw = @file_get_contents(ADMIN_SERVER_URL . '?action=verify_user', false, stream_context_create($opts));
            if ($raw) {
                $remote = json_decode($raw, true);
                if ($remote && !empty($remote['ok'])) {
                    setActiveSessionId(session_id());
                    $_SESSION['logged_in'] = true;
                    $_SESSION['username']  = $user;
                    $_SESSION['is_admin']  = !empty($remote['is_admin']);
                    respond(['ok' => true, 'csrf' => $_SESSION['csrf'], 'is_admin' => $_SESSION['is_admin'], 'username' => $user]);
                }
            }
        }
        respond(['ok' => false, 'error' => 'Invalid username or password'], 401);
    }
}

if ($action === 'logout') {
    if (getActiveSessionId() === session_id()) clearActiveSessionId();
    $_SESSION = [];
    session_destroy();
    respond(['ok' => true]);
}

if ($action === 'check_auth') {
    $authed = isAuthenticated();
    $isAdmin = $authed && !empty($_SESSION['is_admin']);
    $user = $_SESSION['username'] ?? '';
    respond(['ok' => $authed, 'is_admin' => $isAdmin, 'username' => $user]);
}

// ───────────────────────── AUTH GUARD ─────────────────────────
if (!isAuthenticated()) {
    respond(['ok' => false, 'error' => 'Unauthorized. Please log in.'], 401);
}

// ───────────────────────── GLOBAL MAINTENANCE ENFORCEMENT ─────────────────────────
if (isMaintenanceMode() && empty($_SESSION['is_admin'])) {
    if ($method === 'POST') {
        fail('System is currently under maintenance. Transmissions are paused.', 503, ['maintenance' => true]);
    }
}

// ───────────────────────── MAINTENANCE TOGGLE (POST, authenticated) ─────────────────────────
if ($action === 'maintenance' && $method === 'POST') {
    $rawInput = (string) file_get_contents('php://input');
    $body = json_decode($rawInput, true) ?? [];
    $on = !empty($body['enabled']);
    setMaintenanceMode($on);
    respond(['ok' => true, 'maintenance' => isMaintenanceMode()]);
}

// ───────────────────────── ROUTING ─────────────────────────
function currentUsername() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : 'uptcp';
}
function isUserAdmin() {
    return !empty($_SESSION['is_admin']);
}

if ($method === 'GET') {
    if ($action === 'vehicles') {
        $u = isUserAdmin() ? '' : currentUsername();
        respond(['ok' => true, 'vehicles' => $db->getAll($u), 'db_type' => $db->isMySQL() ? 'mysql' : 'json']);
    }

    if ($action === 'logs') {
        $logs = array_reverse(read_history());
        $filterImei = trim($_GET['imei'] ?? '');
        if ($filterImei !== '') {
            $logs = array_values(array_filter($logs, function($l) use ($filterImei) {
                return ($l['imei'] ?? '') === $filterImei;
            }));
        }
        respond(['ok' => true, 'logs' => $logs]);
    }

    respond([
        'csrf'         => $_SESSION['csrf'],
        'default_ip'   => DEFAULT_IP,
        'default_port' => DEFAULT_PORT,
        'db_type'      => $db->isMySQL() ? 'mysql' : 'json',
    ]);
}

// ── Clear Logs / Restore Logs ──
if ($action === 'clear_logs' || $action === 'client_clear_logs') {
    $fp = @fopen(HISTORY_FILE, 'w');
    if ($fp) {
        fwrite($fp, json_encode([]));
        fclose($fp);
    }
    // Also sync cleared state to central admin server
    if (!empty(ADMIN_SERVER_URL)) {
        $opts = [
            'http' => ['method' => 'POST', 'timeout' => 3],
            'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false]
        ];
        @file_get_contents(ADMIN_SERVER_URL . '?action=client_clear_logs', false, stream_context_create($opts));
    }
    respond(['ok' => true, 'message' => 'Client logs cleared. Master archive safely retained in Admin Vault.']);
}

if ($action === 'restore_logs') {
    $rawInput = (string) file_get_contents('php://input');
    $body = json_decode($rawInput, true) ?? [];
    $restoredLogs = $body['logs'] ?? [];
    if (is_array($restoredLogs)) {
        file_put_contents(HISTORY_FILE, json_encode($restoredLogs));
        respond(['ok' => true, 'message' => 'Logs restored', 'count' => count($restoredLogs)]);
    }
}

// Read JSON input body for POST
$rawInput = (string) file_get_contents('php://input');
$body = json_decode($rawInput, true) ?? [];

// ── Auto-add IMEI ──
if ($action === 'imei_auto_add') {
    $imei = trim((string)($body['imei'] ?? ''));
    $lat  = (float)($body['lat']  ?? DEFAULT_LAT);
    $lon  = (float)($body['lon']  ?? DEFAULT_LON);

    if ($imei === '' || !preg_match('/^\d{15}$/', $imei)) {
        respond(['ok' => false, 'added' => false, 'error' => 'Invalid IMEI']);
    }
    $u = currentUsername();
    $existing = $db->findByImei($imei, $u);
    if ($existing) {
        respond(['ok' => true, 'added' => false, 'message' => 'IMEI already exists', 'vehicles' => $db->getAll($u)]);
    }
    try {
        $db->add('0000', $imei, $lat, $lon, $u);
        respond(['ok' => true, 'added' => true, 'message' => 'IMEI added to database', 'vehicles' => $db->getAll($u)]);
    } catch (Throwable $e) {
        respond(['ok' => false, 'added' => false, 'error' => $e->getMessage()]);
    }
}

// Vehicle Database API Endpoints
if ($action === 'vehicle_add') {
    $imei = trim((string)($body['imei'] ?? ''));
    $lat  = (float)($body['lat']  ?? DEFAULT_LAT);
    $lon  = (float)($body['lon']  ?? DEFAULT_LON);

    if ($imei === '') fail('IMEI is required');
    if (!preg_match('/^\d{15}$/', $imei)) fail('IMEI must be exactly 15 digits');
    $u = currentUsername();
    try {
        $v = $db->add('0000', $imei, $lat, $lon, $u);
        respond(['ok' => true, 'vehicle' => $v, 'vehicles' => $db->getAll($u)]);
    } catch (Throwable $e) {
        fail($e->getMessage());
    }
}

if ($action === 'vehicle_edit') {
    $id   = (int)($body['id']   ?? 0);
    $imei = trim((string)($body['imei'] ?? ''));
    $lat  = isset($body['lat']) ? (float)$body['lat'] : null;
    $lon  = isset($body['lon']) ? (float)$body['lon'] : null;

    if ($id <= 0 || $imei === '') fail('Valid ID and IMEI are required');
    if (!preg_match('/^\d{15}$/', $imei)) fail('IMEI must be exactly 15 digits');
    $u = isUserAdmin() ? '' : currentUsername();
    try {
        $db->update($id, '0000', $imei, $lat, $lon, $u);
        respond(['ok' => true, 'vehicles' => $db->getAll(currentUsername())]);
    } catch (Throwable $e) {
        fail($e->getMessage());
    }
}

if ($action === 'vehicle_delete') {
    $id = (int)($body['id'] ?? 0);
    if ($id <= 0) fail('Valid vehicle ID required');
    $u = isUserAdmin() ? '' : currentUsername();
    $db->delete($id, $u);
    respond(['ok' => true, 'vehicles' => $db->getAll(currentUsername())]);
}

// ───────────────────────── TCP SEND PACKET ─────────────────────────
$ip      = trim((string)($body['ip']         ?? DEFAULT_IP));
$port    = (int)($body['port']               ?? DEFAULT_PORT);
$packet  = (string)($body['packet']          ?? '');
$crlf    = !empty($body['append_crlf']);
$wait    = !empty($body['wait_reply']);
$timeout = max(1, min(MAX_TIMEOUT_SEC, (int)($body['timeout'] ?? 5)));
$vId     = (int)($body['vehicle_id']         ?? 0);
$imei    = trim((string)($body['imei']       ?? ''));

if (!is_valid_target_host($ip)) fail('Invalid IP address or Hostname format');
if ($port < 1 || $port > 65535)  fail('Port must be between 1 and 65535');

$packet = trim($packet);
if ($packet === '')                          fail('Packet string is empty');
if (strlen($packet) > MAX_PACKET_BYTES)      fail('Packet size exceeds maximum limit of ' . MAX_PACKET_BYTES . ' bytes');

$payload = $crlf ? $packet . "\r\n" : $packet;

// Socket Transmission
$start  = microtime(true);
$errno  = 0;
$errstr = '';
$reply  = '';
$sent   = 0;
$error  = null;

try {
    $fp = @stream_socket_client("tcp://{$ip}:{$port}", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
    if (!$fp) throw new RuntimeException(explain_socket_error($errno, $errstr));

    stream_set_timeout($fp, $timeout);

    $total = strlen($payload);
    $written = 0;
    while ($written < $total) {
        $n = @fwrite($fp, substr($payload, $written));
        if ($n === false || $n === 0) {
            $meta = stream_get_meta_data($fp);
            fclose($fp);
            throw new RuntimeException(!empty($meta['timed_out']) ? 'Write operation timed out' : 'Connection closed by remote host');
        }
        $written += $n;
    }
    $sent = $written;

    if ($wait) {
        stream_set_timeout($fp, min($timeout, READ_TIMEOUT_SEC));
        $data = @fread($fp, 4096);
        if ($data !== false && $data !== '') {
            $reply = preg_match('//u', $data) ? $data : bin2hex($data);
        }
    }
    fclose($fp);
} catch (Throwable $e) {
    $error = $e->getMessage();
}

$latency = (int) round((microtime(true) - $start) * 1000);
$ok = ($error === null);

$newPacketCount = 0;
if ($ok) {
    if ($imei === '' && preg_match('/\b\d{15}\b/', $packet, $m)) $imei = $m[0];
    $newPacketCount = $db->incrementCount($imei, $vId, currentUsername());
}

append_history([
    'timestamp'  => gmdate('c'),
    'ip'         => $ip,
    'port'       => $port,
    'imei'       => $imei,
    'packet'     => $packet,
    'ok'         => $ok,
    'sent_bytes' => $sent,
    'reply'      => $reply,
    'error'      => $error,
    'latency_ms' => $latency,
]);

respond([
    'ok'           => $ok,
    'sent_bytes'   => $sent,
    'reply'        => $reply,
    'error'        => $error,
    'latency_ms'   => $latency,
    'packet_count' => $newPacketCount,
    'timestamp'    => gmdate('c'),
]);
