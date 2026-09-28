<?php
// IEPRICE — comptes, historique et administration (PHP + SQLite). À déposer à côté de index.html.
// >>> E-mail(s) administrateur : le compte créé avec cet e-mail devient administrateur.
$ADMIN_EMAILS = ['118media.pro@gmail.com'];

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
function out($x, $code = 200) { http_response_code($code); echo json_encode($x, JSON_UNESCAPED_UNICODE); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'iekars') out(['error' => 'bad'], 400);
try {
  $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
  session_set_cookie_params(['lifetime' => 2592000, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Lax']);
  session_start();
  $dir = __DIR__ . '/data';
  if (!is_dir($dir)) {
    mkdir($dir, 0750, true);
    file_put_contents($dir . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
  }
  $db = new PDO('sqlite:' . $dir . '/iekars.sqlite');
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->exec('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, hash TEXT, created TEXT)');
  $db->exec('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, user_id INTEGER, t TEXT, title TEXT, payload TEXT, at TEXT)');
  $db->exec('CREATE INDEX IF NOT EXISTS h_user ON history(user_id)');
  $cols = array_column($db->query('PRAGMA table_info(users)')->fetchAll(PDO::FETCH_ASSOC), 'name');
  foreach (['role' => "TEXT DEFAULT 'user'", 'status' => "TEXT DEFAULT 'active'", 'last_login' => 'TEXT'] as $c => $def)
    if (!in_array($c, $cols)) $db->exec("ALTER TABLE users ADD COLUMN $c $def");

  $a = $_GET['a'] ?? '';
  $d = json_decode(file_get_contents('php://input'), true) ?: [];
  $q = function ($sql, $p = []) use ($db) { $s = $db->prepare($sql); $s->execute($p); return $s; };
  $user = function ($id) use ($q) { $r = $q('SELECT name,email,role,status FROM users WHERE id=?', [$id])->fetch(PDO::FETCH_ASSOC); return $r ?: null; };
  $promote = function ($id, $email) use ($q, $ADMIN_EMAILS) {
    if (in_array($email, array_map('strtolower', $ADMIN_EMAILS), true)) $q("UPDATE users SET role='admin' WHERE id=?", [$id]);
  };
  $pub = function ($u) { return $u ? ['name' => $u['name'], 'email' => $u['email'], 'role' => $u['role'] ?: 'user'] : null; };

  $uid = $_SESSION['uid'] ?? null;
  $me = $uid ? $user($uid) : null;
  if ($me && $me['status'] === 'suspended') { $_SESSION = []; $uid = null; $me = null; }

  if ($a === 'register') {
    $email = strtolower(trim($d['email'] ?? ''));
    $pw = (string)($d['password'] ?? '');
    $name = mb_substr(trim($d['name'] ?? ''), 0, 60) ?: explode('@', $email)[0];
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) out(['error' => 'e_mail']);
    if (mb_strlen($pw) < 8) out(['error' => 'e_pw']);
    if ($q('SELECT 1 FROM users WHERE email=?', [$email])->fetch()) out(['error' => 'e_dup']);
    $q("INSERT INTO users(email,name,hash,created,role,status,last_login) VALUES(?,?,?,?,'user','active',?)", [$email, $name, password_hash($pw, PASSWORD_DEFAULT), gmdate('c'), gmdate('c')]);
    $id = (int)$db->lastInsertId();
    $promote($id, $email);
    session_regenerate_id(true);
    $_SESSION['uid'] = $id;
    out(['user' => $pub($user($id))]);
  }
  if ($a === 'login') {
    $email = strtolower(trim($d['email'] ?? ''));
    $r = $q('SELECT id,hash,status FROM users WHERE email=?', [$email])->fetch(PDO::FETCH_ASSOC);
    if (!$r || !password_verify((string)($d['password'] ?? ''), $r['hash'])) { usleep(600000); out(['error' => 'e_bad']); }
    if ($r['status'] === 'suspended') out(['error' => 'e_susp']);
    $promote($r['id'], $email);
    $q('UPDATE users SET last_login=? WHERE id=?', [gmdate('c'), $r['id']]);
    session_regenerate_id(true);
    $_SESSION['uid'] = (int)$r['id'];
    out(['user' => $pub($user($r['id']))]);
  }
  if ($a === 'logout') { $_SESSION = []; session_destroy(); out(['ok' => 1]); }
  if ($a === 'me') out(['user' => $pub($me)]);
  if (!$uid) out(['error' => 'e_auth'], 401);

  // ---- Administration (réservée aux comptes admin) ----
  if (strpos($a, 'admin_') === 0) {
    if ($me['role'] !== 'admin') out(['error' => 'e_auth'], 403);
    if ($a === 'admin_stats') {
      $one = function ($sql, $p = []) use ($q) { return (int)$q($sql, $p)->fetchColumn(); };
      out(['stats' => [
        'users' => $one('SELECT COUNT(*) FROM users'),
        'suspended' => $one("SELECT COUNT(*) FROM users WHERE status='suspended'"),
        'searches' => $one('SELECT COUNT(*) FROM history'),
        'new7' => $one('SELECT COUNT(*) FROM users WHERE created>=?', [gmdate('c', time() - 7 * 86400)]),
      ]]);
    }
    if ($a === 'admin_users') {
      $l = '%' . trim($d['q'] ?? '') . '%';
      $rows = $q('SELECT u.id,u.name,u.email,u.role,u.status,u.created,u.last_login,(SELECT COUNT(*) FROM history h WHERE h.user_id=u.id) AS n FROM users u WHERE u.email LIKE ? OR u.name LIKE ? ORDER BY u.id DESC LIMIT 500', [$l, $l])->fetchAll(PDO::FETCH_ASSOC);
      foreach ($rows as &$r) { $r['id'] = (int)$r['id']; $r['n'] = (int)$r['n']; }
      out(['users' => $rows]);
    }
    $t = (int)($d['id'] ?? 0);
    if (!$user($t)) out(['error' => 'srv']);
    if ($t === (int)$uid) out(['error' => 'e_self']);
    if ($a === 'admin_status') $q('UPDATE users SET status=? WHERE id=?', [($d['status'] ?? '') === 'suspended' ? 'suspended' : 'active', $t]);
    elseif ($a === 'admin_role') $q('UPDATE users SET role=? WHERE id=?', [($d['role'] ?? '') === 'admin' ? 'admin' : 'user', $t]);
    elseif ($a === 'admin_delete') { $q('DELETE FROM history WHERE user_id=?', [$t]); $q('DELETE FROM users WHERE id=?', [$t]); }
    elseif ($a === 'admin_pw') { $pw = bin2hex(random_bytes(5)); $q('UPDATE users SET hash=? WHERE id=?', [password_hash($pw, PASSWORD_DEFAULT), $t]); out(['password' => $pw]); }
    else out(['error' => 'bad'], 400);
    out(['ok' => 1]);
  }

  // ---- Historique de l'utilisateur ----
  if ($a === 'hist') {
    $rows = $q('SELECT id,t,title,payload,at FROM history WHERE user_id=? ORDER BY id DESC LIMIT 100', [$uid])->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$r) { $r['id'] = (int)$r['id']; $r['payload'] = json_decode($r['payload'], true); }
    out(['items' => $rows]);
  }
  if ($a === 'add') {
    $t = in_array($d['t'] ?? '', ['estimate', 'analysis'], true) ? $d['t'] : null;
    $payload = json_encode($d['payload'] ?? new stdClass(), JSON_UNESCAPED_UNICODE);
    if (!$t || strlen($payload) > 20000) out(['error' => 'bad'], 400);
    $q('INSERT INTO history(user_id,t,title,payload,at) VALUES(?,?,?,?,?)', [$uid, $t, mb_substr((string)($d['title'] ?? ''), 0, 200), $payload, gmdate('c')]);
    out(['ok' => 1]);
  }
  if ($a === 'del')   { $q('DELETE FROM history WHERE id=? AND user_id=?', [(int)($d['id'] ?? 0), $uid]); out(['ok' => 1]); }
  if ($a === 'clear') { $q('DELETE FROM history WHERE user_id=?', [$uid]); out(['ok' => 1]); }
  if ($a === 'delacc') {
    $q('DELETE FROM history WHERE user_id=?', [$uid]); $q('DELETE FROM users WHERE id=?', [$uid]);
    $_SESSION = []; session_destroy(); out(['ok' => 1]);
  }
  out(['error' => 'bad'], 400);
} catch (Throwable $e) { out(['error' => 'srv'], 500); }
