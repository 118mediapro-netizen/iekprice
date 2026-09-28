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
  // Base d'annonces comparables (relevées sur leboncoin, La Centrale, AutoScout24…)
  $db->exec('CREATE TABLE IF NOT EXISTS comparables(id INTEGER PRIMARY KEY, source TEXT, marque TEXT, modele TEXT, finition TEXT, annee INTEGER, km INTEGER, carburant TEXT, boite TEXT, prix INTEGER, pays TEXT, ville TEXT, url TEXT, added_by INTEGER, at TEXT)');
  $db->exec('CREATE INDEX IF NOT EXISTS c_mm ON comparables(marque, modele)');

  $a = $_GET['a'] ?? '';
  $d = json_decode(file_get_contents('php://input'), true) ?: [];
  $q = function ($sql, $p = []) use ($db) { $s = $db->prepare($sql); $s->execute($p); return $s; };
  $user = function ($id) use ($q) { $r = $q('SELECT name,email,role,status FROM users WHERE id=?', [$id])->fetch(PDO::FETCH_ASSOC); return $r ?: null; };
  $promote = function ($id, $email) use ($q, $ADMIN_EMAILS) {
    if (in_array($email, array_map('strtolower', $ADMIN_EMAILS), true)) $q("UPDATE users SET role='admin' WHERE id=?", [$id]);
  };
  // Texte normalisé pour comparer les annonces : minuscules, sans accents, espaces simples
  $norm = function ($x) {
    $x = mb_strtolower(trim((string)$x));
    $x = strtr($x, ['à'=>'a','â'=>'a','ä'=>'a','á'=>'a','ç'=>'c','é'=>'e','è'=>'e','ê'=>'e','ë'=>'e','í'=>'i','î'=>'i','ï'=>'i','ñ'=>'n','ó'=>'o','ô'=>'o','ö'=>'o','ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u']);
    return preg_replace('/\s+/', ' ', $x);
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

  // ---- Estimation : annonces comparables (public, sans compte) ----
  if ($a === 'comps') {
    $n = $norm;
    $marque = $n($d['marque'] ?? ''); $modele = $n($d['modele'] ?? '');
    $annee = (int)($d['annee'] ?? 0); $km = (int)($d['km'] ?? 0);
    $carb = $n($d['carburant'] ?? ''); $bv = $n($d['boite'] ?? '');
    if ($marque === '' || $modele === '' || $annee < 1950) out(['items' => []]);
    $win = max(30000, (int)round($km * 0.35));
    $find = function ($dy, $withBv) use ($q, $marque, $modele, $annee, $km, $win, $carb, $bv) {
      $sql = "SELECT source,annee,km,prix,pays,ville,url,at FROM comparables WHERE marque=? AND (modele LIKE '%'||?||'%' OR ? LIKE '%'||modele||'%') AND annee BETWEEN ? AND ? AND ABS(km-?)<=?";
      $p = [$marque, $modele, $modele, $annee - $dy, $annee + $dy, $km, $win];
      if ($carb !== '') { $sql .= ' AND carburant=?'; $p[] = $carb; }
      if ($withBv && $bv !== '') { $sql .= ' AND boite=?'; $p[] = $bv; }
      return $q($sql . ' ORDER BY prix LIMIT 500', $p)->fetchAll(PDO::FETCH_ASSOC);
    };
    $rows = $find(1, true); $relaxed = false;
    if (count($rows) < 5) { $rows = $find(2, false); $relaxed = true; }
    // Source automatique future (API d'un fournisseur de données) : à ajouter ici, côté serveur uniquement.
    foreach ($rows as &$r) { $r['annee'] = (int)$r['annee']; $r['km'] = (int)$r['km']; $r['prix'] = (int)$r['prix']; }
    out(['items' => $rows, 'relaxed' => $relaxed]);
  }
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
        'comps' => $one('SELECT COUNT(*) FROM comparables'),
      ]]);
    }
    if ($a === 'admin_users') {
      $l = '%' . trim($d['q'] ?? '') . '%';
      $rows = $q('SELECT u.id,u.name,u.email,u.role,u.status,u.created,u.last_login,(SELECT COUNT(*) FROM history h WHERE h.user_id=u.id) AS n FROM users u WHERE u.email LIKE ? OR u.name LIKE ? ORDER BY u.id DESC LIMIT 500', [$l, $l])->fetchAll(PDO::FETCH_ASSOC);
      foreach ($rows as &$r) { $r['id'] = (int)$r['id']; $r['n'] = (int)$r['n']; }
      out(['users' => $rows]);
    }
    // ---- Base de comparables (ajout manuel, import CSV, liste, suppression) ----
    $clean = function ($r) use ($norm) {
      $n = function ($x) use ($norm) { return mb_substr($norm($x), 0, 80); };
      $src = $n($r['source'] ?? '');
      $srcs = ['leboncoin' => 'leboncoin', 'la centrale' => 'La Centrale', 'lacentrale' => 'La Centrale', 'autoscout24' => 'AutoScout24', 'autoscout' => 'AutoScout24', 'autre' => 'Autre'];
      $num = function ($x) { return (int)preg_replace('/\D/', '', (string)$x); };
      $row = ['source' => $srcs[$src] ?? null, 'marque' => $n($r['marque'] ?? ''), 'modele' => $n($r['modele'] ?? ''), 'finition' => $n($r['finition'] ?? ''),
        'annee' => $num($r['annee'] ?? 0), 'km' => $num($r['km'] ?? 0), 'carburant' => $n($r['carburant'] ?? ''), 'boite' => $n($r['boite'] ?? ''),
        'prix' => $num($r['prix'] ?? 0), 'pays' => mb_substr(trim((string)($r['pays'] ?? '')), 0, 40) ?: 'France', 'ville' => mb_substr(trim((string)($r['ville'] ?? '')), 0, 60),
        'url' => trim((string)($r['url'] ?? ''))];
      if ($row['url'] !== '' && !preg_match('#^https?://#i', $row['url'])) $row['url'] = '';
      $row['url'] = mb_substr($row['url'], 0, 500);
      $ok = $row['source'] && $row['marque'] !== '' && $row['modele'] !== '' && $row['annee'] >= 1950 && $row['annee'] <= (int)gmdate('Y') + 1
        && $row['km'] >= 0 && $row['km'] <= 1500000 && $row['prix'] >= 300 && $row['prix'] <= 2000000;
      return $ok ? $row : null;
    };
    $ins = function ($row) use ($q, $uid) {
      $q('INSERT INTO comparables(source,marque,modele,finition,annee,km,carburant,boite,prix,pays,ville,url,added_by,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        [$row['source'], $row['marque'], $row['modele'], $row['finition'], $row['annee'], $row['km'], $row['carburant'], $row['boite'], $row['prix'], $row['pays'], $row['ville'], $row['url'], $uid, gmdate('c')]);
    };
    if ($a === 'admin_comp_add') { $row = $clean($d); if (!$row) out(['error' => 'e_comp']); $ins($row); out(['ok' => 1]); }
    if ($a === 'admin_comp_import') {
      $list = is_array($d['rows'] ?? null) ? array_slice($d['rows'], 0, 2000) : [];
      $added = 0; $db->beginTransaction();
      foreach ($list as $r) { $row = is_array($r) ? $clean($r) : null; if ($row) { $ins($row); $added++; } }
      $db->commit();
      out(['added' => $added, 'skipped' => count($list) - $added]);
    }
    if ($a === 'admin_comp_list') {
      $l = '%' . mb_strtolower(trim($d['q'] ?? '')) . '%';
      $rows = $q("SELECT id,source,marque,modele,finition,annee,km,carburant,boite,prix,pays,ville,url,at FROM comparables WHERE marque||' '||modele LIKE ? ORDER BY id DESC LIMIT 300", [$l])->fetchAll(PDO::FETCH_ASSOC);
      $by = $q('SELECT source, COUNT(*) AS n FROM comparables GROUP BY source')->fetchAll(PDO::FETCH_KEY_PAIR);
      out(['items' => $rows, 'by' => $by]);
    }
    if ($a === 'admin_comp_del') { $q('DELETE FROM comparables WHERE id=?', [(int)($d['id'] ?? 0)]); out(['ok' => 1]); }
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
