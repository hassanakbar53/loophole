<?php
// Fixture: vulnerable PHP (intentionally insecure — scanner must flag)
$api_key = "sk-live-9f2k4m7q8w3e5r6t7y2u9i4o6p1"; // SEC001

$id = $_GET['id']; // tainted
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id); // SQLI004

echo "Hello, " . $_GET['name']; // XSS004
?>
<div><?= $_COOKIE['theme'] ?></div> <!-- XSS004 short echo -->
<?php
$cmd = $_POST['cmd']; // tainted
system($cmd); // CMD004 critical (tainted)

$expr = $_GET['expr'];
eval($expr); // EVAL001 critical

$pw = $_POST['password'];
$hash = md5($_POST['password']); // CRY001

$url = $_POST['webhook']; // tainted
$ch = curl_init($url); // SSRF001 (tainted)
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // TLS001
curl_exec($ch);

$data = file_get_contents($_GET['page']); // PATH001 (tainted)
include $_GET['tpl']; // PATH001 (tainted, LFI)

// --- 2026 expansion: new-rule coverage ---
$obj = unserialize($_GET['data']); // DESER001 (direct superglobal)

$prefs = $_COOKIE['prefs']; // tainted
$obj2 = unserialize($prefs); // DESER001 (tainted var, 2-hop)

$stored = $cache->get('session'); // origin unknown to the scanner
$obj3 = unserialize($stored); // DESER001 (dynamic data, medium)

$obj4 = unserialize(file_get_contents('php://input')); // DESER001 (php://input)

$copy = $prefs; // tainted copy
$obj5 = unserialize($copy); // DESER001 (tainted var, copied)

$obj6 = unserialize(
    $_GET['multi']
); // DESER001 (multiline tainted, high)

$zip = new ZipArchive;
$zip->open('up.zip');
$zip->extractTo('/var/www/html'); // ZIP001

move_uploaded_file($_FILES['doc']['tmp_name'],
    '/uploads/' . $_FILES['doc']['name']); // UPL001 (no validation)

header('Location: ' . $_GET['next']); // REDIR001

$xml = simplexml_load_string($_POST['xml']); // XXE001

curl_setopt($ch, CURLOPT_SSLVERSION, 'TLSv1.0'); // TLS002

$password = $_POST['password'];
error_log("login attempt: " . $password); // LOG001

$res = ldap_search($ldap, 'dc=example,dc=com', '(uid=' . $_GET['u'] . ')'); // LDAP001

$cipher = 'aes-256-ecb'; // CRY005
$enc = openssl_encrypt($data, 'aes-256-ecb', $key); // CRY005

$ok = preg_match('/(a+)+$/', $input); // REDOS001

$up = $_FILES['x']['name']; // tainted ($_FILES)
include($up); // PATH001 ($_FILES taint)

$raw = file_get_contents('php://input'); // tainted (php://input)
eval($raw); // EVAL001 (php://input taint)

$token = mt_rand(0, 999999); // RAND004 (weak randomness for token)

