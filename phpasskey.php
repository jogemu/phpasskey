<?php // https://github.com/jogemu/phpasskey

$mySQLi=new mysqli('server', 'user', 'password', 'database'); // TODO
if($mySQLi->connect_error) { exit('mySQLi unable to connect'); }
$mySQLi->set_charset('utf8');

function login() {
  if(isset($_COOKIE[session_name()])) {
    session_start();
    if(isset($_SESSION['user'])) return;
  }

  if(str_starts_with($_SERVER['HTTP_ACCEPT'], 'text/html')) {
    // TODO custom login page
    // ------------------------------------------------------
    phpasskey_js();
    echo '<button onclick="login()">Login</button>';
    // ------------------------------------------------------
    close();
  }

  if($_SERVER['REQUEST_METHOD'] != 'POST') {
    isset($_COOKIE[session_name()]) or session_start();

    $_SESSION['challenge'] = base64_encode(random_bytes(64));

    header('Content-Type: application/json');
    echo json_encode(['publicKey' => [
      'challenge' => $_SESSION['challenge'],
    ]]);
  } else {
    $post = json_decode(file_get_contents('php://input')) or close(400, 'Expected JSON credential.');
    ($post->type == 'public-key') or close(422, 'Not a public key credential.');

    $msfix = fn($v) => strtr($v, '-_', '+/'); // Microsoft Hello fix
    $b64_dec = fn($v) => base64_decode($msfix($v));

    $id = base64_encode($b64_dec($post->id));
    $authenticatorData = $b64_dec($post->response->authenticatorData);
    $clientDataJSON = $b64_dec($post->response->clientDataJSON);
    $signature = $b64_dec($post->response->signature);
    
    $stmt = $GLOBALS['mySQLi']->prepare("SELECT * FROM `passkeys` WHERE `passkey`=FROM_BASE64(?)");
    $stmt->bind_param('s', $id);
    $stmt->execute() or close(500, 'db failure');
    $result = $stmt->get_result();
    ($result->num_rows == 1) or close(401, 'This passkey is not associated with an account.');
    $passkey = $result->fetch_assoc();

    (rtrim($_SESSION['challenge'], '=') == $msfix(json_decode($clientDataJSON)->challenge)) or close(406, 'The challenge does not match');

    $pub = base64_encode($passkey['pub']);
    $pub = str_replace('MIIBIjANBgkqhkiG9w0BAQsFAAOCAQ8A', 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A', $pub); // MS/Hello fix
    $pub = "\n-----BEGIN PUBLIC KEY-----\n".chunk_split($pub, 64, "\n")."-----END PUBLIC KEY-----\n";

    $challenge = $authenticatorData;
    $challenge.= hash('sha256', $clientDataJSON, true);

    openssl_verify($challenge, $signature, $pub, OPENSSL_ALGO_SHA256) or close(401, 'Invalid signature');
    !openssl_error_string() or close(406, 'Verification error');

    $_SESSION['user'] = $passkey['user'];
    unset($_SESSION['challenge']);

    echo 'OK';
  }
  close();
}

function register() {
  if(!str_starts_with($_SERVER['HTTP_ACCEPT'], 'text/html')) {
    if($_SERVER['REQUEST_METHOD'] != 'POST') {
      $challenge = base64_encode(random_bytes(64));
      $id = base64_encode(iab($_SESSION['user'])); // Assuming 4 byte integer
      ob_json(["publicKey" => [
        "challenge" => $challenge,
        "rp" => ["name" => "domain.com", "id" => "domain.com"], // TODO your domain
        "user" => ["id" => $id, "name" => "user@domain.com", "displayName" => "user@domain.com"], // TODO user name
        "pubKeyCredParams" => [["alg" => -7, "type" => "public-key"], ["alg" => -257, "type" => "public-key"]],
        "authenticatorSelection" => ["residentKey" => "required", "requireResidentKey" => true]
      ]]);
    } else {
      $post = json_decode(file_get_contents('php://input')) or close(400, 'Expected JSON credential.');
      ($post->type == 'public-key') or close(422, 'Not a public key credential.');
  
      $msfix = fn($v) => strtr($v, '-_', '+/'); // Microsoft Hello fix
      $b64_dec = fn($v) => base64_decode($msfix($v));
  
      $passkey = base64_encode($b64_dec($post->id));
      $alg = $post->response->publicKeyAlgorithm;
      $pub = base64_encode($b64_dec($post->response->publicKey));
  
      $stmt = $GLOBALS['mySQLi']->prepare("INSERT INTO `passkeys`(`passkey`, `alg`, `pub`, `user`, `label`) VALUES (FROM_BASE64(?), ?, FROM_BASE64(?), ?, 'passkey')");
      $stmt->bind_param('sisi', $passkey, $alg, $pub, $_SESSION['user']);
      $stmt->execute() or close(500, 'db failure');
  
      echo 'OK';
    }
    close(1);
  }
}

function close($status=null, $message=null) {
  if($status) http_response_code($status);
  if($message) echo $message;
  $GLOBALS['mySQLi']->close();
  exit;
}

function phpasskey_js() { echo "<script>
  function cred(fn) {
    ArrayBuffer.prototype.toJSON = function() { return btoa(String.fromCharCode(...new Uint8Array(this))) }
    PublicKeyCredential.prototype.toJSON = function() {
      function* iter(o) { for(let k in o) {  // only way that lists clientDataJSON
        yield (k.startsWith('get') && (o[k] instanceof Function)) ? [k.charAt(3).toLowerCase() + k.slice(4), o[k]()] : [k, o[k]]
      } }
      let toJSON = o => Object.fromEntries(iter(o))
      return Object.assign(toJSON(this), { response: toJSON(this.response) })
    }
  
    const err = (s) => {throw new Error('Error ' + r.status)};
    const fetchOK = (...a) => fetch(...a).then(r => r.ok ? r : err('Error ' + r.status));
    const fetchJSON = (...a) => fetchOK(...a).then(r => r.json(), _ => err('Notation error'));
    const a2b = s => new Uint8Array(window.atob(s).split('').map(c => c.charCodeAt(0)));
  
    fetchJSON(window.location.href).then(o => {
      o.publicKey.challenge = a2b(o.publicKey.challenge);
      if(o.publicKey.user) o.publicKey.user.id = a2b(o.publicKey.user.id);
      return fn(o);
    }).then(pkc => fetch(window.location.href, {method: 'POST', body: JSON.stringify(pkc)})).then(() => location.reload()).catch(e => alert(e));
  }
  const login = () => cred(o => navigator.credentials.get(o));
  const register = () => cred(o => navigator.credentials.create(o));
  </script>"; }
