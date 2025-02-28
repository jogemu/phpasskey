<?php // https://github.com/jogemu/phpasskey

session_set_cookie_params([
  'secure' => true, // hidden for http
  'httponly' => true, // hidden for javascript
  'samesite' => 'Strict'
]);

return function($form, $mySQLi, $challenge_bytes=64, $register=false) {
  if(!$form) return;
  $a = fn(...$v) => $v;

  $respond = function($message=null, $status=null) {
    if($status) http_response_code($status);
    if(!is_string($message) && is_callable($message)) $message = $message();
    if(is_array($message)) {
      header('Content-Type: application/json');
      $message = json_encode($message);
    }
    if($message) echo $message;
    exit;
  };

  $msfix = fn($v) => strtr($v, '-_', '+/'); // Microsoft Hello fix
  $b64_dec = fn($v) => base64_decode($msfix($v));

  $input = function($empty) use ($respond) {
    if(($_SERVER['PHP_AUTH_USER'] ?? '.') != '') {
      ob_start(fn($v) => substr_replace($v, "<script>
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

  const headers = {Authorization: 'Basic Og'};

  fetchJSON(window.location.href, {headers}).then(o => {
    o.publicKey.challenge = a2b(o.publicKey.challenge);
    if(o.publicKey.user) o.publicKey.user.id = a2b(o.publicKey.user.id);
    return fn(o);
  }).then(pkc => fetch(window.location.href, {method: 'POST', body: JSON.stringify(pkc), headers})).then(() => location.reload()).catch(e => alert(e));
}
const login = () => cred(o => navigator.credentials.get(o));
const register = () => cred(o => navigator.credentials.create(o));
</script>", strrpos($v, '</body>') ?: strlen($v), 0));
      return;
    }
    isset($_COOKIE[session_name()]) or session_start();
    if(file_get_contents('php://input') == '') $respond($empty);
    $result = json_decode(file_get_contents('php://input')) or $respond('Expected JSON credential.', 400);
    ($result->type == 'public-key') or $respond('Not a public key credential.', 422);
    return $result;
  };

  if(isset($_COOKIE[session_name()])) {
    session_start();
    if(isset($_SESSION['user'])) {
      if(!$register) return;
      $post = $input(fn() => $a(publicKey: $a(
        challenge: base64_encode(random_bytes($challenge_bytes)),
        rp: $a(id: $_SERVER['HTTP_HOST'], name: $_SERVER['HTTP_HOST']),
        user: $a(id: base64_encode(gmp_export($_SESSION['user'], 4)), name: $_SESSION['name'], displayName: $_SESSION['displayName'] ?? $_SESSION['name']),
        pubKeyCredParams: [$a(alg: -7, type: 'public-key'), $a(alg: -257, type: 'public-key')],
        authenticatorSelection: $a(residentKey: 'required')
      )));
      if(!$post) return;

      $passkey = base64_encode($b64_dec($post->id));
      $alg = $post->response->publicKeyAlgorithm;
      $pub = base64_encode($b64_dec($post->response->publicKey));
      $pub = preg_replace('/^'.preg_quote('MIIBIjANBgkqhkiG9w0BAQsFAAOCAQ8A').'/', 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A', $pub); // MS/Hello fix

      $mySQLi->prepare("INSERT INTO `passkeys`(`passkey`, `alg`, `pub`, `user`, `label`) VALUES (FROM_BASE64(?), ?, FROM_BASE64(?), ?, ?)");
      $stmt->bind_param('sisis', $passkey, $alg, $pub, $_SESSION['user'], $register);
      $stmt->execute() or $respond('db failure', 500);
      $close('OK', 201);
    }
  }

  $post = $input(fn() => $a(publicKey: $a(
    challenge: $_SESSION['challenge'] = base64_encode(random_bytes($challenge_bytes))
  ))) or $respond($form, 401);

  $id = base64_encode($b64_dec($post->id));
  $authenticatorData = $b64_dec($post->response->authenticatorData);
  $clientDataJSON = $b64_dec($post->response->clientDataJSON);
  $signature = $b64_dec($post->response->signature);
  
  $stmt = $mySQLi->prepare("SELECT * FROM `passkeys` WHERE `passkey`=FROM_BASE64(?)");
  $stmt->bind_param('s', $id);
  $stmt->execute() or $respond('db failure', 500);
  $result = $stmt->get_result() or $respond('db failure', 500);
  ($result->num_rows == 1) or $respond('This passkey is not associated with an account.', 401);
  $passkey = $result->fetch_assoc();

  (rtrim($_SESSION['challenge'], '=') == $msfix(json_decode($clientDataJSON)->challenge)) or $respond('The challenge does not match', 406);
  unset($_SESSION['challenge']);

  $pub = base64_encode($passkey['pub']);
  $cert = "-----BEGIN PUBLIC KEY-----\n".$pub."\n-----END PUBLIC KEY-----";

  $challenge = $authenticatorData;
  $challenge.= hash('sha256', $clientDataJSON, true);

  openssl_verify($challenge, $signature, $cert, OPENSSL_ALGO_SHA256) or $respond('Invalid signature', 401);
  !openssl_error_string() or $respond('Verification error', 406);

  $_SESSION['user'] = $passkey['user'];

  $respond('OK');
};
