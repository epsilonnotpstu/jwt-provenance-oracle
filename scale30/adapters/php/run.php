<?php
// scale30 PHP adapter — ৩টা library, PREREG §3 contract।
// ব্যবহার: run.sh <cases.json> <outdir> [impl ...]   (conda-forge PHP 8.5, ext-sodium সহ)
// load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
// truth.json কখনো পড়া হয় না।
require __DIR__ . '/vendor/autoload.php';

use Composer\InstalledVersions;

function secret($c) { return hex2bin($c['key']['secret_hex']); }
function b64u_to_b64($s) { return base64_encode(base64_decode(strtr($s, '-_', '+/'))); }

final class NowClock implements Psr\Clock\ClockInterface {
    public function now(): DateTimeImmutable { return new DateTimeImmutable(); }
}

function lcobucci_signer($alg) {
    $m = [
        'HS256' => Lcobucci\JWT\Signer\Hmac\Sha256::class, 'HS384' => Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'HS512' => Lcobucci\JWT\Signer\Hmac\Sha512::class, 'RS256' => Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => Lcobucci\JWT\Signer\Rsa\Sha384::class, 'RS512' => Lcobucci\JWT\Signer\Rsa\Sha512::class,
        'ES256' => Lcobucci\JWT\Signer\Ecdsa\Sha256::class, 'ES384' => Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
        'ES512' => Lcobucci\JWT\Signer\Ecdsa\Sha512::class, 'EdDSA' => Lcobucci\JWT\Signer\Eddsa::class,
    ];
    if (!isset($m[$alg])) throw new RuntimeException("lcobucci/jwt has no signer for $alg");
    return new $m[$alg]();
}

function webtoken_alg($alg) {
    $cls = 'Jose\\Component\\Signature\\Algorithm\\' . $alg;
    if (!class_exists($cls)) throw new RuntimeException("web-token has no algorithm class for $alg");
    return new $cls();
}

$IMPLS = [
    // firebase/php-jwt: JWT::decode(token, new Key(material, alg)) — Key একটাই alg-এ বাঁধা; pin allowed_algs[0]
    //   EdDSA material = base64 raw public key (README)
    'php-jwt' => ['pkg' => 'firebase/php-jwt', 'backend' => 'openssl/sodium',
        'load' => function ($c) {
            $k = $c['key'];
            if ($k['kind'] === 'hmac') return secret($c);
            if ($k['kind'] === 'okp') return b64u_to_b64($k['jwk']['x']);
            return $k['pem'];
        },
        'verify' => function ($t, $k, $algs) {
            // G3 fix: cast the library's stdClass directly; the old json_encode→json_decode(…, true) round-trip
            // turned nested {} into [] (adapter artefact, EXP_g2 §2)
            return (array) Firebase\JWT\JWT::decode($t, new Firebase\JWT\Key($k, $algs[0]));
        }],
    // lcobucci/jwt 5: Parser + Validator->assert(SignedWith(signer(allowed_algs[0]), key), LooseValidAt(clock))
    'lcobucci-jwt' => ['pkg' => 'lcobucci/jwt', 'backend' => 'openssl/sodium',
        'load' => function ($c) {
            $k = $c['key'];
            if ($k['kind'] === 'hmac') return Lcobucci\JWT\Signer\Key\InMemory::plainText(secret($c));
            if ($k['kind'] === 'okp') return Lcobucci\JWT\Signer\Key\InMemory::base64Encoded(b64u_to_b64($k['jwk']['x']));
            return Lcobucci\JWT\Signer\Key\InMemory::plainText($k['pem']);
        },
        'verify' => function ($t, $k, $algs) {
            $tok = (new Lcobucci\JWT\Token\Parser(new Lcobucci\JWT\Encoding\JoseEncoder()))->parse($t);
            (new Lcobucci\JWT\Validation\Validator())->assert($tok,
                new Lcobucci\JWT\Validation\Constraint\SignedWith(lcobucci_signer($algs[0]), $k),
                new Lcobucci\JWT\Validation\Constraint\LooseValidAt(new NowClock()));
            $out = [];
            foreach ($tok->claims()->all() as $n => $v) $out[$n] = $v instanceof DateTimeInterface ? $v->getTimestamp() : $v;
            return $out;
        }],
    // web-token/jwt-library: JWSVerifier(AlgorithmManager(allowed)) ->verifyWithKey + ClaimCheckerManager
    'jwt-framework' => ['pkg' => 'web-token/jwt-library', 'backend' => 'openssl/sodium',
        'load' => fn($c) => new Jose\Component\Core\JWK($c['key']['jwk']),
        'verify' => function ($t, $k, $algs) {
            $mgr = new Jose\Component\Core\AlgorithmManager(array_map('webtoken_alg', $algs));
            $ser = new Jose\Component\Signature\Serializer\JWSSerializerManager([new Jose\Component\Signature\Serializer\CompactSerializer()]);
            $jws = $ser->unserialize($t);
            if (!(new Jose\Component\Signature\JWSVerifier($mgr))->verifyWithKey($jws, $k, 0))
                throw new RuntimeException('verifyWithKey returned false');
            $claims = json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR);
            (new Jose\Component\Checker\ClaimCheckerManager([new Jose\Component\Checker\IssuedAtChecker(new NowClock()),
                new Jose\Component\Checker\NotBeforeChecker(new NowClock()), new Jose\Component\Checker\ExpirationTimeChecker(new NowClock())]))->check($claims);
            // G3 fix: report belief from an object-preserving decode ({} stays {}); the checker keeps the array form
            return (array) json_decode($jws->getPayload(), false, 512, JSON_THROW_ON_ERROR);
        }],
];

function err($e) { return substr(get_class($e) . ': ' . $e->getMessage(), 0, 200); }

$cases = json_decode(file_get_contents($argv[1]), true)['cases'];
$outdir = $argv[2];
@mkdir($outdir, 0777, true);
$names = array_slice($argv, 3) ?: array_keys($IMPLS);
foreach ($names as $name) {
    $I = $IMPLS[$name];
    $f = fopen("$outdir/php__$name.jsonl", 'w');
    foreach ($cases as $i => $c) {
        $r = ['impl' => "php/$name", 'version' => InstalledVersions::getPrettyVersion($I['pkg']), 'lang' => 'php',
              'backend' => $I['backend'], 'case' => $c['id'], 'accepted' => false, 'claims' => new stdClass(),
              'error' => '', 'stage' => '', 'ns' => 0];
        try { $k = $I['load']($c); }
        catch (Throwable $e) { $r['stage'] = 'keyload'; $r['error'] = err($e); fwrite($f, json_encode($r, JSON_UNESCAPED_UNICODE) . "\n"); continue; }
        $once = function () use ($I, $c, $k) {
            $t0 = hrtime(true);
            try { $cl = $I['verify']($c['token'], $k, $c['allowed_algs']); return [$cl, null, hrtime(true) - $t0]; }
            catch (Throwable $e) { return [null, $e, hrtime(true) - $t0]; }
        };
        [$cl, $e, $dt] = $once();
        if ($i === 0) [$cl, $e, $dt] = $once();
        $r['ns'] = $dt; $r['stage'] = 'verify';
        if ($e) $r['error'] = err($e);
        elseif (is_array($cl)) { $r['accepted'] = true; $r['claims'] = $cl ?: new stdClass(); }
        else { $r['stage'] = 'claims'; $r['error'] = 'non-array claims'; }
        fwrite($f, json_encode($r, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR) . "\n");
    }
    fclose($f);
    fwrite(STDERR, "done $name\n");
}
