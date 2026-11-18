// scale30 Dart adapter — ২টা library, PREREG §3 contract (PREREG_newlangs)।
// ব্যবহার: ./run.sh <cases.json> <outdir> [impl ...]   (build: dart compile exe run.dart -o bin/adapter)
// load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
// config = README-র নিরাপদ স্বাভাবিক ব্যবহার। truth.json কখনো পড়া হয় না।
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart' as djwt;
import 'package:jose/jose.dart' as jose;

typedef Load = Object Function(Map<String, dynamic> c);
typedef Verify = Future<Object?> Function(String tok, Object k, List<String> algs);

class Impl {
  final String pkg, backend;
  final Load load;
  final Verify verify;
  Impl(this.pkg, this.backend, this.load, this.verify);
}

Map<String, dynamic> key(Map<String, dynamic> c) => c['key'] as Map<String, dynamic>;
bool isH(Map<String, dynamic> c) => key(c)['kind'] == 'hmac';
Uint8List hex(String s) =>
    Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);

final impls = <String, Impl>{
  // dart_jsonwebtoken: JWT.verify(token, key) — alg allow-list API নেই (alg header থেকে; key-টাইপ cast করে)।
  // default: typ=="JWT" আবশ্যক, exp/nbf যাচাই।
  'dart_jsonwebtoken': Impl('dart_jsonwebtoken', 'pointycastle', (c) {
    final k = key(c);
    switch (k['kind']) {
      case 'hmac':
        return djwt.SecretKey(base64.encode(hex(k['secret_hex'] as String)), isBase64Encoded: true);
      case 'rsa':
        return djwt.RSAPublicKey(k['pem'] as String);
      case 'ec':
        return djwt.ECPublicKey(k['pem'] as String);
      case 'okp':
        return djwt.EdDSAPublicKey.fromPEM(k['pem'] as String);
    }
    throw ArgumentError('unknown key kind ${k['kind']}');
  }, (tok, k, algs) async => djwt.JWT.verify(tok, k as djwt.JWTKey).payload),

  // jose: JsonWebToken.decodeAndVerify(token, keyStore, allowedArguments) + claims.validate()
  'jose': Impl('jose', 'pointycastle', (c) {
    final jwk = jose.JsonWebKey.fromJson(Map<String, dynamic>.from(key(c)['jwk'] as Map));
    return jose.JsonWebKeyStore()..addKey(jwk);
  }, (tok, k, algs) async {
    final t = await jose.JsonWebToken.decodeAndVerify(tok, k as jose.JsonWebKeyStore,
        allowedArguments: algs);
    final errs = t.claims.validate().toList();
    if (errs.isNotEmpty) throw errs.first;
    return t.claims.toJson();
  }),
};

String err(Object e) {
  final s = '${e.runtimeType}: $e';
  return s.length > 200 ? s.substring(0, 200) : s;
}

/// version = pubspec.lock থেকে (hard-code নয়)
Map<String, String> lockVersions() {
  // run.dart (adapters/dart/) বা compiled bin/adapter — দুই জায়গা থেকেই pubspec.lock খোঁজা
  var dir = File(Platform.script.toFilePath()).parent;
  if (!File('${dir.path}/pubspec.lock').existsSync()) dir = dir.parent;
  final lock = File('${dir.path}/pubspec.lock').readAsLinesSync();
  final out = <String, String>{};
  String? cur;
  for (final l in lock) {
    final m = RegExp(r'^  ([A-Za-z0-9_]+):$').firstMatch(l);
    if (m != null) cur = m.group(1);
    final v = RegExp(r'^    version: "(.+)"$').firstMatch(l);
    if (v != null && cur != null) out[cur] = v.group(1)!;
  }
  return out;
}

int ns(Stopwatch sw) => sw.elapsedTicks * 1000000000 ~/ sw.frequency;

Future<void> runOne(String name, List cases, String out, Map<String, String> vers) async {
  final impl = impls[name]!;
  final base = {'impl': 'dart/$name', 'version': vers[impl.pkg], 'lang': 'dart', 'backend': impl.backend};
  final f = File(out).openWrite();
  for (var i = 0; i < cases.length; i++) {
    final c = cases[i] as Map<String, dynamic>;
    final algs = (c['allowed_algs'] as List).cast<String>();
    final r = <String, dynamic>{...base, 'case': c['id'], 'accepted': false, 'claims': {}, 'error': '', 'stage': '', 'ns': 0};
    Object? k;
    try {
      k = impl.load(c);
    } catch (e) {
      r['stage'] = 'keyload';
      r['error'] = err(e);
    }
    if (k != null) {
      final sw = Stopwatch()..start();
      try {
        final cl = await impl.verify(c['token'] as String, k, algs);
        r['ns'] = ns(sw);
        if (cl is Map) {
          r.addAll({'accepted': true, 'claims': cl, 'stage': 'verify'});
        } else {
          r.addAll({'stage': 'claims', 'error': 'non-map claims: ${cl.runtimeType}'});
        }
      } catch (e) {
        r.addAll({'ns': ns(sw), 'stage': 'verify', 'error': err(e)});
      }
      if (i == 0) {
        // প্রথম call-এ JIT/lazy init — timing বাদ দিয়ে আবার মাপা
        final sw2 = Stopwatch()..start();
        try {
          await impl.verify(c['token'] as String, k, algs);
        } catch (_) {}
        r['ns'] = ns(sw2);
      }
    }
    f.writeln(jsonEncode(r, toEncodable: (o) => o.toString()));
  }
  await f.flush();
  await f.close();
}

Future<void> main(List<String> argv) async {
  final cases = (jsonDecode(File(argv[0]).readAsStringSync()) as Map)['cases'] as List;
  final outdir = Directory(argv[1])..createSync(recursive: true);
  final vers = lockVersions();
  for (final name in (argv.length > 2 ? argv.sublist(2) : impls.keys.toList())) {
    await runOne(name, cases, '${outdir.path}/dart__$name.jsonl', vers);
    stderr.writeln('done $name');
  }
}
