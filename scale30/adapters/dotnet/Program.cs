// scale30 .NET adapter — ৩টা library, PREREG §3 contract।
// ব্যবহার: dotnet bin/Release/net8.0/Scale30Dotnet.dll <cases.json> <outdir> [impl ...]
// load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
// JIT warm-up: corpus দুবার চালিয়ে দ্বিতীয় রান লেখা হয় (PREREG §3)। truth.json কখনো পড়া হয় না।
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

static byte[] Secret(JsonNode c) => Convert.FromHexString(c["key"]!["secret_hex"]!.GetValue<string>());
static string Kind(JsonNode c) => c["key"]!["kind"]!.GetValue<string>();
static string Pem(JsonNode c) => c["key"]!["pem"]!.GetValue<string>();
static object JcaLike(JsonNode c) => Kind(c) switch {
    "hmac" => Secret(c),
    "rsa" => ((Func<RSA>)(() => { var r = RSA.Create(); r.ImportFromPem(Pem(c)); return r; }))(),
    "ec" => ((Func<ECDsa>)(() => { var e = ECDsa.Create(); e.ImportFromPem(Pem(c)); return e; }))(),
    _ => throw new NotSupportedException("no BCL container for OKP (EdDSA) keys"),
};
static Dictionary<string, object?> ToDict(string json) =>
    JsonSerializer.Deserialize<Dictionary<string, object?>>(json)!;

var impls = new Dictionary<string, (string pkg, string backend, Func<JsonNode, object> load,
                                     Func<string, object, string[], Dictionary<string, object?>> verify)>
{
    // Microsoft.IdentityModel.JsonWebTokens: JsonWebTokenHandler.ValidateTokenAsync(token, TVP)
    //   IssuerSigningKey = JsonWebKey(case jwk), ValidAlgorithms = allowed; issuer/audience configure করা নেই
    //   (অন্য adapter-এর মতো) তাই ValidateIssuer/ValidateAudience = false; lifetime যাচাই চালু।
    ["IdentityModel"] = ("Microsoft.IdentityModel.JsonWebTokens", "BCL",
        c => new JsonWebKey(c["key"]!["jwk"]!.ToJsonString()),
        (t, k, algs) => {
            var tvp = new TokenValidationParameters {
                IssuerSigningKey = (SecurityKey)k, ValidAlgorithms = algs,
                ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = true };
            var r = new JsonWebTokenHandler().ValidateTokenAsync(t, tvp).GetAwaiter().GetResult();
            if (!r.IsValid) throw r.Exception ?? new Exception("invalid");
            var jwt = (JsonWebToken)r.SecurityToken;
            return ToDict(Base64UrlEncoder.Decode(jwt.EncodedPayload));
        }),
    // jose-jwt: Jose.JWT.Decode(token, key, JwsAlgorithm) — pin allowed_algs[0]
    ["jose-jwt"] = ("jose-jwt", "BCL",
        c => JcaLike(c),
        (t, k, algs) => {
            if (!Enum.TryParse<Jose.JwsAlgorithm>(algs[0], out var a))
                throw new NotSupportedException($"jose-jwt has no JwsAlgorithm {algs[0]}");
            return ToDict(Jose.JWT.Decode(t, k, a));
        }),
    // JWT (jwt-dotnet): JwtBuilder.Create().WithAlgorithm(X).[WithSecret].MustVerifySignature().Decode(token)
    //   pin allowed_algs[0]; library-তে শুধু HS*, RS*, ES* algorithm class আছে
    ["JWT"] = ("JWT", "BCL",
        c => JcaLike(c),
        (t, k, algs) => {
            var b = JWT.Builder.JwtBuilder.Create();
            JWT.Algorithms.IJwtAlgorithm alg = algs[0] switch {
                "HS256" => new JWT.Algorithms.HMACSHA256Algorithm(),
                "HS384" => new JWT.Algorithms.HMACSHA384Algorithm(),
                "HS512" => new JWT.Algorithms.HMACSHA512Algorithm(),
                "RS256" => new JWT.Algorithms.RS256Algorithm((RSA)k),
                "RS384" => new JWT.Algorithms.RS384Algorithm((RSA)k),
                "RS512" => new JWT.Algorithms.RS512Algorithm((RSA)k),
                "ES256" => new JWT.Algorithms.ES256Algorithm((ECDsa)k),
                "ES384" => new JWT.Algorithms.ES384Algorithm((ECDsa)k),
                "ES512" => new JWT.Algorithms.ES512Algorithm((ECDsa)k),
                _ => throw new NotSupportedException($"JWT.NET has no algorithm class for {algs[0]}"),
            };
            b = b.WithAlgorithm(alg);
            if (k is byte[] s) b = b.WithSecret(s);
            return ToDict(b.MustVerifySignature().Decode(t));
        }),
};

static string Err(Exception e) { var s = $"{e.GetType().Name}: {e.Message}"; return s.Length > 200 ? s[..200] : s; }
var cases = JsonNode.Parse(File.ReadAllText(args[0]))!["cases"]!.AsArray();
Directory.CreateDirectory(args[1]);
var names = args.Length > 2 ? args[2..] : impls.Keys.ToArray();
var versions = new Dictionary<string, string> {
    ["IdentityModel"] = typeof(JsonWebTokenHandler).Assembly.GetName().Version!.ToString(),
    ["jose-jwt"] = typeof(Jose.JWT).Assembly.GetName().Version!.ToString(),
    ["JWT"] = typeof(JWT.Builder.JwtBuilder).Assembly.GetName().Version!.ToString() };
foreach (var name in names)
{
    var I = impls[name];
    var lines = new List<string>();
    for (int pass = 0; pass < 2; pass++)
    {
        lines.Clear();
        foreach (var c in cases)
        {
            var r = new JsonObject { ["impl"] = $"dotnet/{name}", ["version"] = versions[name], ["lang"] = "dotnet",
                ["backend"] = I.backend, ["case"] = c!["id"]!.GetValue<string>(), ["accepted"] = false,
                ["claims"] = new JsonObject(), ["error"] = "", ["stage"] = "", ["ns"] = 0 };
            object k;
            try { k = I.load(c); }
            catch (Exception e) { r["stage"] = "keyload"; r["error"] = Err(e); lines.Add(r.ToJsonString()); continue; }
            var algs = c["allowed_algs"]!.AsArray().Select(a => a!.GetValue<string>()).ToArray();
            var sw = Stopwatch.StartNew();
            try {
                var cl = I.verify(c["token"]!.GetValue<string>(), k, algs);
                r["ns"] = (long)(sw.Elapsed.TotalMilliseconds * 1e6); r["stage"] = "verify"; r["accepted"] = true;
                r["claims"] = JsonNode.Parse(JsonSerializer.Serialize(cl));
            } catch (Exception e) {
                r["ns"] = (long)(sw.Elapsed.TotalMilliseconds * 1e6); r["stage"] = "verify"; r["error"] = Err(e);
            }
            lines.Add(r.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        }
    }
    File.WriteAllLines(Path.Combine(args[1], $"dotnet__{name}.jsonl"), lines);
    Console.Error.WriteLine($"done {name}");
}
