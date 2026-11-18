// scale30 Swift adapter — JWTKit, PREREG §3 contract (PREREG_newlangs)।
// ব্যবহার: ./run.sh <cases.json> <outdir> [impl ...]   (build: ./run.sh --build)
// load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
// config = README-র নিরাপদ স্বাভাবিক ব্যবহার: JWTKeyCollection-এ key যোগ (alg key-এর সাথে বাঁধা → pin[0]),
// `keys.verify(token, as: Payload)`; payload-এর `verify(using:)`-এ exp যাচাই। truth.json কখনো পড়া হয় না।
// Swift-JWT (Kitura) 4.0.2 বাদ: BlueRSA OpenSSL 3-এ build হয় না (ADAPTERS.md)।
import Foundation
import JWTKit

// ── claim-এর জন্য সাধারণ JSON মান (library যা decode করে, হুবহু) ──
indirect enum AnyJSON: Codable, Sendable, Equatable {
    case null, bool(Bool), int(Int64), double(Double), string(String), array([AnyJSON]), object([String: AnyJSON])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let i = try? c.decode(Int64.self) { self = .int(i) }
        else if let d = try? c.decode(Double.self) { self = .double(d) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([AnyJSON].self) { self = .array(a) }
        else { self = .object(try c.decode([String: AnyJSON].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    var number: Double? {
        switch self { case .int(let i): return Double(i); case .double(let d): return d; default: return nil }
    }
}

struct Payload: JWTPayload {
    let fields: [String: AnyJSON]

    init(from decoder: Decoder) throws {
        fields = try decoder.singleValueContainer().decode([String: AnyJSON].self)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(fields)
    }

    // README-র নিয়ম: payload নিজেই claim যাচাই করে — exp থাকলে মেয়াদ দেখা
    func verify(using _: some JWTAlgorithm) async throws {
        if let v = fields["exp"] {
            guard let t = v.number else { throw JWTError.claimVerificationFailure(failedClaim: nil, reason: "exp not a number") }
            try ExpirationClaim(value: Date(timeIntervalSince1970: t)).verifyNotExpired()
        }
    }
}

struct KeyIn: Decodable { let kind: String; let secret_hex: String?; let pem: String? }
struct CaseIn: Decodable { let id: String; let token: String; let allowed_algs: [String]; let key: KeyIn }
struct CasesFile: Decodable { let cases: [CaseIn] }

struct Rec: Encodable {
    let impl: String, version: String, lang: String, backend: String, `case`: String
    var accepted = false
    var claims: [String: AnyJSON] = [:]
    var error = ""
    var stage = ""
    var ns: Int64 = 0
}

enum LoadedKey: Sendable {
    case hmac(HMACKey), rsa(Insecure.RSA.PublicKey), es256(ES256PublicKey), es384(ES384PublicKey),
         es512(ES512PublicKey), eddsa(EdDSA.PublicKey), noAPI(String)
}

struct AdapterError: Error, CustomStringConvertible { let description: String }

func hexData(_ s: String) -> Data {
    var d = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return d
}

// keyload = key material → JWTKit container (library-র নিজস্ব key-policy check এখানেই পড়ে, যেমন RSA < 2048)
func jwtkitLoad(_ c: CaseIn) throws -> LoadedKey {
    let a0 = c.allowed_algs[0]
    switch c.key.kind {
    case "hmac": return .hmac(HMACKey(from: hexData(c.key.secret_hex!)))
    case "rsa": return .rsa(try Insecure.RSA.PublicKey(pem: c.key.pem!))
    case "ec":
        switch a0 {
        case "ES256": return .es256(try ES256PublicKey(pem: c.key.pem!))
        case "ES384": return .es384(try ES384PublicKey(pem: c.key.pem!))
        case "ES512": return .es512(try ES512PublicKey(pem: c.key.pem!))
        default: return .noAPI(a0)                                   // যেমন ES256K: API নেই → verify-stage reject
        }
    case "okp": return .eddsa(try EdDSA.PublicKey(pem: c.key.pem!))
    default: throw AdapterError(description: "unknown key kind \(c.key.kind)")
    }
}

func jwtkitVerify(_ token: String, _ key: LoadedKey, _ algs: [String]) async throws -> [String: AnyJSON] {
    let a0 = algs[0]
    let keys = JWTKeyCollection()
    let digest: [String: DigestAlgorithm] = ["256": .sha256, "384": .sha384, "512": .sha512]
    switch (key, a0) {
    case (.noAPI(let a), _): throw AdapterError(description: "no algorithm for \(a)")
    case (.hmac(let k), _) where a0.hasPrefix("HS"): await keys.add(hmac: k, digestAlgorithm: digest[String(a0.dropFirst(2))]!)
    case (.rsa(let k), _) where a0.hasPrefix("RS"): await keys.add(rsa: k, digestAlgorithm: digest[String(a0.dropFirst(2))]!)
    case (.rsa(let k), _) where a0.hasPrefix("PS"): await keys.add(pss: k, digestAlgorithm: digest[String(a0.dropFirst(2))]!)
    case (.es256(let k), "ES256"): await keys.add(ecdsa: k)
    case (.es384(let k), "ES384"): await keys.add(ecdsa: k)
    case (.es512(let k), "ES512"): await keys.add(ecdsa: k)
    case (.eddsa(let k), "EdDSA"): await keys.add(eddsa: k)
    default: throw AdapterError(description: "no algorithm for \(a0)")
    }
    return try await keys.verify(token, as: Payload.self).fields
}

func errString(_ e: Error) -> String {
    let s = "\(type(of: e)): \(e)"
    return String(s.prefix(200))
}

func nowNs() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds) }

func jwtkitVersion() -> String {
    // Package.resolved থেকে (hard-code নয়)
    let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    var dir = exe.deletingLastPathComponent()
    for _ in 0..<6 {
        let f = dir.appendingPathComponent("Package.resolved")
        if let d = try? Data(contentsOf: f),
           let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
           let pins = o["pins"] as? [[String: Any]],
           let p = pins.first(where: { ($0["identity"] as? String) == "jwt-kit" }),
           let st = p["state"] as? [String: Any], let v = st["version"] as? String { return v }
        dir = dir.deletingLastPathComponent()
    }
    return "unknown"
}

func attempt(_ c: CaseIn, _ k: LoadedKey) async -> (Rec) -> Rec {
    let t0 = nowNs()
    do {
        let cl = try await jwtkitVerify(c.token, k, c.allowed_algs)
        let ns = nowNs() - t0
        return { r in var r = r; r.accepted = true; r.claims = cl; r.stage = "verify"; r.ns = ns; return r }
    } catch {
        let ns = nowNs() - t0
        let e = errString(error)
        return { r in var r = r; r.stage = "verify"; r.error = e; r.ns = ns; return r }
    }
}

@main
struct Main {
    static func main() async throws {
        let argv = CommandLine.arguments
        guard argv.count >= 3 else { FileHandle.standardError.write("usage: adapter <cases.json> <outdir>\n".data(using: .utf8)!); exit(2) }
        let cases = try JSONDecoder().decode(CasesFile.self, from: Data(contentsOf: URL(fileURLWithPath: argv[1]))).cases
        let outdir = URL(fileURLWithPath: argv[2])
        try FileManager.default.createDirectory(at: outdir, withIntermediateDirectories: true)
        let names = argv.count > 3 ? Array(argv[3...]) : ["jwt-kit"]
        let enc = JSONEncoder()
        enc.outputFormatting = [.withoutEscapingSlashes]
        for name in names where name == "jwt-kit" {
            let version = jwtkitVersion()
            var out = Data()
            for (i, c) in cases.enumerated() {
                var r = Rec(impl: "swift/jwt-kit", version: version, lang: "swift", backend: "swift-crypto", case: c.id)
                do {
                    let k = try jwtkitLoad(c)
                    r = await attempt(c, k)(r)
                    if i == 0 { r.ns = await attempt(c, k)(r).ns }   // প্রথম call-এ lazy init — আবার মাপা
                } catch {
                    r.stage = "keyload"
                    r.error = errString(error)
                }
                out.append(try enc.encode(r))
                out.append(0x0A)
            }
            try out.write(to: outdir.appendingPathComponent("swift__\(name).jsonl"))
            FileHandle.standardError.write("done \(name)\n".data(using: .utf8)!)
        }
    }
}
