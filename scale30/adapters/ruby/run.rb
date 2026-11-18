# scale30 Ruby adapter — ২টা library, PREREG §3 contract।
# ব্যবহার: run.sh <cases.json> <outdir> [impl ...]
# load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
# optional plug-in gem (যেমন jwt-eddsa) যোগ করা হয়নি — default install (nimbus-এ Tink না দেওয়ার মতোই)।
# truth.json কখনো পড়া হয় না।
require "bundler/setup"
require "json"
require "openssl"
require "fileutils"
require "jwt"
require "json/jwt"

def secret(c) = [c["key"]["secret_hex"]].pack("H*")
def pub(c) = OpenSSL::PKey.read(c["key"]["pem"])

IMPLS = {
  # ruby-jwt: JWT.decode(token, key, true, { algorithm: [...] }) → [payload, header]
  "ruby-jwt" => { gem: "jwt", backend: "openssl",
    load: ->(c) { c["key"]["kind"] == "hmac" ? secret(c) : pub(c) },
    verify: ->(t, k, algs) { JWT.decode(t, k, true, { algorithm: algs })[0] } },
  # json-jwt: JSON::JWT.decode(token, key, algorithms) — JWS lib, exp যাচাই নেই
  "json-jwt" => { gem: "json-jwt", backend: "openssl",
    load: ->(c) { c["key"]["kind"] == "hmac" ? secret(c) : pub(c) },
    verify: ->(t, k, algs) { JSON::JWT.decode(t, k, algs.map(&:to_sym)).to_h } },
}

def err(e) = "#{e.class}: #{e.message}"[0, 200]

cases = JSON.parse(File.read(ARGV[0]))["cases"]
# G3 D2: output must survive claims a library produced from edge inputs — non-finite floats (1e400 → Infinity)
# and strings that are not valid UTF-8 (a JSON lone surrogate). NaN/Infinity are written as JSON extensions,
# invalid byte sequences are scrubbed to U+FFFD (the claim then differs from Signed — excluded strata only).
def out_json(r)
  scrub = ->(v) { v.is_a?(String) ? v.dup.force_encoding("UTF-8").scrub("\uFFFD") :
                  v.is_a?(Hash) ? v.to_h { |k, x| [scrub.(k), scrub.(x)] } : v.is_a?(Array) ? v.map { |x| scrub.(x) } : v }
  JSON.generate(scrub.(r), allow_nan: true)
end

outdir = ARGV[1]
FileUtils.mkdir_p(outdir)
names = ARGV[2..].empty? ? IMPLS.keys : ARGV[2..]
names.each do |name|
  im = IMPLS.fetch(name)
  ver = Gem.loaded_specs[im[:gem]].version.to_s
  File.open("#{outdir}/ruby__#{name}.jsonl", "w") do |f|
    cases.each_with_index do |c, i|
      r = { impl: "ruby/#{name}", version: ver, lang: "ruby", backend: im[:backend], case: c["id"],
            accepted: false, claims: {}, error: "", stage: "", ns: 0 }
      begin
        k = im[:load].(c)
      rescue Exception => e
        r[:stage] = "keyload"; r[:error] = err(e); f.puts(out_json(r)); next
      end
      once = lambda do
        t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
        begin
          cl = im[:verify].(c["token"], k, c["allowed_algs"])
          [cl, nil, Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - t0]
        rescue Exception => e
          [nil, e, Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - t0]
        end
      end
      cl, e, dt = once.()
      cl, e, dt = once.() if i.zero?
      r[:ns] = dt; r[:stage] = "verify"
      if e then r[:error] = err(e)
      elsif cl.is_a?(Hash) then r[:accepted] = true; r[:claims] = cl
      else r[:stage] = "claims"; r[:error] = "non-hash claims: #{cl.class}"
      end
      f.puts(out_json(r))
    end
  end
  warn "done #{name}"
end
