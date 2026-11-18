// scale30 Go adapter — ৪টা library, PREREG §3 contract।
// ব্যবহার: go run . <cases.json> <outdir> [impl ...]
// load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
// config = README-র নিরাপদ ব্যবহার: allow-list পিন, key টাইপ করা। truth.json কখনো পড়া হয় না।
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	gjwt "github.com/golang-jwt/jwt/v5"
	kjwt "github.com/kataras/jwt"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	xjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

type Key struct {
	Kind      string          `json:"kind"`
	SecretHex string          `json:"secret_hex"`
	PEM       string          `json:"pem"`
	JWK       json.RawMessage `json:"jwk"`
}
type Case struct {
	ID    string   `json:"id"`
	Token string   `json:"token"`
	Algs  []string `json:"allowed_algs"`
	Key   Key      `json:"key"`
}

type impl struct {
	mod     string
	backend string
	load    func(c Case) (any, error)
	verify  func(tok string, k any, algs []string) (map[string]any, error)
}

func secret(c Case) ([]byte, error) { return hex.DecodeString(c.Key.SecretHex) }

var impls = map[string]impl{
	// golang-jwt/v5: Parse(token, keyfunc, WithValidMethods(algs)); keyfunc একটাই typed key দেয়
	"golang-jwt": {"github.com/golang-jwt/jwt/v5", "crypto/*", func(c Case) (any, error) {
		switch c.Key.Kind {
		case "hmac":
			return secret(c)
		case "rsa":
			return gjwt.ParseRSAPublicKeyFromPEM([]byte(c.Key.PEM))
		case "ec":
			return gjwt.ParseECPublicKeyFromPEM([]byte(c.Key.PEM))
		default:
			return gjwt.ParseEdPublicKeyFromPEM([]byte(c.Key.PEM))
		}
	}, func(tok string, k any, algs []string) (map[string]any, error) {
		t, err := gjwt.Parse(tok, func(*gjwt.Token) (any, error) { return k, nil }, gjwt.WithValidMethods(algs))
		if err != nil {
			return nil, err
		}
		return t.Claims.(gjwt.MapClaims), nil
	}},
	// lestrrat-go/jwx/v3: jwt.Parse(buf, WithKey(alg, key)...) — প্রতিটা allowed alg-এর জন্য একটা WithKey
	"jwx": {"github.com/lestrrat-go/jwx/v3", "crypto/*", func(c Case) (any, error) {
		return jwk.ParseKey(c.Key.JWK)
	}, func(tok string, k any, algs []string) (map[string]any, error) {
		var opts []xjwt.ParseOption
		for _, a := range algs {
			sa, ok := jwa.LookupSignatureAlgorithm(a)
			if !ok {
				return nil, fmt.Errorf("unknown alg %s", a)
			}
			opts = append(opts, xjwt.WithKey(sa, k))
		}
		t, err := xjwt.Parse([]byte(tok), opts...)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		m := map[string]any{}
		return m, json.Unmarshal(b, &m)
	}},
	// go-jose/v4: jwt.ParseSigned(token, algs) → Claims(key, &std, &m) → std.Validate(now)
	"go-jose": {"github.com/go-jose/go-jose/v4", "crypto/*", func(c Case) (any, error) {
		var j gojose.JSONWebKey
		if err := j.UnmarshalJSON(c.Key.JWK); err != nil {
			return nil, err
		}
		return j.Key, nil
	}, func(tok string, k any, algs []string) (map[string]any, error) {
		var sa []gojose.SignatureAlgorithm
		for _, a := range algs {
			sa = append(sa, gojose.SignatureAlgorithm(a))
		}
		t, err := gojosejwt.ParseSigned(tok, sa)
		if err != nil {
			return nil, err
		}
		var std gojosejwt.Claims
		m := map[string]any{}
		if err := t.Claims(k, &std, &m); err != nil {
			return nil, err
		}
		if err := std.Validate(gojosejwt.Expected{Time: time.Now()}); err != nil {
			return nil, err
		}
		return m, nil
	}},
	// kataras/jwt: Verify(alg, key, token) — একটাই alg নেয়; নিরাপদ ব্যবহার = pin allowed_algs[0]
	"kataras-jwt": {"github.com/kataras/jwt", "crypto/*", func(c Case) (any, error) {
		switch c.Key.Kind {
		case "hmac":
			return secret(c)
		case "rsa":
			return kjwt.ParsePublicKeyRSA([]byte(c.Key.PEM))
		case "ec":
			return kjwt.ParsePublicKeyECDSA([]byte(c.Key.PEM))
		default:
			return kjwt.ParsePublicKeyEdDSA([]byte(c.Key.PEM))
		}
	}, func(tok string, k any, algs []string) (map[string]any, error) {
		alg := map[string]kjwt.Alg{"HS256": kjwt.HS256, "HS384": kjwt.HS384, "HS512": kjwt.HS512,
			"RS256": kjwt.RS256, "RS384": kjwt.RS384, "RS512": kjwt.RS512, "PS256": kjwt.PS256,
			"PS384": kjwt.PS384, "PS512": kjwt.PS512, "ES256": kjwt.ES256, "ES384": kjwt.ES384,
			"ES512": kjwt.ES512, "EdDSA": kjwt.EdDSA}[algs[0]]
		if alg == nil {
			return nil, fmt.Errorf("unsupported alg %s", algs[0])
		}
		v, err := kjwt.Verify(alg, k, []byte(tok))
		if err != nil {
			return nil, err
		}
		m := map[string]any{}
		return m, v.Claims(&m)
	}},
}

func modVersion(mod string) string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == mod {
				return d.Version
			}
		}
	}
	return "?"
}

func errStr(e error) string {
	s := fmt.Sprintf("%T: %v", errors.Unwrap(e), e)
	if errors.Unwrap(e) == nil {
		s = fmt.Sprintf("%T: %v", e, e)
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func safe[T any](f func() (T, error)) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return f()
}

func runOne(name string, cases []Case, out string) {
	I := impls[name]
	f, _ := os.Create(out)
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for i, c := range cases {
		r := map[string]any{"impl": "go/" + name, "version": modVersion(I.mod), "lang": "go", "backend": I.backend,
			"case": c.ID, "accepted": false, "claims": map[string]any{}, "error": "", "stage": "", "ns": 0}
		k, err := safe(func() (any, error) { return I.load(c) })
		if err != nil {
			r["stage"], r["error"] = "keyload", errStr(err)
			enc.Encode(r)
			continue
		}
		once := func() (map[string]any, error, int64) {
			t0 := time.Now()
			cl, e := safe(func() (map[string]any, error) { return I.verify(c.Token, k, c.Algs) })
			return cl, e, time.Since(t0).Nanoseconds()
		}
		cl, e, dt := once()
		if i == 0 {
			cl, e, dt = once()
		}
		r["ns"] = dt
		r["stage"] = "verify"
		if e != nil {
			r["error"] = errStr(e)
		} else {
			r["accepted"], r["claims"] = true, cl
		}
		enc.Encode(r)
	}
}

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var doc struct{ Cases []Case }
	if err := json.Unmarshal(b, &doc); err != nil {
		panic(err)
	}
	os.MkdirAll(os.Args[2], 0o755)
	names := os.Args[3:]
	if len(names) == 0 {
		names = []string{"golang-jwt", "jwx", "go-jose", "kataras-jwt"}
	}
	for _, n := range names {
		runOne(n, doc.Cases, filepath.Join(os.Args[2], "go__"+strings.ReplaceAll(n, "/", "_")+".jsonl"))
		fmt.Fprintln(os.Stderr, "done", n)
	}
}
