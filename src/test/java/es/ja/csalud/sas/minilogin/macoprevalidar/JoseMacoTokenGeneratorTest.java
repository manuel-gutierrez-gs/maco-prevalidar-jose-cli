package es.ja.csalud.sas.minilogin.macoprevalidar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class JoseMacoTokenGeneratorTest {

    private static final String SIGNING_JWK = "{\"alg\":\"HS256\",\"kty\":\"oct\",\"use\":\"sig\",\"k\":\"c2VjcmV0MDEyMzQ1Njc4OXNlY3JldDAxMjM0NTY3ODk\",\"kid\":\"001\"}";
    private static final String ENCRYPTION_JWK = "{\"alg\":\"HS256\",\"kty\":\"oct\",\"use\":\"enc\",\"k\":\"c2VjcmV0MDEyMzQ1Njc4OXNlY3JldDAxMjM0NTY3ODk\",\"kid\":\"002\"}";

    @Test
    void createsSignedThenEncryptedTypeOneMacoToken() throws Exception {
        LocalConfiguration configuration = new LocalConfiguration("http://localhost", SIGNING_JWK, ENCRYPTION_JWK, 300);
        MacoIdentity identity = new MacoIdentity("TICKET", "FIRMA", "7274343", "usuario", "E10ADC3949BA59ABBE56E057F20F883E", "713", "SAS", "1", "Nombre", "ApellidoUno", "ApellidoDos");

        String serialized = new JoseMacoTokenGenerator(configuration).generate(identity);
        JWEObject encrypted = JWEObject.parse(serialized);
        assertEquals(JWEAlgorithm.DIR, encrypted.getHeader().getAlgorithm());
        assertEquals(EncryptionMethod.A128CBC_HS256, encrypted.getHeader().getEncryptionMethod());
        assertEquals("JWT", encrypted.getHeader().getContentType());
        assertEquals(CompressionAlgorithm.DEF, encrypted.getHeader().getCompressionAlgorithm());

        OctetSequenceKey encryptionKey = OctetSequenceKey.parse(ENCRYPTION_JWK);
        encrypted.decrypt(new DirectDecrypter(encryptionKey.toByteArray()));
        SignedJWT signed = SignedJWT.parse(encrypted.getPayload().toString());
        OctetSequenceKey signingKey = OctetSequenceKey.parse(SIGNING_JWK);
        assertEquals(JWSAlgorithm.HS256, signed.getHeader().getAlgorithm());
        assertTrue(signed.verify(new MACVerifier(signingKey.toByteArray())));
        assertEquals("1", signed.getJWTClaimsSet().getStringClaim("tipo"));
        assertEquals("TICKET", signed.getJWTClaimsSet().getStringClaim("tMaco"));
        assertEquals("1", signed.getJWTClaimsSet().getStringClaim("modalidadAsistencial"));
        assertFalse(signed.getJWTClaimsSet().getClaims().containsKey("centro"));
        assertFalse(signed.getJWTClaimsSet().getClaims().containsKey("rolesUsuario"));
        assertTrue(signed.getJWTClaimsSet().getIssueTime().toInstant().isBefore(Instant.now().plusSeconds(2)));
    }
}
