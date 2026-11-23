package es.ja.csalud.sas.minilogin.macoprevalidar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class JoseMacoTokenDecoderTest {

    private static final String SIGNING_JWK = "{\"alg\":\"HS256\",\"kty\":\"oct\",\"use\":\"sig\",\"k\":\"c2VjcmV0MDEyMzQ1Njc4OXNlY3JldDAxMjM0NTY3ODk\",\"kid\":\"001\"}";
    private static final String ENCRYPTION_JWK = "{\"alg\":\"HS256\",\"kty\":\"oct\",\"use\":\"enc\",\"k\":\"c2VjcmV0MDEyMzQ1Njc4OXNlY3JldDAxMjM0NTY3ODk\",\"kid\":\"002\"}";
    private static final String OTHER_ENCRYPTION_JWK = "{\"alg\":\"HS256\",\"kty\":\"oct\",\"use\":\"enc\",\"k\":\"b3RyYWNsYXZlMDEyMzQ1Njc4OW90cmFjbGF2ZTAxMjM\",\"kid\":\"003\"}";

    private static LocalConfiguration configuration() {
        return new LocalConfiguration("http://localhost", SIGNING_JWK, ENCRYPTION_JWK, 300);
    }

    @Test
    void decodesPreviouslyGeneratedTokenAndExposesClaims() {
        LocalConfiguration configuration = configuration();
        MacoIdentity identity = new MacoIdentity("TICKET", "FIRMA", "7274343", "usuario",
            "E10ADC3949BA59ABBE56E057F20F883E", "713", "SAS", "1", "Nombre", "ApellidoUno", "ApellidoDos");
        String token = new JoseMacoTokenGenerator(configuration).generate(identity);

        DecodedMacoToken decoded = new JoseMacoTokenDecoder(configuration).decode(token);

        assertEquals("dir", decoded.jweAlgorithm());
        assertEquals("A128CBC-HS256", decoded.encryptionMethod());
        assertEquals("JWT", decoded.contentType());
        assertEquals("DEF", decoded.compressionAlgorithm());
        assertEquals("HS256", decoded.jwsAlgorithm());
        assertTrue(decoded.signatureValid());
        assertEquals("1", decoded.claims().get("tipo"));
        assertEquals("TICKET", decoded.claims().get("tMaco"));
        assertEquals("FIRMA", decoded.claims().get("fMaco"));
        assertEquals("7274343", decoded.claims().get("codDry"));
        assertEquals("usuario", decoded.claims().get("login"));
        assertEquals("1", decoded.claims().get("modalidadAsistencial"));
    }

    @Test
    void failsToDecryptWhenEncryptionKeyDoesNotMatch() {
        MacoIdentity identity = new MacoIdentity("TICKET", "FIRMA", "7274343", "usuario",
            "E10ADC3949BA59ABBE56E057F20F883E", "713", "SAS", "1", "Nombre", "ApellidoUno", "ApellidoDos");
        String token = new JoseMacoTokenGenerator(configuration()).generate(identity);

        LocalConfiguration wrongKeyConfiguration =
            new LocalConfiguration("http://localhost", SIGNING_JWK, OTHER_ENCRYPTION_JWK, 300);

        assertThrows(IllegalStateException.class,
            () -> new JoseMacoTokenDecoder(wrongKeyConfiguration).decode(token));
    }

    @Test
    void rejectsBlankToken() {
        assertThrows(IllegalArgumentException.class,
            () -> new JoseMacoTokenDecoder(configuration()).decode("  "));
    }

    @Test
    void rejectsMalformedToken() {
        assertThrows(IllegalArgumentException.class,
            () -> new JoseMacoTokenDecoder(configuration()).decode("no-es-un-jwe"));
    }
}
