package es.ja.csalud.sas.minilogin.macoprevalidar;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Operacion inversa a {@link JoseMacoTokenGenerator}: dado un JOSE Token MACO
 * (JWE que anida un JWS), lo desencripta con la JWK de cifrado configurada,
 * verifica la firma con la JWK de firma configurada y expone sus claims.
 *
 * <p>Usa las mismas JWK que el generador (configuracion local), ya que el
 * JOSE Token MACO es simetrico: la misma pareja de claves que lo emite es la
 * que puede desencriptarlo y verificar su firma.</p>
 */
public final class JoseMacoTokenDecoder {

    private final OctetSequenceKey signingKey;
    private final OctetSequenceKey encryptionKey;

    public JoseMacoTokenDecoder(LocalConfiguration configuration) {
        this.signingKey = JoseKeys.parseKey(configuration.signingJwk(), KeyUse.SIGNATURE, "firma");
        this.encryptionKey = JoseKeys.parseKey(configuration.encryptionJwk(), KeyUse.ENCRYPTION, "cifrado");
    }

    public DecodedMacoToken decode(String joseToken) {
        if (joseToken == null || joseToken.isBlank()) {
            throw new IllegalArgumentException("El joseToken a decodificar no puede estar vacio");
        }
        JWEObject encrypted = parseJwe(joseToken.trim());
        decrypt(encrypted);
        SignedJWT signed = parseSignedJwt(encrypted);
        boolean signatureValid = verifySignature(signed);
        JWEHeader jweHeader = encrypted.getHeader();
        return new DecodedMacoToken(
            jweHeader.getAlgorithm() == null ? null : jweHeader.getAlgorithm().getName(),
            jweHeader.getEncryptionMethod() == null ? null : jweHeader.getEncryptionMethod().getName(),
            jweHeader.getContentType(),
            jweHeader.getCompressionAlgorithm() == null ? null : jweHeader.getCompressionAlgorithm().getName(),
            signed.getHeader().getAlgorithm() == null ? null : signed.getHeader().getAlgorithm().getName(),
            extractClaims(signed),
            signatureValid
        );
    }

    private static JWEObject parseJwe(String joseToken) {
        try {
            return JWEObject.parse(joseToken);
        } catch (ParseException exception) {
            throw new IllegalArgumentException("El joseToken no tiene el formato JWE esperado", exception);
        }
    }

    private void decrypt(JWEObject encrypted) {
        try {
            encrypted.decrypt(new DirectDecrypter(encryptionKey.toByteArray()));
        } catch (JOSEException exception) {
            throw new IllegalStateException(
                "No se pudo desencriptar el joseToken con la JWK de cifrado configurada", exception);
        }
    }

    private static SignedJWT parseSignedJwt(JWEObject decrypted) {
        try {
            return SignedJWT.parse(decrypted.getPayload().toString());
        } catch (ParseException exception) {
            throw new IllegalStateException(
                "El contenido desencriptado no es un JWT firmado valido", exception);
        }
    }

    private boolean verifySignature(SignedJWT signed) {
        try {
            return signed.verify(new MACVerifier(signingKey.toByteArray()));
        } catch (JOSEException exception) {
            return false;
        }
    }

    private static Map<String, Object> extractClaims(SignedJWT signed) {
        try {
            return new LinkedHashMap<>(signed.getJWTClaimsSet().getClaims());
        } catch (ParseException exception) {
            throw new IllegalStateException("No se pudieron leer los claims del JWT", exception);
        }
    }
}
