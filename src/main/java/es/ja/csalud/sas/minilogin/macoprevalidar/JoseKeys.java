package es.ja.csalud.sas.minilogin.macoprevalidar;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import java.text.ParseException;

/**
 * Utilidades compartidas para parsear y validar las JWK simetricas (firma y
 * cifrado) usadas tanto para generar como para decodificar el JOSE Token MACO.
 */
final class JoseKeys {

    private JoseKeys() {
    }

    static OctetSequenceKey parseKey(String source, KeyUse expectedUse, String purpose) {
        try {
            JWK parsed = JWK.parse(source);
            if (!(parsed instanceof OctetSequenceKey key)) {
                throw new IllegalArgumentException("La JWK de " + purpose + " debe tener kty=oct");
            }
            if (!expectedUse.equals(key.getKeyUse()) || !JWSAlgorithm.HS256.equals(key.getAlgorithm())) {
                throw new IllegalArgumentException("La JWK de " + purpose + " debe usar HS256 y use=" + expectedUse);
            }
            if (KeyUse.ENCRYPTION.equals(expectedUse) && key.size() != 256) {
                throw new IllegalArgumentException("La JWK de cifrado debe tener exactamente 256 bits");
            }
            if (KeyUse.SIGNATURE.equals(expectedUse) && key.size() < 256) {
                throw new IllegalArgumentException("La JWK de firma debe tener al menos 256 bits");
            }
            return key;
        } catch (ParseException exception) {
            throw new IllegalArgumentException("La JWK de " + purpose + " no es valida", exception);
        }
    }
}
