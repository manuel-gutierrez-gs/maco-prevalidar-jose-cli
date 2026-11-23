package es.ja.csalud.sas.minilogin.macoprevalidar;

import java.util.Map;

/**
 * Resultado de decodificar un JOSE Token MACO (JWE anidando un JWS).
 *
 * @param jweAlgorithm algoritmo de cifrado de clave indicado en la cabecera JWE (p.ej. "dir").
 * @param encryptionMethod metodo de cifrado de contenido indicado en la cabecera JWE (p.ej. "A128CBC-HS256").
 * @param contentType valor del "cty" de la cabecera JWE (habitualmente "JWT").
 * @param compressionAlgorithm algoritmo de compresion indicado en la cabecera JWE, si lo hay (p.ej. "DEF").
 * @param jwsAlgorithm algoritmo de firma indicado en la cabecera JWS interna (p.ej. "HS256").
 * @param claims claims (payload) del JWT firmado, ya desencriptado.
 * @param signatureValid true si la firma JWS se ha podido verificar correctamente con la JWK de firma configurada.
 */
public record DecodedMacoToken(
    String jweAlgorithm,
    String encryptionMethod,
    String contentType,
    String compressionAlgorithm,
    String jwsAlgorithm,
    Map<String, Object> claims,
    boolean signatureValid
) {
}
