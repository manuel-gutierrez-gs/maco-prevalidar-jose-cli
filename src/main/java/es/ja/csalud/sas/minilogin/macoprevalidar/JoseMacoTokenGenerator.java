package es.ja.csalud.sas.minilogin.macoprevalidar;

import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

public final class JoseMacoTokenGenerator {

    private final LocalConfiguration configuration;
    private final OctetSequenceKey signingKey;
    private final OctetSequenceKey encryptionKey;

    public JoseMacoTokenGenerator(LocalConfiguration configuration) {
        this.configuration = configuration;
        this.signingKey = JoseKeys.parseKey(configuration.signingJwk(), KeyUse.SIGNATURE, "firma");
        this.encryptionKey = JoseKeys.parseKey(configuration.encryptionJwk(), KeyUse.ENCRYPTION, "cifrado");
    }

    public String generate(MacoIdentity identity) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(configuration.ttlSeconds())))
            .jwtID(UUID.randomUUID().toString())
            .claim("tipo", "1")
            .claim("tMaco", identity.ticket())
            .claim("fMaco", identity.signature())
            .claim("codDry", identity.codDry())
            .claim("codMod", identity.codMod())
            .claim("codPer", identity.codPer())
            .claim("login", identity.login())
            .claim("passMD5", identity.passMd5())
            .claim("codUni", identity.codUni())
            .claim("nombre", identity.nombre())
            .claim("apellido1", identity.apellido1())
            .claim("apellido2", identity.apellido2())
            .claim("modalidadAsistencial", "1")
            .build();
        try {
            SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), claims);
            signed.sign(new MACSigner(signingKey.toByteArray()));
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .compressionAlgorithm(CompressionAlgorithm.DEF)
                .build();
            JWEObject encrypted = new JWEObject(header, new Payload(signed.serialize()));
            encrypted.encrypt(new DirectEncrypter(encryptionKey.toByteArray()));
            return encrypted.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("No se pudo generar el JWT MACO", exception);
        }
    }

}
