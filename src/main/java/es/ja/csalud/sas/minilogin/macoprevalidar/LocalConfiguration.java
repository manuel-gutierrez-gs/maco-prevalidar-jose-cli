package es.ja.csalud.sas.minilogin.macoprevalidar;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public record LocalConfiguration(String prevalidarUrl, String signingJwk, String encryptionJwk, long ttlSeconds) {

    public static LocalConfiguration load(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("No existe el fichero de configuracion local: " + path.toAbsolutePath());
        }
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path)) {
            properties.load(reader);
        }
        long ttl = Long.parseLong(required(properties, "maco.jwt.ttl-seconds"));
        if (ttl <= 0) {
            throw new IllegalArgumentException("maco.jwt.ttl-seconds debe ser positivo");
        }
        return new LocalConfiguration(
            required(properties, "maco.prevalidar.url"),
            required(properties, "maco.jwt.signing-jwk"),
            required(properties, "maco.jwt.encryption-jwk"),
            ttl);
    }

    private static String required(Properties properties, String name) {
        String value = properties.getProperty(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Falta la propiedad obligatoria " + name);
        }
        return value.trim();
    }
}

