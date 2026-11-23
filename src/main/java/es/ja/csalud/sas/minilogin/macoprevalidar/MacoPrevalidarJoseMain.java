package es.ja.csalud.sas.minilogin.macoprevalidar;

import java.nio.file.Path;
import java.util.Map;

public final class MacoPrevalidarJoseMain {

    private static final String DECODE_FLAG = "--decode";

    private MacoPrevalidarJoseMain() {
    }

    public static void main(String[] args) {
        try {
            if (args.length > 0 && DECODE_FLAG.equals(args[0])) {
                if (args.length != 2 || args[1].isBlank()) {
                    throw new IllegalArgumentException("Uso: --decode <joseToken>");
                }
                decode(args[1]);
                return;
            }
            CommandArguments commandArguments = CommandArguments.parse(args);
            execute(commandArguments.login(), commandArguments.passMd5(), commandArguments.module());
        } catch (Exception exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        }
    }

    public static String execute(String login, String passMd5, String module) throws Exception {
        LocalConfiguration configuration = loadConfiguration();
        PrevalidarResponse response = new PrevalidarClient(configuration.prevalidarUrl())
            .prevalidate(login, passMd5, module);
        MacoIdentity identity = PrevalidarResponseParser.parse(response.innerXml(), module);
        String token = new JoseMacoTokenGenerator(configuration).generate(identity);
        printSummary(identity);
        System.out.println("jwtMaco=" + token);
        return token;
    }

    public static Map<String, Object> decode(String joseToken) throws Exception {
        LocalConfiguration configuration = loadConfiguration();
        DecodedMacoToken decoded = new JoseMacoTokenDecoder(configuration).decode(joseToken);
        printDecoded(decoded);
        return decoded.claims();
    }

    private static LocalConfiguration loadConfiguration() throws Exception {
        Path configPath = Path.of(System.getProperty("maco.config.file", "config/local.properties"));
        return LocalConfiguration.load(configPath);
    }

    private static void printSummary(MacoIdentity identity) {
        System.out.printf("codDry=%s%n", identity.codDry());
        System.out.printf("login=%s%n", identity.login());
        System.out.printf("codMod=%s%n", identity.codMod());
        System.out.printf("codUni=%s%n", identity.codUni());
        System.out.printf("codPer=%s%n", identity.codPer());
        System.out.printf("nombre=%s %s %s%n", identity.nombre(), identity.apellido1(), identity.apellido2());
        System.out.println("tipo=1");
        System.out.println("modalidadAsistencial=1");
    }

    private static void printDecoded(DecodedMacoToken decoded) {
        System.out.printf("jweAlgorithm=%s%n", decoded.jweAlgorithm());
        System.out.printf("encryptionMethod=%s%n", decoded.encryptionMethod());
        System.out.printf("contentType=%s%n", decoded.contentType());
        System.out.printf("compressionAlgorithm=%s%n", decoded.compressionAlgorithm());
        System.out.printf("jwsAlgorithm=%s%n", decoded.jwsAlgorithm());
        System.out.printf("signatureValid=%s%n", decoded.signatureValid());
        System.out.println("claims:");
        decoded.claims().forEach((key, value) -> System.out.printf("  %s=%s%n", key, value));
    }
}
