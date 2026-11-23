package es.ja.csalud.sas.minilogin.macoprevalidar;

public record CommandArguments(String login, String passMd5, String module) {

    public static CommandArguments parse(String[] args) {
        if (args.length != 6) {
            throw new IllegalArgumentException("Uso: --login <usuario> --pass-md5 <md5> --module <modulo>");
        }
        String login = null;
        String passMd5 = null;
        String module = null;
        for (int index = 0; index < args.length; index += 2) {
            String value = args[index + 1];
            switch (args[index]) {
                case "--login" -> login = unique(login, value, "--login");
                case "--pass-md5" -> passMd5 = unique(passMd5, value, "--pass-md5");
                case "--module" -> module = unique(module, value, "--module");
                default -> throw new IllegalArgumentException("Argumento no reconocido " + args[index]);
            }
        }
        login = required(login, "--login");
        passMd5 = required(passMd5, "--pass-md5");
        module = required(module, "--module");
        if (!passMd5.matches("(?i)^[a-f0-9]{32}$")) {
            throw new IllegalArgumentException("--pass-md5 debe contener un MD5 hexadecimal de 32 caracteres");
        }
        return new CommandArguments(login, passMd5.toUpperCase(), module);
    }

    private static String unique(String previous, String value, String key) {
        if (previous != null) {
            throw new IllegalArgumentException("El argumento " + key + " solo puede indicarse una vez");
        }
        return value;
    }

    private static String required(String value, String key) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Falta el argumento obligatorio " + key);
        }
        return value.trim();
    }
}
