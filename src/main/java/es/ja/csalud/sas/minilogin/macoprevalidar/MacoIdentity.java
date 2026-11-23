package es.ja.csalud.sas.minilogin.macoprevalidar;

public record MacoIdentity(
    String ticket,
    String signature,
    String codDry,
    String login,
    String passMd5,
    String codMod,
    String codUni,
    String codPer,
    String nombre,
    String apellido1,
    String apellido2
) {
}

