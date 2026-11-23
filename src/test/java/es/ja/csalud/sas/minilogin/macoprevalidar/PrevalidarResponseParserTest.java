package es.ja.csalud.sas.minilogin.macoprevalidar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PrevalidarResponseParserTest {

    private static final String RESPONSE = """
        <diraya_respuesta>
          <cabecera_msj><entidad_origen><operador codigo_diraya="7274343">
            <accesos firma="FIRMA">TICKET</accesos>
          </operador><localizacion><unidad codigo=""/><modulo codigo="713"/><perfil codigo=""/></localizacion></entidad_origen></cabecera_msj>
          <contenido_msj><Operador><respuesta_operador><operador codigo_diraya="7274343" login="usuario" pwd="E10ADC3949BA59ABBE56E057F20F883E">
            <datos_personales><nombre_completo><nombre>Nombre</nombre><apellido1>ApellidoUno</apellido1><apellido2>ApellidoDos</apellido2></nombre_completo></datos_personales>
            <localizacion><modulo codigo="713"/><unidad codigo="SAS"/><perfil codigo="1">Administrador</perfil></localizacion>
          </operador></respuesta_operador></Operador></contenido_msj>
        </diraya_respuesta>
        """;

    @Test
    void extractsTheIdentityAndMacoTicketFromPrevalidarResponse() throws Exception {
        MacoIdentity identity = PrevalidarResponseParser.parse(RESPONSE, "713");

        assertEquals("TICKET", identity.ticket());
        assertEquals("FIRMA", identity.signature());
        assertEquals("7274343", identity.codDry());
        assertEquals("usuario", identity.login());
        assertEquals("E10ADC3949BA59ABBE56E057F20F883E", identity.passMd5());
        assertEquals("713", identity.codMod());
        assertEquals("SAS", identity.codUni());
        assertEquals("1", identity.codPer());
        assertEquals("Nombre", identity.nombre());
    }

    @Test
    void rejectsAResponseForADifferentModule() {
        assertThrows(IllegalStateException.class, () -> PrevalidarResponseParser.parse(RESPONSE, "845"));
    }

    @Test
    void emitsAnEmptySecondSurnameWhenPrevalidarDoesNotReturnIt() throws Exception {
        String responseWithoutSecondSurname = RESPONSE.replace("<apellido2>ApellidoDos</apellido2>", "");

        MacoIdentity identity = PrevalidarResponseParser.parse(responseWithoutSecondSurname, "713");

        assertEquals("", identity.apellido2());
    }
}
