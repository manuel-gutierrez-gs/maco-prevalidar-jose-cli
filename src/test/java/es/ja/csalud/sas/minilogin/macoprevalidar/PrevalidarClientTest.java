package es.ja.csalud.sas.minilogin.macoprevalidar;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PrevalidarClientTest {

    @Test
    void buildsTheExpectedSoapRequestAndExtractsEscapedInnerResponse() throws Exception {
        String request = PrevalidarClient.requestXml("usuario", "E10ADC3949BA59ABBE56E057F20F883E", "713");
        assertTrue(request.contains("<wsc:PreValidar>"));
        assertTrue(request.contains("login=\"usuario\""));
        assertTrue(request.contains("modulo codigo=\"713\""));

        String soap = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
            + "<PreValidarResponse><PreValidarResult>&lt;diraya_respuesta/&gt;</PreValidarResult>"
            + "</PreValidarResponse></soap:Body></soap:Envelope>";
        assertTrue(PrevalidarClient.extractResult(soap).contains("diraya_respuesta"));
    }
}
