package es.ja.csalud.sas.minilogin.macoprevalidar;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public final class PrevalidarClient {

    private static final String SOAP_ACTION = "http://Diraya/WSCentralizada/PreValidar";
    private final HttpClient client;
    private final URI endpoint;

    public PrevalidarClient(String endpoint) {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(), URI.create(endpoint));
    }

    PrevalidarClient(HttpClient client, URI endpoint) {
        this.client = client;
        this.endpoint = endpoint;
    }

    public PrevalidarResponse prevalidate(String login, String passMd5, String module) throws Exception {
        String requestXml = requestXml(login, passMd5, module);
        HttpRequest request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(30))
            .header("SOAPAction", SOAP_ACTION)
            .header("Content-Type", "text/xml; charset=UTF-8")
            .POST(HttpRequest.BodyPublishers.ofString(requestXml, StandardCharsets.UTF_8))
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("PreValidar respondio HTTP " + response.statusCode());
        }
        return new PrevalidarResponse(extractResult(response.body()));
    }

    static String requestXml(String login, String passMd5, String module) {
        String inner = "<diraya_solicitud><cabecera_msj fecha=\"%s\" hora=\"%s\" version=\"5.2\"/>"
            + "<contenido_msj><Operador><validar_operador><operador login=\"%s\" pwd=\"%s\" devolver_datos=\"S\">"
            + "<localizacion><modulo codigo=\"%s\"/><unidad codigo=\"\"/></localizacion>"
            + "</operador></validar_operador></Operador></contenido_msj></diraya_solicitud>";
        java.time.ZonedDateTime now = java.time.ZonedDateTime.now(java.time.ZoneId.of("Europe/Madrid"));
        String payload = inner.formatted(
            now.format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy")),
            now.format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss")),
            xmlAttribute(login), xmlAttribute(passMd5), xmlAttribute(module));
        return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsc=\"http://Diraya/WSCentralizada\">"
            + "<soapenv:Header/><soapenv:Body><wsc:PreValidar><wsc:sXmlEntrada><![CDATA["
            + payload + "]]></wsc:sXmlEntrada></wsc:PreValidar></soapenv:Body></soapenv:Envelope>";
    }

    static String extractResult(String soapXml) throws Exception {
        Element result = firstElementByName(parse(soapXml).getDocumentElement(), "PreValidarResult");
        if (result == null || result.getTextContent().isBlank()) {
            throw new IllegalStateException("La respuesta SOAP no contiene PreValidarResult");
        }
        return result.getTextContent().trim();
    }

    static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    static Element firstElementByName(Node node, String expectedName) {
        if (node instanceof Element element && expectedName.equals(localName(element))) {
            return element;
        }
        NodeList children = node.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Element found = firstElementByName(children.item(index), expectedName);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static String localName(Element element) {
        return element.getLocalName() == null ? element.getNodeName() : element.getLocalName();
    }

    private static String xmlAttribute(String value) {
        if (value.contains("]]>") || value.contains(">")) {
            throw new IllegalArgumentException("Los argumentos no pueden contener la secuencia de cierre CDATA ni el caracter >");
        }
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }
}
