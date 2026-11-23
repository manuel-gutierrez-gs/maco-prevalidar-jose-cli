package es.ja.csalud.sas.minilogin.macoprevalidar;

import org.w3c.dom.Element;

public final class PrevalidarResponseParser {

    private PrevalidarResponseParser() {
    }

    public static MacoIdentity parse(String responseXml, String requestedModule) throws Exception {
        Element root = PrevalidarClient.parse(responseXml).getDocumentElement();
        Element header = requiredChild(root, "cabecera_msj");
        Element origin = requiredChild(header, "entidad_origen");
        Element originOperator = requiredChild(origin, "operador");
        Element access = requiredChild(originOperator, "accesos");
        Element content = requiredChild(root, "contenido_msj");
        Element operatorSection = requiredChild(content, "Operador");
        Element operatorResponse = requiredChild(operatorSection, "respuesta_operador");
        Element responseOperator = requiredChild(operatorResponse, "operador");
        Element location = requiredChild(responseOperator, "localizacion");
        Element personalData = requiredChild(responseOperator, "datos_personales");
        Element fullName = requiredChild(personalData, "nombre_completo");

        String codMod = requiredAttribute(requiredChild(location, "modulo"), "codigo", "codMod");
        if (!requestedModule.equals(codMod)) {
            throw new IllegalStateException("El modulo devuelto por PreValidar no coincide con el solicitado");
        }
        String codDryOrigin = requiredAttribute(originOperator, "codigo_diraya", "codDry");
        String codDryResponse = requiredAttribute(responseOperator, "codigo_diraya", "codDry");
        if (!codDryOrigin.equals(codDryResponse)) {
            throw new IllegalStateException("PreValidar devolvio codigos Diraya inconsistentes");
        }

        return new MacoIdentity(
            requiredText(access, "tMaco"),
            requiredAttribute(access, "firma", "fMaco"),
            codDryOrigin,
            requiredAttribute(responseOperator, "login", "login"),
            requiredMd5(requiredAttribute(responseOperator, "pwd", "passMD5")),
            codMod,
            requiredAttribute(requiredChild(location, "unidad"), "codigo", "codUni"),
            requiredAttribute(requiredChild(location, "perfil"), "codigo", "codPer"),
            requiredText(requiredChild(fullName, "nombre"), "nombre"),
            requiredText(requiredChild(fullName, "apellido1"), "apellido1"),
            optionalText(fullName, "apellido2"));
    }

    private static Element requiredChild(Element parent, String expectedName) {
        org.w3c.dom.NodeList children = parent.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            org.w3c.dom.Node child = children.item(index);
            if (child instanceof Element element && expectedName.equals(localName(element))) {
                return element;
            }
        }
        throw new IllegalStateException("PreValidar no contiene el campo obligatorio " + expectedName);
    }

    private static String requiredAttribute(Element element, String attribute, String claim) {
        String value = element.getAttribute(attribute).trim();
        if (value.isEmpty()) {
            throw new IllegalStateException("PreValidar no informa el campo obligatorio " + claim);
        }
        return value;
    }

    private static String requiredText(Element element, String claim) {
        String value = element.getTextContent().trim();
        if (value.isEmpty()) {
            throw new IllegalStateException("PreValidar no informa el campo obligatorio " + claim);
        }
        return value;
    }

    private static String optionalText(Element parent, String expectedName) {
        org.w3c.dom.NodeList children = parent.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            org.w3c.dom.Node child = children.item(index);
            if (child instanceof Element element && expectedName.equals(localName(element))) {
                return element.getTextContent().trim();
            }
        }
        return "";
    }

    private static String requiredMd5(String value) {
        if (!value.matches("(?i)^[a-f0-9]{32}$")) {
            throw new IllegalStateException("PreValidar devolvio passMD5 con formato invalido");
        }
        return value.toUpperCase();
    }

    private static String localName(Element element) {
        return element.getLocalName() == null ? element.getNodeName() : element.getLocalName();
    }
}
