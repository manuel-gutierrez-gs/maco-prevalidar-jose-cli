# MACO PreValidar JOSE CLI

Herramienta local Java 21 para solicitar un ticket MACO mediante `PreValidar` y emitir una credencial JOSE de tipo 1, compatible con la generada por `minilogin-oauth2-maco`.

## Configuración local

Copiar `config/local.properties.example` como `config/local.properties`. Este último fichero está ignorado por Git. Configure en él las JWK que correspondan al receptor del token:

- `maco.jwt.signing-jwk`: JWK con `use=sig` y `alg=HS256`.
- `maco.jwt.encryption-jwk`: JWK con `use=enc` y `alg=HS256`.

Aunque las denominaciones históricas sean confusas, la JWK `use=sig` siempre firma el JWS y la JWK `use=enc` siempre cifra el JWE.

## Compilación y uso

```powershell
mvn clean verify
java -jar target/maco-prevalidar-jose-cli-1.0.0-SNAPSHOT.jar --login <usuario> --pass-md5 <md5> --module <modulo>
```

Se puede indicar otra ruta de configuración con `-Dmaco.config.file=C:\ruta\local.properties`.

La salida contiene un resumen no sensible y el JWE final. No imprime contraseña, ticket ni firma MACO.

## Decodificar un JOSE Token existente

La herramienta también soporta la operación inversa: dado un `joseToken` ya emitido, lo desencripta, verifica su firma y vuelca sus claims. Usa las mismas JWK (`maco.jwt.signing-jwk` / `maco.jwt.encryption-jwk`) configuradas en `local.properties`, ya que el token es simétrico.

```powershell
java -jar target/maco-prevalidar-jose-cli-1.0.0-SNAPSHOT.jar --decode <joseToken>
```

La salida incluye las cabeceras JWE/JWS (algoritmo, método de cifrado, compresión), si la firma es válida, y todos los claims del token (`tipo`, `tMaco`, `fMaco`, `codDry`, `codMod`, `codPer`, `login`, `passMD5`, `codUni`, `nombre`, `apellido1`, `apellido2`, `modalidadAsistencial`, `professionalCode` si está presente, etc.).

Si el token no se puede desencriptar con la JWK de cifrado configurada (clave incorrecta o token corrupto), la herramienta lo reporta como error. Si se desencripta pero la firma no es válida, se informa igualmente con `signatureValid=false` sin impedir la inspección de los claims.

