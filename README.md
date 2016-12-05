# client-tls-tools


### Example

```java
final String user = "user";
final CertKeyPaths certKeyPaths = CertKeyPaths.create(Paths.get("/foo"), Paths.get("/bar"));
final CertFileHttpsHandler certFileHttpsHandler =
    HttpsHandlers.createCertFileHttpsHandler(user, false, certKeyPaths);
final URL url = new URL("https://example.net");
final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
certFileHttpsHandler.handle(conn);
```
