# client-tls-tools [![CircleCI](https://circleci.com/gh/spotify/client-tls-tools.svg?style=svg&circle-token=89c903359be012a0295ce44da66278125976f688)](https://circleci.com/gh/spotify/client-tls-tools)


## Getting started

```java
final String user = "user";
final CertKeyPaths certKeyPaths = CertKeyPaths.create(Paths.get("/foo"), Paths.get("/bar"));
final CertFileHttpsHandler certFileHttpsHandler =
    HttpsHandlers.createCertFileHttpsHandler(user, false, certKeyPaths);
final URL url = new URL("https://example.net");
final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
certFileHttpsHandler.handle(conn);
```

## How to build

`mvn verify`
