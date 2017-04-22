# ssh-agent-tls

[![Build Status](https://travis-ci.org/spotify/ssh-agent-tls.svg?branch=master)](https://travis-ci.org/spotify/ssh-agent-tls)
[![codecov](https://codecov.io/gh/spotify/ssh-agent-tls/branch/master/graph/badge.svg)](https://codecov.io/gh/spotify/ssh-agent-tls)
[![Maven Central](https://img.shields.io/maven-central/v/com.spotify/ssh-agent-tls.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.spotify%22%20ssh-agent-tls)
[![License](https://img.shields.io/github/license/spotify/ssh-agent-tls.svg)](LICENSE)

This Java library provides tools for client-side TLS operations.
This project is currently stable and used in [Helios](https://github.com/spotify/helios).

* [Download](#download)
* [Getting started](#getting-started)
* [Prerequisites](#prerequisites)
* [Code of conduct](#code-of-conduct)

## Download

Download the latest JAR or grab [via Maven][maven-search].

```xml
<dependency>
  <groupId>com.spotify</groupId>
  <artifactId>ssh-agent-tls</artifactId>
  <version>0.0.1</version>
</dependency>
```

## Getting started

This example shows how to present a static TLS certificate stored on disk.
Specify the paths of the certificate "cert.pem" and private key "key.pem" for `CertKeyPaths`.
Then create an instance of `CertFileHttpsHandler`, an implementation of `HttpsHandler`,
and use it to `handle()` the `HttpsURLConnection`.

```java
final URL url = new URL("https://example.net");
final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

final CertKeyPaths certKeyPaths = CertKeyPaths.create(Paths.get("/cert.pem"), Paths.get("/key.pem"));
final CertFileHttpsHandler certFileHttpsHandler =
    HttpsHandlers.createCertFileHttpsHandler("username", false, certKeyPaths);
certFileHttpsHandler.handle(conn);
```

This example shows how to use an SSH key pair via ssh-agent (only RSA keys are supported right now)
to sign a randomly generated X.509 certificate. Create an instance of `SshAgentHttpsHandler`,
an implementation of `HttpsHandler`, and use it to `handle()` the `HttpsURLConnection`.

```java
import com.spotify.sshagentproxy.AgentProxies;
import com.spotify.sshagentproxy.Identity;

final URL url = new URL("https://example.net");
final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

final AgentProxy agentProxy = AgentProxies.newInstance();
final List<Identity> identities = agentProxy.list();
final SshAgentHttpsHandler sshAgentHttpsHandler =
    HttpsHandlers.createSshAgentHttpsHandler("username", false, agentProxy, identities.get(0));
sshAgentHttpsHandler.handle(conn);
```


## Prerequisities

Any platform that has the following

* Java 7+
* Maven 3 (for compiling)


## Code of conduct

This project adheres to the [Open Code of Conduct][code-of-conduct]. By participating, you are
expected to honor this code.

  [code-of-conduct]: https://github.com/spotify/code-of-conduct/blob/master/code-of-conduct.md
  [maven-search]: https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.spotify%22%20ssh-agent-tls
