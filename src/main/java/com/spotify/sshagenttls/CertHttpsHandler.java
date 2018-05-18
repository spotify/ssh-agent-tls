/*-
 * -\-\-
 * ssh-agent-tls
 * --
 * Copyright (C) 2016 - 2017 Spotify AB
 * --
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -/-/-
 */

package com.spotify.sshagenttls;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class CertHttpsHandler implements HttpsHandler {

  private static final Logger LOG = LoggerFactory.getLogger(CertHttpsHandler.class);

  private final boolean failOnCertError;

  CertHttpsHandler(final boolean failOnCertError) {
    this.failOnCertError = failOnCertError;
  }

  /**
   * Generate the {@link Certificate} and {@link PrivateKey} that will be used in
   * {@link #handle(HttpsURLConnection)}.
   *
   * <p>The method signature is defined as throwing GeneralSecurityException because there are a
   * handful of GeneralSecurityException subclasses that can be thrown in loading an X.509
   * Certificate and we handle all of them identically.
   */
  protected abstract CertKey createCertKey() throws IOException, GeneralSecurityException;

  /**
   * Return a String describing the source of the cert for use in error messages logged by
   * {@link #handle(HttpsURLConnection)}.
   */
  protected abstract String getCertSource();

  public void handle(final HttpsURLConnection conn) {
    final CertKey certKey;
    try {
      certKey = createCertKey();
    } catch (IOException | GeneralSecurityException e) {
      if (failOnCertError) {
        throw new RuntimeException(e);
      } else {
        LOG.warn(
            "Error when setting up client certificates fromPaths {}. Error was '{}'. "
            + "No cert will be sent with request.",
            getCertSource(),
            e.toString());
        LOG.debug("full exception fromPaths setting up ClientCertificate follows", e);
        return;
      }
    }

    final Certificate cert = certKey.cert();
    final PrivateKey key = certKey.key();

    // Generate a keystore password.
    // Do all this locally to not make copies of the password in memory.
    final SecureRandom random = new SecureRandom();
    final int numBytes = 60;
    final char[] keyStorePassword = new char[numBytes];
    for (int i = 0; i < numBytes; i++) {
      // Only use ASCII characters for the password. The corresponding integer range is [32, 126].
      keyStorePassword[i] = (char) (random.nextInt(95) + 32);
    }

    try {
      // We're creating a keystore in memory and putting the cert & key into it.
      // The keystore needs a password when we put the key into it, even though it's only going to
      // exist for the lifetime of the process. So we just have some random password that we use.

      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
      keyStore.setCertificateEntry("client", cert);
      keyStore.setKeyEntry("key", key, keyStorePassword, new Certificate[]{cert});

      // build an SSLContext based on our keystore, and then get an SSLSocketFactory fromPaths that
      final SSLContext sslContext = SSLContexts.custom()
          .useProtocol("TLS")
          .loadKeyMaterial(keyStore, keyStorePassword)
          .build();

      // Clear out arrays that had password
      Arrays.fill(keyStorePassword, '\0');

      conn.setSSLSocketFactory(sslContext.getSocketFactory());
    } catch (CertificateException
        | IOException
        | NoSuchAlgorithmException
        | KeyStoreException
        | UnrecoverableKeyException
        | KeyManagementException e) {
      // so many dumb ways to die. see https://www.youtube.com/watch?v=IJNR2EpS0jw for more.
      throw new RuntimeException(e);
    }
  }
}
