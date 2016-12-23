/*-
 * -\-\-
 * client-https
 * --
 * Copyright (C) 2016 Spotify AB
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

package com.spotify.clienttlstools.https;

import static com.google.common.base.Strings.isNullOrEmpty;

import com.google.common.base.Preconditions;
import com.spotify.clienttlstools.tls.CertKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class CertHttpsHandler implements HttpsHandler {

  private static final Logger LOG = LoggerFactory.getLogger(CertHttpsHandler.class);
  private static final char[] KEY_STORE_PASSWORD = "FPLSlZQuM3ZCM3SjINSKuWyPK2HeS4".toCharArray();

  private final String user;
  private final boolean failOnCertError;

  CertHttpsHandler(final String user, final boolean failOnCertError) {
    Preconditions.checkArgument(!isNullOrEmpty(user));
    this.user = user;
    this.failOnCertError = failOnCertError;
  }

  String getUser() {
    return user;
  }

  /**
   * Generate the {@link Certificate} and {@link PrivateKey} that will be used in
   * {@link #handle(HttpsURLConnection)}.
   *
   * <p>The method signature is defined as throwing GeneralSecurityException because there are a
   * handful of GeneralSecurityException subclasses that can be thrown in loading an X.509
   * Certificate and we handle all of them identically.
   */
  protected abstract CertKey createCertKey()
      throws IOException, GeneralSecurityException;

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

    try {
      // We're creating a keystore in memory and putting the cert & key into it.
      // The keystore needs a password when we put the key into it, even though it's only going to
      // exist for the lifetime of the process. So we just have some random password that we use.

      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null, null);
      keyStore.setCertificateEntry("client", cert);
      keyStore.setKeyEntry("key", key, KEY_STORE_PASSWORD, new Certificate[]{cert});

      // build an SSLContext based on our keystore, and then get an SSLSocketFactory fromPaths that
      final SSLContext sslContext = SSLContexts.custom()
          .useProtocol("TLS")
          .loadKeyMaterial(keyStore, KEY_STORE_PASSWORD)
          .build();
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
