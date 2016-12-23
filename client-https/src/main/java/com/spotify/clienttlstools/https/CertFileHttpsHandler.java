/*-
 * -\-\-
 * x509-ssh-client
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

import static com.google.common.base.Preconditions.checkNotNull;

import com.spotify.clienttlstools.tls.CertKey;
import com.spotify.clienttlstools.tls.CertKeyPaths;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class CertFileHttpsHandler extends CertHttpsHandler {

  private final CertKeyPaths certKeyPaths;

  private CertFileHttpsHandler(final String user,
                               final boolean failOnCertError,
                               final CertKeyPaths certKeyPaths) {
    super(user, failOnCertError);
    this.certKeyPaths = checkNotNull(certKeyPaths);
  }

  static CertFileHttpsHandler create(
      final String user,
      final boolean failOnError,
      final CertKeyPaths certKeyPaths) {
    return new CertFileHttpsHandler(user, failOnError, certKeyPaths);
  }

  @Override
  protected CertKey createCertKey() throws IOException, GeneralSecurityException {
    return CertKey.fromPaths(certKeyPaths.certPath(), certKeyPaths.keyPath());
  }

  @Override
  protected String getCertSource() {
    return certKeyPaths.toString();
  }

}
