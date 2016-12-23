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

import static com.google.common.base.Preconditions.checkNotNull;

import com.spotify.clienttlstools.tls.CertKey;
import com.spotify.clienttlstools.tls.SshAgentContentSigner;
import com.spotify.clienttlstools.tls.X509CachingCertKeyCreator;
import com.spotify.clienttlstools.tls.X509CertKeyCreator;
import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.bouncycastle.operator.ContentSigner;

public class SshAgentHttpsHandler extends CertHttpsHandler {

  private static final Path CERT_CACHE_DIR = Paths.get(
      System.getProperty("user.home"), ".client-tls-tools", "cert_cache");

  private final Identity identity;
  private final X509CachingCertKeyCreator x509CachingCertKeyCreator;

  private SshAgentHttpsHandler(final String user,
                               final boolean failOnCertError,
                               final AgentProxy agentProxy,
                               final Identity identity) {
    super(user, failOnCertError);
    checkNotNull(agentProxy, "agentProxy");
    this.identity = checkNotNull(identity, "identity");
    final ContentSigner contentSigner = SshAgentContentSigner.create(agentProxy, identity);
    final X509CertKeyCreator delegate = X509CertKeyCreator.create(getUser(), contentSigner);
    x509CachingCertKeyCreator = X509CachingCertKeyCreator.create(
        delegate, CERT_CACHE_DIR, identity, getUser());
  }

  static SshAgentHttpsHandler create(final String user,
                                     final boolean failOnCertError,
                                     final AgentProxy agentProxy,
                                     final Identity identity) {
    return new SshAgentHttpsHandler(user, failOnCertError, agentProxy, identity);
  }

  @Override
  protected CertKey createCertKey() {
    return x509CachingCertKeyCreator.createCertKey();
  }

  @Override
  protected String getCertSource() {
    return "ssh-agent key: " + identity.getComment();
  }
}
