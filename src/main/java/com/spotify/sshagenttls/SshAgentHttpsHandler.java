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

import static com.google.common.base.Preconditions.checkNotNull;

import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;

import java.nio.file.Path;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.ContentSigner;

public class SshAgentHttpsHandler extends CertHttpsHandler {

  private final String user;
  private final Identity identity;
  private final X509CachingCertKeyCreator x509CachingCertKeyCreator;
  private final X500Principal x500Principal;

  private SshAgentHttpsHandler(final Builder builder) {
    super(builder.failOnCertError);

    this.user = checkNotNull(builder.user, "user");
    checkNotNull(builder.agentProxy, "agentProxy");
    this.identity = checkNotNull(builder.identity, "identity");
    checkNotNull(builder.certCacheDir, "certCacheDir");

    final ContentSigner contentSigner = SshAgentContentSigner.create(builder.agentProxy, identity);
    final X509CertKeyCreator delegate = X509CertKeyCreator.create(contentSigner);
    x509CachingCertKeyCreator = X509CachingCertKeyCreator.create(
        delegate, builder.certCacheDir, identity);
    this.x500Principal = checkNotNull(builder.x500Principal);
  }

  public static Builder builder() {
    return new Builder()
        .setX500Principal(new X500Principal("C=US,O=Spotify,CN=sshagenttls"));
  }

  public static class Builder {

    private String user;
    private boolean failOnCertError;
    private AgentProxy agentProxy;
    private Identity identity;
    private Path certCacheDir;
    private X500Principal x500Principal;

    public Builder setUser(final String user) {
      this.user = user;
      return this;
    }

    public Builder setFailOnCertError(final boolean failOnCertError) {
      this.failOnCertError = failOnCertError;
      return this;
    }

    public Builder setAgentProxy(final AgentProxy agentProxy) {
      this.agentProxy = agentProxy;
      return this;
    }

    public Builder setIdentity(final Identity identity) {
      this.identity = identity;
      return this;
    }

    public Builder setX500Principal(final X500Principal x500Principal) {
      this.x500Principal = x500Principal;
      return this;
    }

    public Builder setCertCacheDir(final Path certCacheDir) {
      this.certCacheDir = certCacheDir;
      return this;
    }

    public SshAgentHttpsHandler build() {
      return new SshAgentHttpsHandler(this);
    }
  }

  @Override
  protected CertKey createCertKey() {
    return x509CachingCertKeyCreator.createCertKey(user, x500Principal);
  }

  @Override
  protected String getCertSource() {
    return "ssh-agent key: " + identity.getComment();
  }
}
