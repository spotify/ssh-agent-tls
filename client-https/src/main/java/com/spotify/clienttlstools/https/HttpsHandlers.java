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

import com.spotify.clienttlstools.tls.CertKeyPaths;
import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;


/**
 * Provides various implementations of {@link HttpsHandler}.
 */
@SuppressWarnings("WeakerAccess")
public class HttpsHandlers {

  private HttpsHandlers() {
    // Prevent instantiation
  }

  public static SshAgentHttpsHandler createSshAgentHttpsHandler(
      final String user,
      final boolean failOnCertError,
      final AgentProxy agentProxy,
      final Identity identity) {
    return SshAgentHttpsHandler.create(user, failOnCertError, agentProxy, identity);
  }

  public static CertFileHttpsHandler createCertFileHttpsHandler(
      final String user,
      final boolean failOnCertError,
      final CertKeyPaths certKeyPaths) {
    return CertFileHttpsHandler.create(user, failOnCertError, certKeyPaths);
  }

}
