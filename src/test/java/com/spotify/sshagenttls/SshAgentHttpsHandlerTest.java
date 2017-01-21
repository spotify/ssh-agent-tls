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

import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class SshAgentHttpsHandlerTest {

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();


  @Test
  public void testSshAgent() throws Exception {
    final byte[] random = new byte[255];
    new Random().nextBytes(random);

    final AgentProxy proxy = mock(AgentProxy.class);
    final Identity identity = mock(Identity.class);
    when(identity.getKeyBlob()).thenReturn(random);

    when(proxy.sign(any(Identity.class), any(byte[].class))).thenAnswer(new Answer<byte[]>() {
      @Override
      public byte[] answer(InvocationOnMock invocation) throws Throwable {
        final byte[] bytesToSign = (byte[]) invocation.getArguments()[1];
        final MessageDigest messageDigest;
        try {
          messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
        return messageDigest.digest(bytesToSign);
      }
    });

    final SshAgentHttpsHandler h = SshAgentHttpsHandler.builder()
        .setUser("foo")
        .setFailOnCertError(true)
        .setAgentProxy(proxy)
        .setIdentity(identity)
        .setX500Principal(new X500Principal("C=US,O=Spotify,CN=foobar"))
        .setCertCacheDir(folder.newFolder().toPath())
        .build();

    final CertKey pair = h.createCertKey();
    assertNotNull(pair);
    assertNotNull(pair.cert());
    assertNotNull(pair.key());
  }
}