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

import static com.google.common.io.Resources.getResource;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.spotify.clienttlstools.tls.CertKey;
import com.spotify.clienttlstools.tls.CertKeyPaths;
import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;
import java.io.EOFException;
import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import javax.net.ssl.HttpsURLConnection;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class HttpsHandlersTest {

  @Test
  public void testCertificateFile() throws Exception {
    final CertKeyPaths certKeyPaths = CertKeyPaths.create(
        Paths.get(getResource("UIDCACert.pem").getPath()),
        Paths.get(getResource("UIDCACert.key").getPath())
    );

    final CertFileHttpsHandler h =
        HttpsHandlers.createCertFileHttpsHandler("foo", true, certKeyPaths);

    final CertKey pair = h.creatCertKey();
    assertNotNull(pair);
    assertNotNull(pair.cert());
    assertNotNull(pair.key());
  }

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

    final SshAgentHttpsHandler h = HttpsHandlers.createSshAgentHttpsHandler(
        "foo", true, proxy, identity);

    final CertKey pair = h.creatCertKey();
    assertNotNull(pair);
    assertNotNull(pair.cert());
    assertNotNull(pair.key());
  }

  void test() throws Exception {
    final String user = "user";
    final CertKeyPaths certKeyPaths = CertKeyPaths.create(Paths.get("/foo"), Paths.get("/bar"));
    final CertFileHttpsHandler certFileHttpsHandler =
        HttpsHandlers.createCertFileHttpsHandler(user, false, certKeyPaths);
    final URL url = new URL("https://example.net");
    final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    certFileHttpsHandler.handle(conn);
  }
}
