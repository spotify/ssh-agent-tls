/*-
 * -\-\-
 * client-tls
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

package com.spotify.clienttlstools.tls;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class X509CachingCertKeyTest {

  @Rule
  public TemporaryFolder cacheFolder = new TemporaryFolder();

  private static final String USERNAME = "rohan";

  private static final String ROHAN_PUB_KEY =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo6Uv9Ed/6g8IEdjponMNZ/s/IC/Lebo4wgUTegF7fvByb2Jk"
      + "3ldeaNLt5Ds6jg8s1eF/5AlcN4xR844foOh85vFixgyh9bu6OceKk8rzHxYB9kqRpDgEaZzEGNAbV2EYenC07nMtGK"
      + "rcNbTtKDVA7MPChzJ3qzNW+L4MTUtac8YrTWqaUaFyjL8bSkS5cF3rtnAQXWY3Js1bQnPmtRo6ZTBltu5RtvC9p2vc"
      + "iuOID7br7s1eCGf2g1mGwdj7enr3O4TLUiTR7l7KZuM+ggQyIcoGf6PU3nTS5FgHlgrowyORqBONjye09lDw1io+n6"
      + "XnXSfO3tCOAG/kTSW2zSPaPQIDAQAB";

  private final AgentProxy agentProxy = mock(AgentProxy.class);
  private final Identity identity = mock(Identity.class);

  private X509CachingCertKeyCreator sut;

  @Before
  public void setUp() throws Exception {
    final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(ROHAN_PUB_KEY));
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

    when(identity.getPublicKey()).thenReturn(publicKey);
    when(identity.getKeyBlob()).thenReturn(publicKey.getEncoded());
    when(agentProxy.sign(any(Identity.class), any(byte[].class))).thenAnswer(new Answer<byte[]>() {
      @Override
      public byte[] answer(InvocationOnMock invocation) throws Throwable {
        final byte[] bytesToSign = (byte[]) invocation.getArguments()[1];
        try {
          return MessageDigest.getInstance("SHA-1").digest(bytesToSign);
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
      }
    });

    final X509CertKeyCreator delegate = X509CertKeyCreator.create(
        USERNAME, SshAgentContentSigner.create(agentProxy, identity), 500, 5000);
    sut = X509CachingCertKeyCreator.create(
        delegate, cacheFolder.getRoot().toPath(), identity, USERNAME);
  }

  @Test
  public void testCreateCertKey() throws Exception {
    final CertKey original = sut.createCertKey();

    // repeated invocations should return the exact same cert & keypair
    for (int i = 0; i < 5; i++) {
      final CertKey shouldBeFromCache = sut.createCertKey();

      assertThat("cert does not match original",
          original.cert().getEncoded(),
          equalTo(shouldBeFromCache.cert().getEncoded()));
      assertThat("key does not match original",
          original.key().getEncoded(),
          equalTo(shouldBeFromCache.key().getEncoded()));
    }

    // TODO (dxia) Use a fake clock
    // sleep for long enough that the cert expires
    Thread.sleep(5000);

    final CertKey shouldBeNew = sut.createCertKey();
    assertThat("cached cert being used past expiry",
        shouldBeNew.cert().getEncoded(),
        not(equalTo(original.cert().getEncoded())));
    assertThat("cached key being used past expiry",
        shouldBeNew.key().getEncoded(),
        not(equalTo(original.key().getEncoded())));
  }

  @Test
  public void testCacheWithNewUsername() throws Exception {
    final CertKey original = sut.createCertKey();

    final String newUsername = USERNAME + "2";
    final X509CertKeyCreator delegate = X509CertKeyCreator.create(
        newUsername, SshAgentContentSigner.create(agentProxy, identity), 500, 5000);
    final X509CachingCertKeyCreator sut2 = X509CachingCertKeyCreator.create(
        delegate, cacheFolder.getRoot().toPath(), identity, newUsername);

    // invocation with a different username should return different cert & keypair
    final CertKey shouldBeNew = sut2.createCertKey();
    assertThat("cached cert being used with new username",
        shouldBeNew.cert().getEncoded(),
        not(equalTo(original.cert().getEncoded())));
    assertThat("cached key being used with new username",
        shouldBeNew.key().getEncoded(),
        not(equalTo(original.key().getEncoded())));
  }
}