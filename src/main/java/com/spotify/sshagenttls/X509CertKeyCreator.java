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

import static java.util.concurrent.TimeUnit.HOURS;

import com.eaio.uuid.UUID;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.io.BaseEncoding;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509CertKeyCreator implements CertKeyCreator {

  private static final Logger LOG = LoggerFactory.getLogger(X509CertKeyCreator.class);
  private static final JcaX509CertificateConverter CERT_CONVERTER =
      new JcaX509CertificateConverter().setProvider("BC");
  private static final BaseEncoding KEY_ID_ENCODING =
      BaseEncoding.base16().upperCase().withSeparator(":", 2);
  private static final int KEY_SIZE = 2048;

  private final ContentSigner contentSigner;
  private final String username;
  private final int validBeforeMillis;
  private final int validAfterMillis;

  private X509CertKeyCreator(final String username,
                             final ContentSigner contentSigner,
                             final int validBeforeMillis,
                             final int validAfterMillis) {
    this.username = username;
    this.validBeforeMillis = validBeforeMillis;
    this.validAfterMillis = validAfterMillis;
    this.contentSigner = contentSigner;
  }

  public static X509CertKeyCreator create(final String username,
                                          final ContentSigner contentSigner) {
    return X509CertKeyCreator.create(username, contentSigner,
        (int) HOURS.toMillis(1), (int) HOURS.toMillis(48));
  }

  @VisibleForTesting
  static X509CertKeyCreator create(final String username,
                                   final ContentSigner contentSigner,
                                   final int validBeforeMillis,
                                   final int validAfterMills) {
    return new X509CertKeyCreator(username, contentSigner, validBeforeMillis, validAfterMills);
  }


  @Override
  public CertKey createCertKey() {
    final UUID uuid = new UUID();
    final Calendar calendar = Calendar.getInstance();
    final X500Name issuerDn = new X500Name("C=US,O=Spotify,CN=sshagenttls");
    final X500Name subjectDn = new X500NameBuilder().addRDN(BCStyle.UID, username).build();

    calendar.add(Calendar.MILLISECOND, -validBeforeMillis);
    final Date notBefore = calendar.getTime();

    calendar.add(Calendar.MILLISECOND, validBeforeMillis + validAfterMillis);
    final Date notAfter = calendar.getTime();

    // Reuse the UUID time as a SN
    final BigInteger serialNumber = BigInteger.valueOf(uuid.getTime()).abs();

    try {
      final KeyPair keyPair = generateRandomKeyPair();
      final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
          ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));

      final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
          issuerDn, serialNumber, notBefore, notAfter, subjectDn, subjectPublicKeyInfo);

      final DigestCalculator digestCalculator = new BcDigestCalculatorProvider()
          .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
      final X509ExtensionUtils utils = new X509ExtensionUtils(digestCalculator);

      final SubjectKeyIdentifier keyId = utils.createSubjectKeyIdentifier(subjectPublicKeyInfo);
      final String keyIdHex = KEY_ID_ENCODING.encode(keyId.getKeyIdentifier());
      LOG.info("generating an X509 certificate for {} with key ID={}", username, keyIdHex);

      builder.addExtension(Extension.subjectKeyIdentifier, false, keyId);
      builder.addExtension(Extension.authorityKeyIdentifier, false,
          utils.createAuthorityKeyIdentifier(subjectPublicKeyInfo));
      builder.addExtension(Extension.keyUsage, false,
          new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign));
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

      final X509CertificateHolder holder = builder.build(contentSigner);

      final X509Certificate cert = CERT_CONVERTER.getCertificate(holder);
      LOG.debug("generated certificate:\n{}", Utils.asPemString(cert));

      return CertKey.create(cert, keyPair.getPrivate());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static KeyPair generateRandomKeyPair()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    Security.addProvider(new BouncyCastleProvider());
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
    return keyPairGenerator.generateKeyPair();
  }
}
