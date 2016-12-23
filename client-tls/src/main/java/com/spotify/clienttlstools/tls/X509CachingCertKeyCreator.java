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

import static com.spotify.clienttlstools.tls.Utils.asPemString;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.WRITE;

import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import com.spotify.sshagentproxy.Identity;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X509CachingCertKeyCreator implements CertKeyCreator {

  private static final Logger LOG = LoggerFactory.getLogger(X509CachingCertKeyCreator.class);
  private static final BaseEncoding HEX_ENCODING = BaseEncoding.base16().lowerCase();

  private final X509CertKeyCreator delegate;
  private final Path cacheDirectory;
  // TODO (dxia) It'd be nice if this class didn't need to know about ssh-agent stuff
  private final Identity identity;
  private final String username;

  private X509CachingCertKeyCreator(final X509CertKeyCreator delegate,
                                    final Path cacheDirectory,
                                    final Identity identity,
                                    final String username) {
    this.delegate = delegate;
    this.cacheDirectory = cacheDirectory;
    this.identity = identity;
    this.username = username;
  }

  public static X509CachingCertKeyCreator create(final X509CertKeyCreator delegate,
                                                 final Path cacheDirectory,
                                                 final Identity identity,
                                                 final String username) {
    return new X509CachingCertKeyCreator(delegate, cacheDirectory, identity, username);
  }

  @Override
  public CertKey createCertKey() {
    final MessageDigest identityHash;
    try {
      identityHash = MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }

    identityHash.update(identity.getKeyBlob());
    identityHash.update(username.getBytes());

    final String identityHex = HEX_ENCODING.encode(identityHash.digest()).substring(0, 8);
    final Path cacheCertPath = cacheDirectory.resolve(identityHex + ".crt");
    final Path cacheKeyPath = cacheDirectory.resolve(identityHex + ".pem");

    boolean useCached = false;
    CertKey cached = null;

    try {
      if (Files.exists(cacheCertPath) && Files.exists(cacheKeyPath)) {
        cached = CertKey.fromPaths(cacheCertPath, cacheKeyPath);
      }
    } catch (IOException | GeneralSecurityException e) {
      // some sort of issue with cached cert, that's fine
      LOG.debug("error reading cached cert and key fromPaths {} for identity={}",
          cacheDirectory, identity.getComment(), e);
    }

    if ((cached != null) && (cached.cert() instanceof X509Certificate)) {
      final X509Certificate cachedX509 = (X509Certificate) cached.cert();
      final Date now = new Date();

      if (now.after(cachedX509.getNotBefore()) && now.before(cachedX509.getNotAfter())) {
        useCached = true;
      }
    }

    if (useCached) {
      LOG.debug("using existing cert for {} fromPaths {}", username, cacheCertPath);
      return cached;
    } else {
      final CertKey generated = delegate.createCertKey();
      saveToCache(cacheDirectory, cacheCertPath, cacheKeyPath, generated);

      return generated;
    }
  }

  private static void saveToCache(final Path cacheDirectory,
                                  final Path cacheCertPath,
                                  final Path cacheKeyPath,
                                  final CertKey certKey) {
    try {
      Files.createDirectories(cacheDirectory);

      final String certPem = asPemString(certKey.cert());
      final String keyPem = asPemString(certKey.key());

      // overwrite any existing file, and make sure it's only readable by the current user
      final Set<StandardOpenOption> options = ImmutableSet.of(CREATE, WRITE);
      final Set<PosixFilePermission> perms = ImmutableSet.of(PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE);
      final FileAttribute<Set<PosixFilePermission>> attrs =
          PosixFilePermissions.asFileAttribute(perms);

      try (final SeekableByteChannel sbc =
               Files.newByteChannel(cacheCertPath, options, attrs)) {
        sbc.write(ByteBuffer.wrap(certPem.getBytes()));
      }

      try (final SeekableByteChannel sbc =
               Files.newByteChannel(cacheKeyPath, options, attrs)) {
        sbc.write(ByteBuffer.wrap(keyPem.getBytes()));
      }

      LOG.debug("cached generated cert to {}", cacheCertPath);
    } catch (IOException e) {
      // couldn't save to the cache, oh well
      LOG.warn("error caching generated cert", e);
    }
  }
}
