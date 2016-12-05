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

package com.spotify.clienttlstools.tls;

import com.google.auto.value.AutoValue;
import com.google.common.base.Preconditions;
import java.nio.file.Path;

/**
 * Holds the {@link Path}s to files necessary to construct a {@link CertKey}.
 */
@AutoValue
public abstract class CertKeyPaths {

  CertKeyPaths() {
    // Prevent outside instantiation
  }

  public abstract Path certPath();

  public abstract Path keyPath();

  public static CertKeyPaths create(final Path certPath, final Path keyPath) {
    checkExists(certPath);
    checkExists(keyPath);
    return new AutoValue_CertKeyPaths(certPath, keyPath);
  }

  private static Path checkExists(final Path path) {
    Preconditions.checkNotNull(path);
    Preconditions.checkArgument(path.toFile().canRead(),
        path + " does not exist or cannot be read");
    return path;
  }
}
