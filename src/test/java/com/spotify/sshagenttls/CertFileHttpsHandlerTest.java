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

import static com.google.common.io.Resources.getResource;
import static org.junit.Assert.assertNotNull;

import java.nio.file.Paths;
import org.junit.Test;


public class CertFileHttpsHandlerTest {
  @Test
  public void testCertificateFile() throws Exception {
    final CertKeyPaths certKeyPaths = CertKeyPaths.create(
        Paths.get(getResource("UIDCACert.pem").getPath()),
        Paths.get(getResource("UIDCACert.key").getPath())
    );

    final CertFileHttpsHandler h = CertFileHttpsHandler.create(true, certKeyPaths);

    final CertKey pair = h.createCertKey();
    assertNotNull(pair);
    assertNotNull(pair.cert());
    assertNotNull(pair.key());
  }

}