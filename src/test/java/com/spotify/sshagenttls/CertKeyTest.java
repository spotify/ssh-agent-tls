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

import com.google.common.io.Resources;

import java.nio.file.Paths;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CertKeyTest {

  @Rule
  public final ExpectedException thrown = ExpectedException.none();

  @Test
  public void testFromPaths() throws Exception {
    CertKey.fromPaths(
        Paths.get(Resources.getResource("UIDCACert.pem").getPath()),
        Paths.get(Resources.getResource("UIDCACert.key").getPath())
    );
  }

  @Test
  public void testFromPathsNoCert() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("resource foo.pem not found.");
    CertKey.fromPaths(
        Paths.get(Resources.getResource("foo.pem").getPath()),
        Paths.get(Resources.getResource("UIDCACert.key").getPath())
    );
  }

}
