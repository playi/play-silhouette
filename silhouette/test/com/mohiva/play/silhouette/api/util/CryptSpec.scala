/**
 * Copyright 2015 Mohiva Organisation (license at mohiva dot com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mohiva.play.silhouette.api.util

import play.api.test._

/**
 * Test case for the [[com.mohiva.play.silhouette.api.util.Crypt]] object.
 */
class CryptSpec extends PlaySpecification {

  "The `sha1` method" should {
    "create a SHA1 hash of a string" in {
      Crypt.sha1("SÄÜ%&/($§QW@\\'Ä_:;>|§`´*~") must be equalTo "a87babacb5ef14f1f811527c2028706a55c56be5"
    }
  }
}
