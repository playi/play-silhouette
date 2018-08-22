/**
 * Original work: SecureSocial (https://github.com/jaliss/securesocial)
 * Copyright 2013 Jorge Aliss (jaliss at gmail dot com) - twitter: @jaliss
 *
 * Derivative work: Silhouette (https://github.com/mohiva/play-silhouette)
 * Modifications Copyright 2015 Mohiva Organisation (license at mohiva dot com)
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
package com.mohiva.play.silhouette.impl.providers.oauth2

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.api.util.HTTPLayer
import com.mohiva.play.silhouette.impl.exceptions.ProfileRetrievalException
import com.mohiva.play.silhouette.impl.providers._
import com.mohiva.play.silhouette.impl.providers.oauth2.MicrosoftProvider._
import play.api.http.HeaderNames
import play.api.libs.json.{ JsObject, JsValue }

import scala.concurrent.Future

/**
 * Base Microsoft OAuth2 Provider.
 *
 * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/azure-ad-developers-guide
 * @see https://msdn.microsoft.com/Library/Azure/Ad/Graph/api/signed-in-user-operations
 * @see https://apps.dev.microsoft.com/#/appList (your list of apps)
 */
trait BaseMicrosoftProvider extends OAuth2Provider {

  /**
   * The content type to parse a profile from.
   */
  override type Content = JsValue

  /**
   * The provider ID.
   */
  override val id = ID

  /**
   * Defines the URLs that are needed to retrieve the profile data.
   */
  override protected val urls = Map("api" -> settings.apiURL.getOrElse(API))

  /**
   * Builds the social profile.
   *
   * @param authInfo The auth info received from the provider.
   * @return On success the build social profile, otherwise a failure.
   */
  override protected def buildProfile(authInfo: OAuth2Info): Future[Profile] = {
    httpLayer.url(urls("api").format(authInfo.accessToken))
      .addHttpHeaders(HeaderNames.AUTHORIZATION -> authInfo.accessToken).get()
      .flatMap { response =>
        val json = response.json
        (json \ "error").asOpt[JsObject] match {
          case Some(error) =>
            val errorCode = (error \ "code").as[Int]
            val errorMsg = (error \ "message").as[String]

            throw new ProfileRetrievalException(SpecifiedProfileError.format(id, errorCode, errorMsg))
          case _ => profileParser.parse(json, authInfo)
        }
      }
  }
}

/**
 * The profile parser for the common social profile.
 */
class MicrosoftProfileParser extends SocialProfileParser[JsValue, CommonSocialProfile, OAuth2Info] {

  /**
   * Parses the social profile.
   *
   * @param json     The content returned from the provider.
   * @param authInfo The auth info to query the provider again for additional data.
   * @return The social profile from given result.
   */
  override def parse(json: JsValue, authInfo: OAuth2Info) = Future.successful {
    val userID = (json \ "id").as[String]

    CommonSocialProfile(
      loginInfo = LoginInfo(ID, userID),
      firstName = (json \ "givenName").asOpt[String],
      lastName = (json \ "surname").asOpt[String],
      email = (json \ "userPrincipalName").asOpt[String]
    )
  }
}

/**
 * The Microsoft OAuth2 Provider.
 *
 * @param httpLayer     The HTTP layer implementation.
 * @param stateHandler  The state provider implementation.
 * @param settings      The provider settings.
 */
class MicrosoftProvider(
  protected val httpLayer: HTTPLayer,
  protected val stateHandler: SocialStateHandler,
  val settings: OAuth2Settings)
  extends BaseMicrosoftProvider with CommonSocialProfileBuilder {

  /**
   * The type of this class.
   */
  type Self = MicrosoftProvider

  /**
   * The profile parser implementation.
   */
  val profileParser = new MicrosoftProfileParser

  /**
   * Gets a provider initialized with a new settings object.
   *
   * @param f A function which gets the settings passed and returns different settings.
   * @return An instance of the provider initialized with new settings.
   */
  def withSettings(f: (Settings) => Settings) = new MicrosoftProvider(httpLayer, stateHandler, f(settings))
}

/**
 * The companion object.
 */
object MicrosoftProvider {

  /**
   * The error messages.
   */
  val SpecifiedProfileError = "[Silhouette][%s] Error retrieving profile information. Error code: %s, message: %s"

  /**
   * The Microsoft constants.
   */
  val ID = "microsoft"
  val API = "https://graph.microsoft.com/v1.0/me?access_token=%s"
}
