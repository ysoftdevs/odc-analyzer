package models

import scala.concurrent.duration._

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.profile.MappedJdbcType
import models.jodaSupport._
import models.profile.api._
import org.joda.time.DateTime
import slick.lifted.{ProvenShape, Tag}

import scala.concurrent.duration.FiniteDuration


class CookieAuthenticators(tag: Tag) extends Table[CookieAuthenticator](tag, "cookie_authenticators") {

  private implicit val FiniteDurationType = MappedJdbcType.base[FiniteDuration, Long](_.toSeconds, FiniteDuration.apply(_, SECONDS))

  def id = column[String]("id")
  def providerId = column[String]("provider_id")
  def providerKey = column[String]("provider_key")
  def lastUsedDateTime = column[DateTime]("last_used")
  def expirationDateTime = column[DateTime]("expiration")
  def idleTimeout = column[FiniteDuration]("idle_timeout").?
  def cookieMaxAge = column[FiniteDuration]("cookie_max_age").?
  def fingerprint = column[String]("fingerprint").?

  def loginInfo = (providerId, providerKey) <> (LoginInfo.tupled, LoginInfo.unapply)

  override def * : ProvenShape[CookieAuthenticator] = (id, loginInfo, lastUsedDateTime, expirationDateTime, idleTimeout, cookieMaxAge, fingerprint) <> ((CookieAuthenticator.apply _).tupled, CookieAuthenticator.unapply)

}
