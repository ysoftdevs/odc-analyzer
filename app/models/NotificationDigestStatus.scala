package models

import com.mohiva.play.silhouette.api.LoginInfo
import models.profile.api._
import slick.lifted.Tag

case class NotificationDigestStatus(user: LoginInfo, lastChangelogIdOption: Option[Int])


class NotificationDigestStatuses(tag: Tag) extends Table[NotificationDigestStatus](tag, "notification_digest_status"){
  val user = new LoginInfoColumns("user", this)
  def lastChangelogId = column[Int]("last_changelog_id").?
  def * = (user(), lastChangelogId) <> (NotificationDigestStatus.tupled, NotificationDigestStatus.unapply)
  def idx = index("notification_digest_status_user_idx", user(), unique = true)
}
