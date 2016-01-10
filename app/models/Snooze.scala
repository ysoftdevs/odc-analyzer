package models

import models.jodaSupport._
import models.profile.api._
import org.joda.time.LocalDate
import play.api.data.Form
import slick.lifted.Tag

case class Snooze(until: LocalDate, snoozedObjectId: String, reason: String)

case class ObjectSnooze(until: LocalDate, reason: String){
  def toSnooze(objectId: String) = Snooze(until, objectId, reason)
}

class Snoozes(tag: Tag) extends Table[(Int, Snooze)](tag, "snooze") {
  def id = column[Int]("id", O.PrimaryKey)
  def until = column[LocalDate]("until")
  def snoozedObjectId = column[String]("snoozed_object_identifier")
  def reason = column[String]("reason")
  def base = (until, snoozedObjectId, reason) <> (Snooze.tupled, Snooze.unapply)
  def * = (id, base)
}

case class SnoozeInfo(form: Form[ObjectSnooze], snoozes: Seq[(Int, Snooze)]){
  def shouldCollapse(default: Boolean) = {
    shouldExpandForm match {
      case true => false
      case false =>
        isSnoozed match {
          case true => true
          case false => default
        }
    }
  }

  def isSnoozed = snoozes.nonEmpty

  def shouldExpandForm = form.hasErrors || form.hasGlobalErrors

  def adjustForm(f: Form[ObjectSnooze] => Form[ObjectSnooze]): SnoozeInfo = copy(form = f(form))

  def adjustSnoozes(f: Seq[(Int, Snooze)] => Seq[(Int, Snooze)]): SnoozeInfo = copy(snoozes = f(snoozes))

}