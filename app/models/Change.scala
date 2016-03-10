package models

import java.time.LocalTime

import models.profile.MappedJdbcType
import models.profile.api._
import models.jodaSupport._
import models.profile.api._
import org.joda.time.{DateTime, LocalDate}
import play.api.data.Form
import slick.lifted.{ProvenShape, Tag}


object Change {
  abstract sealed class Direction private[Change] (private[Change] val description: String)
  object Direction{
    object Added extends Direction("added")
    object Removed extends Direction("removed")
    val All = Set(Added, Removed)
    val ByName = All.map(x => x.description -> x).toMap
    implicit val TypeMapper = MappedJdbcType.base[Direction, String](_.description, ByName)
  }

}

case class Change (time: DateTime, vulnerabilityName: String, projectName: String, direction: Change.Direction, notifiedToSomebody: Boolean)

class Changes(tag: Tag) extends Table[(Int, Change)](tag, "change"){
  def id = column[Int]("id", O.PrimaryKey, O.AutoInc)
  import Change.Direction.TypeMapper
  def time = column[DateTime]("time")
  def vulnerabilityName = column[String]("vulnerability_name")
  def projectName = column[String]("project_name")
  def direction = column[Change.Direction]("direction")
  def notifiedToSomebody = column[Boolean]("notified_to_somebody")

  def base = (time, vulnerabilityName, projectName, direction, notifiedToSomebody) <> ((Change.apply _).tupled, Change.unapply)
  override def * = (id, base)
}