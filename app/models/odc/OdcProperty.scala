package models.odc
import models.odc.profile.api._

final case class OdcProperty (id: String, value: String)

final class OdcProperties(tag: Tag) extends Table[OdcProperty](tag, "properties"){
  def id = column[String]("id")
  def value = column[String]("value")

  def * = (id, value) <> (OdcProperty.tupled, OdcProperty.unapply)
}