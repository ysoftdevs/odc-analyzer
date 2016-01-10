package models.odc

import models.odc.profile.api._
import slick.lifted.Tag

final case class CpeEntry(cpe: String, vendor: String, product: String)

class CpeEntries(tag: Tag)  extends Table[(Int, CpeEntry)](tag, "cpeEntry") {

  def id = column[Int]("id", O.PrimaryKey)

  def cpe = column[String]("cpe")
  def vendor = column[String]("vendor")
  def product = column[String]("product")

  def base = (cpe, vendor, product) <> (CpeEntry.tupled, CpeEntry.unapply)

  def * = (id, base)

}
