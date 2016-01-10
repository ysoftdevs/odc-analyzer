package models.odc

import com.ysoft.odc.Reference
import models.odc
import models.odc.profile.MappedJdbcType
import models.odc.profile.api._
import slick.lifted.Tag

class References (tag: Tag) extends Table[(Int, Reference)](tag, "reference") {
  def cveId = column[Int]("cveid")
  def name = column[String]("name")
  def url = column[String]("url")
  def source = column[String]("source")

  def base = (source, url, name) <>  (Reference.tupled, Reference.unapply)
  def * = (cveId, base)
}
