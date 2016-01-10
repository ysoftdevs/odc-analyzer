package models

import models.profile.api._
import slick.lifted.Tag

final case class LibraryTag (name: String, note: Option[String], warningOrder: Option[Int])

class LibraryTags(tag: Tag) extends Table[(Int, LibraryTag)](tag, "library_tag") {
  def id = column[Int]("id", O.PrimaryKey)
  def name = column[String]("name")
  def note = column[Option[String]]("note")
  def warningOrder = column[Option[Int]]("warning_order")

  def base = (name, note, warningOrder) <> (LibraryTag.tupled, LibraryTag.unapply)
  def * = (id, base)
}