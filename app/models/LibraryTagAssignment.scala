package models

import models.profile.api._
import slick.lifted.Tag

final case class LibraryTagPair(libraryId: Int, tagId: Int)
final case class LibraryTagAssignment(libraryTagPair: LibraryTagPair, contextDependent: Boolean){
  def libraryId = libraryTagPair.libraryId
  def tagId = libraryTagPair.tagId
}

class LibraryTagAssignments(tag: Tag) extends Table[LibraryTagAssignment](tag, "library_to_library_tag") {
  def libraryId = column[Int]("library_id")
  def libraryTagId = column[Int]("library_tag_id")
  def contextDependent = column[Boolean]("context_dependent")

  def libraryTagPair = (libraryId, libraryTagId) <> (LibraryTagPair.tupled, LibraryTagPair.unapply)
  def * = (libraryTagPair, contextDependent) <> (LibraryTagAssignment.tupled, LibraryTagAssignment.unapply)
}