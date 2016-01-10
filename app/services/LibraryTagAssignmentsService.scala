package services

import com.google.inject.Inject
import models.tables._
import models.{LibraryTagAssignment, LibraryTagPair}
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}

import scala.concurrent.{ExecutionContext, Future}
class LibraryTagAssignmentsService @Inject() (protected val dbConfigProvider: DatabaseConfigProvider) extends HasDatabaseConfigProvider[models.profile.type]{
  import dbConfig.driver.api._


  def all = db.run(libraryTagAssignments.result): Future[Seq[LibraryTagAssignment]]

  def insert(item: LibraryTagAssignment) = db.run(libraryTagAssignments += item)

  def remove(libraryTagPair: LibraryTagPair) = db.run(
    libraryTagAssignments
      .filter(_.libraryTagId === libraryTagPair.tagId)
      .filter(_.libraryId === libraryTagPair.libraryId)
      .delete
  )

  def forLibraries(libraryIds: Set[Int]): Future[Seq[LibraryTagAssignment]] = db.run(libraryTagAssignments.filter(_.libraryId inSet libraryIds).result)

  def byLibrary(implicit executionContext: ExecutionContext) = all.map(_.groupBy(_.libraryId).withDefaultValue(Seq()))

  def tagsToLibraries(tagAssignmentsFuture: Future[Seq[LibraryTagAssignment]])(implicit executionContext: ExecutionContext): Future[Map[Int, Set[LibraryTagAssignment]]] =
    tagAssignmentsFuture.map(x => tagsToLibraries(x))

  def tagsToLibraries(tagAssignments: Seq[LibraryTagAssignment]): Map[Int, Set[LibraryTagAssignment]] = tagAssignments.groupBy(_.tagId).mapValues(_.toSet).map(identity).withDefaultValue(Set.empty)


}
