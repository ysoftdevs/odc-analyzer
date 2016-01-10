package services

import com.google.inject.Inject
import models._
import models.tables._
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}

import scala.concurrent.{ExecutionContext, Future}

class LibrariesService @Inject() (protected val dbConfigProvider: DatabaseConfigProvider)(implicit executionContext: ExecutionContext) extends HasDatabaseConfigProvider[models.profile.type]{
  import dbConfig.driver.api._

  def all: Future[Seq[(Int, Library)]] = db.run(libraries.result)

  def allBase: Future[Seq[Library]] = db.run(libraries.map(_.base).result)

  // TODO: unify or differentiate librariesForTags and byTags
  def librariesForTags(tagIds: Iterable[Int]): Future[Seq[(Int, (Int, Library))]] = db.run(
    libraryTagAssignments
      .join(libraries).on { case (a, l) => a.libraryId === l.id }
      .filter { case (a, l) => a.libraryTagId inSet tagIds }
      .map { case (a, l) => a.libraryTagId -> l }
      .result
  )

  def byTags(libraryIds: Set[Int]) = {
    (db.run(
      libraryTagAssignments
        .filter(_.libraryId inSet libraryIds)
        .result
    ): Future[Seq[LibraryTagAssignment]]).map(_.groupBy(_.libraryId).mapValues(_.toSet).map(identity))
  }


  def setClassified(libraryId: Int, classified: Boolean): Future[_] = db.run(libraries.filter(_.id === libraryId).map(_.classified).update(classified))

  def touched(tagIds: Iterable[Int]): Future[Seq[(Int, Library)]] = db.run(libraries.filter(l => l.classified || l.id.inSet(tagIds) ).result)

  def unclassified: Future[Seq[(Int, Library)]] = db.run(libraries.filter(!_.classified).sortBy(l => l.plainLibraryIdentifierUnmapped).result)

  def insert(lib: Library) = db.run(libraries.map(_.base).returning(libraries.map(_.id)) += lib)

  def insertMany(newItems: Iterable[Library]): Future[_] = db.run(libraries.map(_.base) ++= newItems)

  def filtered(requiredClassification: Option[Boolean], requiredTagsOption: Option[Set[Int]]): Query[Libraries, (Int, Library), Seq] = {
    libraries
      .joinLeft(libraryTagAssignments).on { case (l, a) => l.id === a.libraryId }
      .filter { case (l, a) => requiredClassification.map(l.classified === _).getOrElse(l.classified === l.classified) } // classification matches
      .filter { case (l, a) =>
      requiredTagsOption.fold(
        // actually a.isEmpty; The t.isEmpty should work, but there is a bug – it uses (… = 1) on a null value, which has a different semantics in SQL. Related to https://github.com/slick/slick/issues/1156 .
        // So, I created following workaround:
        a.fold(true.asColumnOf[Boolean])(_ => false) // Filter only libraries with no tags (i.e. LEFT JOIN added NULLs (they corresponsd to None value))
      )(requiredTagsSet =>
        if (requiredTagsSet.isEmpty) true.asColumnOf[Boolean] // If we don't filter any by tag, we should allow all
        else a.map(_.libraryTagId inSet requiredTagsSet).getOrElse(false.asColumnOf[Boolean]) // Filter tags
        )
    }
      .groupBy { case (l, a) => l } // a library with multiple tags should be present only once
      .map { case (l, q) => (l, q.size) } // we are not interested in the tags, but only in their count
      .filter { case (l, c) => requiredTagsOption.fold( true.asColumnOf[Boolean] )(requiredTagsSet => c >= requiredTagsSet.size ) } // filter libraries with all the tags we are looking for
      .map { case (l, c) => l } // all is filtered, so we need libraries only
      .sortBy { l => l.plainLibraryIdentifierUnmapped }
  }

  def byPlainLibraryIdentifiers(plainLibraryIdentifiers: Set[PlainLibraryIdentifier]): Future[Map[PlainLibraryIdentifier, (Int, Library)]] = {
    val groupedIdentifiers = plainLibraryIdentifiers.groupBy(_.libraryType).mapValues(_.map(_.libraryIdentifier)).map(identity)
    val resFuture: Future[Seq[(Int, Library)]] = db.run(libraries.filter{l =>
      val conditions = for((libraryType, identifiers) <- groupedIdentifiers) yield l.libraryType === libraryType && l.libraryIdentifier.inSet(identifiers)
      conditions.foldLeft(false.asColumnOf[Boolean])(_ || _)
    }.result)
    resFuture.map(
      //_.toSet.groupBy(_._2.plainLibraryIdentifier)
      _.map(x => x._2.plainLibraryIdentifier -> x).toMap
    )
  }

}
