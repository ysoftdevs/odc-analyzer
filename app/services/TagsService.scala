package services

import com.google.inject.Inject
import models._
import models.tables._
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}

import scala.concurrent.{ExecutionContext, Future}

class TagsService @Inject() (protected val dbConfigProvider: DatabaseConfigProvider) extends HasDatabaseConfigProvider[models.profile.type]{
  import dbConfig.driver.api._

  def all: Future[Seq[(Int, LibraryTag)]] = db.run(tags.result)

  def insertMany(newTags: Iterable[LibraryTag]): Future[_] = db.run(tags.map(_.base) ++= newTags)

  def getById(id: Int)(implicit executionContext: ExecutionContext): Future[(Int, LibraryTag)] = db.run(tags.filter(_.id === id).result).map(_.head)

}
