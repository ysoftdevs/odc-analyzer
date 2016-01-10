package services

import javax.inject.Inject

import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import com.mohiva.play.silhouette.impl.daos.AuthenticatorDAO
import play.api.db.slick.{HasDatabaseConfigProvider, DatabaseConfigProvider}
import models.tables._

import scala.concurrent.{Future, ExecutionContext}


class TokenService @Inject() (protected val dbConfigProvider: DatabaseConfigProvider)(implicit executionContext: ExecutionContext)
  extends AuthenticatorDAO[CookieAuthenticator]
  with HasDatabaseConfigProvider[models.profile.type]{
  import dbConfig.driver.api._

  println(authTokens.schema.create.statements.toIndexedSeq)

  override def find(id: String): Future[Option[CookieAuthenticator]] = {
    db.run(authTokens.filter(_.id === id).result).map{_.headOption}
  }

  override def add(authenticator: CookieAuthenticator): Future[CookieAuthenticator] = {
    db.run(authTokens += authenticator).map(_ => authenticator)
  }

  override def remove(id: String): Future[Unit] = {
    db.run(authTokens.filter(_.id === id).delete).map(_ => ())
  }

  override def update(authenticator: CookieAuthenticator): Future[CookieAuthenticator] = {
    db.run(authTokens.filter(_.id === authenticator.id).update(authenticator)).map(_ => authenticator)
  }

}
