package services

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.api.services.IdentityService
import com.mohiva.play.silhouette.api.util.PasswordInfo
import com.mohiva.play.silhouette.impl.daos.DelegableAuthInfoDAO
import models.User

import scala.concurrent.Future

class UserService extends DelegableAuthInfoDAO[PasswordInfo] with IdentityService[User]
{
  override def retrieve(loginInfo: LoginInfo): Future[Option[User]] = if(loginInfo.providerID == "credentials-verification") Future.successful(Some(User(loginInfo.providerKey))) else Future.successful(None)

  override def find(loginInfo: LoginInfo): Future[Option[PasswordInfo]] = {
    println(s"loginInfo: $loginInfo")

    ???
  }

  override def update(loginInfo: LoginInfo, authInfo: PasswordInfo): Future[PasswordInfo] = ???

  override def remove(loginInfo: LoginInfo): Future[Unit] = ???

  override def save(loginInfo: LoginInfo, authInfo: PasswordInfo): Future[PasswordInfo] = ???

  override def add(loginInfo: LoginInfo, authInfo: PasswordInfo): Future[PasswordInfo] = ???

}
