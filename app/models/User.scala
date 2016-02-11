package models

import com.mohiva.play.silhouette.api.{LoginInfo, Identity}

case class User(username: String) extends Identity{
  def loginInfo = LoginInfo(providerID = "credentials-verification", providerKey = username)
}