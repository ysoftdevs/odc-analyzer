package controllers.api


class ApiConfig(applications: Map[String, ApiApplication]){
  def getApplication(appName: String, appToken: String): Option[AuthenticatedApiApplication] = for{
    app <- applications.get(appName)
    authenticatedApp <- app.authenticate(appToken)
  } yield authenticatedApp
}
