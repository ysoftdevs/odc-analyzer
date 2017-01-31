package controllers.api

class AuthenticatedApiApplication(resources: Set[ApiResource]) {
  def isAllowed(resource: ApiResource): Boolean = resources contains resource
}
