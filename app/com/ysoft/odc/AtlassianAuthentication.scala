package com.ysoft.odc

import play.api.libs.ws.{WSAuthScheme, WSRequest}

trait AtlassianAuthentication{
  def addAuth(request: WSRequest): WSRequest
}

class SessionIdAtlassianAuthentication(sessionId: String) extends AtlassianAuthentication{
  override def addAuth(request: WSRequest): WSRequest = request.withHeaders("Cookie" -> s"JSESSIONID=${sessionId.takeWhile(_.isLetterOrDigit)}")
}

class CredentialsAtlassianAuthentication(user: String, password: String) extends AtlassianAuthentication{
  override def addAuth(request: WSRequest): WSRequest = request.withQueryString("os_authType" -> "basic").withAuth(user, password, WSAuthScheme.BASIC)
}
