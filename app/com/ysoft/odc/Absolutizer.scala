package com.ysoft.odc

import play.api.mvc.Call

class Absolutizer(host: String, secure: Boolean){
  def absolutize(call: Call) = call.absoluteURL(secure, host)
}