import javax.inject.Inject

import play.api._
import play.api.http.HttpFilters
import play.api.libs.iteratee.{Done, Iteratee}
import play.api.mvc._
import play.filters.csrf.CSRFFilter
import play.twirl.api.Txt

import scala.concurrent.Future

class HostValidatingAction(allowedHosts: Set[String], allowAllIps: Boolean, next: EssentialAction) extends EssentialAction with Results{

  private val IpAddressPatternComponent = // comes from http://www.mkyong.com/regular-expressions/how-to-validate-ip-address-with-regular-expression/
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
    "([01]?\\d\\d?|2[0-4]\\d|25[0-5])"

  private val IpAddress = ("""^"""+IpAddressPatternComponent+"""((:[0-9]+)?)$""").r

  override def apply(request: RequestHeader): Iteratee[Array[Byte], Result] = {
    if( (allowedHosts contains request.host) || (allowAllIps && IpAddress.findFirstMatchIn(request.host).isDefined )) next.apply(request)
    else Iteratee.flatten(Future.successful(Done(Unauthorized(Txt(s"not allowed for host ${request.host}")))))
  }

}


class HostFilter(allowedHosts: Set[String], allowAllIps: Boolean = false) extends EssentialFilter {
  override def apply(next: EssentialAction): EssentialAction = new HostValidatingAction(allowedHosts, allowAllIps, next)
}

class Filters @Inject() (csrfFilter: CSRFFilter, configuration: Configuration) extends HttpFilters {
  def filters = Seq(csrfFilter, new HostFilter(configuration.getString("app.host").toSet, allowAllIps = true))
}