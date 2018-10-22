package controllers

import java.net.URL
import javax.inject.Inject

import com.github.nscala_time.time.Imports._
import com.ysoft.odc.SecureXml
import modules.TemplateCustomization
import org.joda.time.DateTime
import play.api.Configuration
import play.api.i18n.MessagesApi
import play.api.mvc.{Action, AnyContent, Result}
import play.twirl.api.Html
import services.{DependencyNotFoundException, OdcDbService, OdcService, SingleLibraryScanResult}
import views.html.DefaultRequest

import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try

class LibraryAdvisor @Inject() (
                      config: Configuration,
                      odcServiceOption: Option[OdcService],
                      odcDbService: OdcDbService,
                      val messagesApi: MessagesApi,
                      val env: AuthEnv,
                      val templateCustomization: TemplateCustomization
                    ) (implicit ec: ExecutionContext) extends AuthenticatedController
{

  import secureRequestConversion._

  private def withOdc(f: OdcService => Future[Result])(implicit defaultRequest: DefaultRequest) = {
    odcServiceOption.fold(Future.successful(InternalServerError(views.html.libraryAdvisor.notEnabled())))(odcService =>
      f(odcService)
    )
  }

  private val InputParsers = Seq[(OdcService, String) => Option[Either[Future[SingleLibraryScanResult], String]]](
    (odcService, xmlString) => {
      val triedElem = Try {
        SecureXml.loadString(xmlString)
      }
      triedElem.toOption.map{ xml =>
        xml.label match {
          case "dependency" =>
            /*
            Maven POM, e.g.:
            <dependency>
                <groupId>com.google.code.gson</groupId>
                <artifactId>gson</artifactId>
                <version>2.3.1</version>
            </dependency>
            */
            val groupId = (xml \ "groupId").text
            val artifactId = (xml \ "artifactId").text
            val version = (xml \ "version").text
            val depType = (xml \ "type").text
            Left(odcService.scanMaven(groupId, artifactId, version, depType))
          case other =>
            Right(s"Unknown root XML element: $other")
        }
      }
    },
    (odcService, urlString) => {
      Try{new URL(urlString)}.toOption.map{url =>
        url.getHost match {
          case "www.mvnrepository.com" | "mvnrepository.com" =>
            // https://www.mvnrepository.com/artifact/ch.qos.logback/logback-classic/0.9.10
            // https://mvnrepository.com/artifact/ch.qos.logback/logback-classic/0.9.10
            url.getPath.split('/') match {
              case Array("", "artifact", groupId, artifactId, version) =>
                Left(odcService.scanMaven(groupId, artifactId, version, ""))
              case _ =>
                Right("Unknown path for mvnrepository.com: Expected https://mvnrepository.com/artifact/<groupId>/<artifactId>/<version>")
            }
          case "www.nuget.org" | "preview.nuget.org" =>
            // https://www.nuget.org/packages/Newtonsoft.Json/9.0.1
            url.getPath.split('/') match {
              case Array("", "packages", packageName, version) => Left(odcService.scanDotNet(packageName, version))
              case _ => Right("Unknown path for nuget.org: Expected https://www.nuget.org/packages/<package>/<version>")
            }
          case otherHost => Right(s"Unknown host – there is no rule how to get library identification from its path: $otherHost")
        }
      }
    }
  )

  def index(dependency: Option[String]): Action[AnyContent] = ReadAction.async{ implicit req =>
    withOdc{ odcService =>
      Future.successful(Ok(views.html.libraryAdvisor.scanLibrary(dependency, Seq(
        Html("&lt;dependency>…&lt;/dependency> – Maven POM format"),
        Html("https://mvnrepository.com/artifact/<i>groupId</i>/<i>artifactId</i>/<i>version</i>"),
        Html("https://www.nuget.org/packages/<i>package</i>/<i>version</i>")
      ))))
    }
  }

  //noinspection TypeAnnotation
  def scan() = ReadAction.async(parse.json[String]){ implicit req =>
    withOdc{ odcService =>
      val now = DateTime.now()

      val oldDataThreshold = 2.days
      val lastDbUpdateFuture = odcDbService.loadLastDbUpdate()
      val isOldFuture = lastDbUpdateFuture.map{ lastUpdate => now - oldDataThreshold > lastUpdate}

      val response = InputParsers.toStream.map(_(odcService, req.body)).find(_.nonEmpty).flatten match{
        case None => Future.successful(Ok(views.html.libraryAdvisor.scanInputError("Unknown input format")))
        case Some(Right(message)) => Future.successful(Ok(views.html.libraryAdvisor.scanInputError(s"Unknown input format: $message")))
        case Some(Left(resFuture)) =>
          for{
            res <- resFuture
            isOld <- isOldFuture
          } yield Ok(views.html.libraryAdvisor.scanResults(isOld, res))
      }
      response.recover{
        case DependencyNotFoundException(dependency) =>
          NotFound(views.html.libraryAdvisor.notFound(dependency))
      }.map { _.withHeaders("Content-type" -> "text/plain; charset=utf-8")}
    }
  }

}
