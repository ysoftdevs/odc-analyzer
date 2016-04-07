package com.ysoft.odc

import com.google.inject.Inject
import com.google.inject.name.Named
import org.ccil.cowan.tagsoup.jaxp.SAXFactoryImpl
import play.api.libs.ws.{WS, WSClient}
import upickle.default._

import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}
import scala.xml.Node

final case class Link(
  href: String,
  rel: String
)

final case class Artifact(
  name: String,
  link: Link
  //size: Option[Long]
){
  def url: String = link.href
}

final case class Artifacts(
  size: Int,
  //`start-index`: Int,
  //`max-result`: Int
  artifact: Seq[Artifact]
)

final case class Build(
  state: String,
  //link: Link,
  buildResultKey: String,
  buildState: String,
  projectName: String,
  artifacts: Artifacts
) {
  def resultLink(urlBase: String): String = s"$urlBase/browse/$buildResultKey/log"
}
sealed trait FlatArtifactItem{
  def name: String
}
abstract sealed class ArtifactItem{
  def name: String
  final def flatFiles: Map[String, Array[Byte]] = flatFilesWithPrefix("")
  def flatFilesWithPrefix(prefix: String): Map[String, Array[Byte]]
  def toTree(indent: Int = 0): String
  def toTree: String = toTree(0)
}
final case class ArtifactFile(name: String, data: Array[Byte]) extends ArtifactItem with FlatArtifactItem{
  override def toTree(indent: Int): String = " "*indent + s"$name = $data"
  override def flatFilesWithPrefix(prefix: String): Map[String, Array[Byte]] = Map(prefix + name -> data)
  def dataString = new String(data, "utf-8")
}
final case class ArtifactDirectory(name: String, items: Map[String, ArtifactItem]) extends ArtifactItem{
  override def toTree(indent: Int): String = " "*indent + s"$name:\n"+items.values.map(_.toTree(indent+2)).mkString("\n")
  override def flatFilesWithPrefix(prefix: String): Map[String, Array[Byte]] = items.values.flatMap(_.flatFilesWithPrefix(s"$prefix$name/")).toMap
}
final case class FlatArtifactDirectory(name: String, items: Seq[(String, String)]) extends FlatArtifactItem{}


final class BambooDownloader @Inject()(@Named("bamboo-server-url") val server: String, @Named("bamboo-authentication") auth: AtlassianAuthentication)(implicit executionContext: ExecutionContext, wSClient: WSClient) extends Downloader {

  private object ArtifactKeys{
    val BuildLog = "Build log"
    val ResultsHtml = "Report results-HTML"
    val ResultsXml = "Report results-XML"
  }

  private def downloadArtifact(artifactMap: Map[String, Artifact], key: String)(implicit wSClient: WSClient): Future[FlatArtifactItem] = {
    val artifact = artifactMap(key)
    downloadArtifact(artifact.url, artifact.name)
  }

  private def downloadArtifact(url: String, name: String)(implicit wSClient: WSClient): Future[FlatArtifactItem] = {
    bambooUrl(url).get().map{response =>
      response.header("Content-Disposition") match{
        case Some(_) => ArtifactFile(name = name, data = response.bodyAsBytes)
        case None =>
          val html = response.body
          val hpf = new SAXFactoryImpl
          hpf.setFeature("http://xml.org/sax/features/external-general-entities", false)
          //hpf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
          hpf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
          val HtmlParser = hpf.newSAXParser()
          val Html = scala.xml.XML.withSAXParser(HtmlParser)
          val xml = Html.loadString(html)
          val tds = xml \\ "td"
          val subdirs = tds flatMap { td =>
            (td \ "img").headOption.flatMap{img =>
              val suffix = img.attribute("alt").map(_.text) match { // suffix seems to be no longer needed, as we recognize directories elsehow
                case Some("(dir)") => "/"
                case Some("(file)") => ""
                case other => sys.error(s"unexpected directory item type: $other")
              }
              (td \ "a").headOption.map{ link =>
                val hrefAttribute: Option[Seq[Node]] = link.attribute("href")
                link.text -> (hrefAttribute.getOrElse(sys.error(s"bad link $link at $url")).text+suffix) : (String, String)
              } : Option[(String, String)]
            } : Option[(String, String)]
          }
          FlatArtifactDirectory(name = name, items = subdirs)
      }
    }
  }

  private def downloadArtifactRecursively(artifactMap: Map[String, Artifact], key: String)(implicit wSClient: WSClient): Future[ArtifactItem] = {
    val artifact = artifactMap(key)
    downloadArtifactRecursively(url = artifact.url, name = artifact.name)
  }

  private def downloadArtifactRecursively(url: String, name: String/*artifactMap: Map[String, Artifact], key: String*/)(implicit wSClient: WSClient): Future[ArtifactItem] = {
    downloadArtifact(url/*artifactMap, key*/, name).flatMap{
      case directoryStructure: FlatArtifactDirectory =>
        Future.traverse(directoryStructure.items){case (subName, urlString) =>
          downloadArtifactRecursively(server+urlString, subName)
        }.map{ items =>
          ArtifactDirectory(name = directoryStructure.name, items = items.map(i => i.name->i).toMap)
        }
      case file: ArtifactFile => Future.successful(file)
    }
  }

  override def downloadProjectReports(projects: Set[String], requiredVersions: Map[String, Int]): Future[(Map[String, (Build, ArtifactItem, ArtifactFile)], Map[String, Throwable])] = {
    val resultsFuture = Future.traverse(projects){project =>
      downloadProjectReport(project, requiredVersions.get(project))
    }
    resultsFuture.map{ originalResults =>
      val buildFailureFilteredResults = originalResults.map{case (name, resultTry) =>
        name -> resultTry.flatMap{ case result @ (build, _, _) =>
          // Note that this is triggered only if the artifact directory exists.
          // If it does not, it will throw “java.util.NoSuchElementException: key not found: Report results-XML” instead.
          if (build.state != "Successful" || build.buildState != "Successful") Failure(new RuntimeException("failed build"))
          else Success(result)
        }
      }
      val (successfulReportTries, failedReportTries) = buildFailureFilteredResults.partition(_._2.isSuccess)
      val successfulReports = successfulReportTries.map{case (name, Success(data)) => name -> data; case _ => ???}.toMap
      val failedReports = failedReportTries.map{case (name, Failure(data)) => name -> data; case _ => ???}.toMap
      (successfulReports, failedReports)
    }
  }

  private def bambooUrl(url: String) = auth.addAuth(WS.clientUrl(url))

  private def downloadProjectReport(project: String, versionOption: Option[Int]): Future[(String, Try[(Build, ArtifactItem, ArtifactFile)])] = {
    val url = s"$server/rest/api/latest/result/$project-${versionOption.getOrElse("latest")}.json?expand=artifacts"
    val resultFuture = (bambooUrl(url).get().flatMap { response =>
      val build = read[Build](response.body)
      val artifactMap: Map[String, Artifact] = build.artifacts.artifact.map(x => x.name -> x).toMap
      val logFuture = downloadArtifact(artifactMap, ArtifactKeys.BuildLog).map(_.asInstanceOf[ArtifactFile])
      val reportsFuture: Future[ArtifactItem] = downloadArtifactRecursively(artifactMap, ArtifactKeys.ResultsXml)
      for {
        log <- logFuture
        reports <- reportsFuture
      } yield (build, reports, log)
    }: Future[(Build, ArtifactItem, ArtifactFile)])
    resultFuture.map(data => project -> Success(data)).recover{case e => project -> Failure(e)}
  }
}
