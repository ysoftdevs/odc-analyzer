package modules

import java.io._
import java.net.URLEncoder
import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.Executors

import akka.util.ClassLoaderObjectInputStream
import com.typesafe.config.{Config, ConfigObject, ConfigValue}
import com.ysoft.odc._
import controllers.api._
import controllers.{MissingGavExclusions, Projects, TeamId, WarningSeverity}
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import play.api.cache.CacheApi
import play.api.inject.{Binding, Module}
import play.api.{Configuration, Environment, Logger}
import services.IssueTrackerService

import scala.collection.mutable
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.Duration
import scala.reflect.ClassTag
import scala.util.{Failure, Success, Try}

/**
  * This class is rather a temporary hack and should be replaced by something better.
  *
  * Issues:
  * * Thread safety
  * * fsync: https://stackoverflow.com/questions/4072878/i-o-concept-flush-vs-sync
  * * probably not removing files that are not used for a long time
  *
  * @param path
  */
class FileCacheApi(path: Path) extends CacheApi{
  private def cacheFile(name: String) = path.resolve("X-"+URLEncoder.encode(name, "utf-8"))
  override def remove(key: String): Unit = Files.deleteIfExists(cacheFile(key))

  private def serialize(out: ObjectOutputStream, value: Any, duration: Duration) = {
    import com.github.nscala_time.time.Imports._
    out.writeObject((value, if(duration.isFinite()) Some(DateTime.now.plus(duration.toMillis)) else None))
  }

  private def unserialize[T](data: Array[Byte]): Try[T] = {
    val in = new ByteArrayInputStream(data)
    import com.github.nscala_time.time.Imports._
    try{
      new ClassLoaderObjectInputStream(this.getClass.getClassLoader, in).readObject() match {
        case (value, None) => Success(value.asInstanceOf[T])
        case (value, Some(exp: DateTime)) if exp < DateTime.now => Success(value.asInstanceOf[T])
        case _ => Failure(new RuntimeException("cache expired"))
      }
    }catch{
      case e: ObjectStreamException => Failure(e)
    }
  }

  override def set(key: String, value: Any, expiration: Duration): Unit = {
    for(out <- resource.managed(new ObjectOutputStream(new FileOutputStream(cacheFile(key).toFile)))){
      serialize(out, value, expiration)
    }
  }

  override def get[T: ClassTag](key: String): Option[T] = {
    val f = cacheFile(key)
    if(Files.exists(f)){
      val res = unserialize[T](Files.readAllBytes(f))
      res match {
        case Failure(e) =>
          Logger.warn("not using cache for following key, removing that: "+key, e)
          remove(key)
        case Success(_) => // nothing to do
      }
      res.toOption
    }else{
      None
    }
  }

  override def getOrElse[A: ClassTag](key: String, expiration: Duration)(orElse: => A): A = get(key).getOrElse{
    val v = orElse
    set(key, v, expiration)
    v
  }

}


class ConfigModule extends Module {

  private val bambooAuthentication = bind[AtlassianAuthentication].qualifiedWith("bamboo-authentication")
  //private val jiraAuthentication = bind[AtlassianAuthentication].qualifiedWith("jira-authentication")

  private def parseProjects(configuration: Configuration): Projects = {
    import scala.collection.JavaConversions._
    val teamLeaders = configuration.getObject("yssdc.teamLeaders").getOrElse(sys.error("yssdc.teamLeaders is not set")).map { case (k, v) =>
      TeamId(k) -> v.unwrapped().asInstanceOf[String]
    }.toMap // Calling .toMap is needed for immutable Map.
    val teamIdSet = configuration.getStringSeq("yssdc.teams").getOrElse(sys.error("yssdc.teams is not set")).map(TeamId).toSet
    val teamsByIds = teamIdSet.map(t => t.id -> t).toMap
    val extraTeams = teamLeaders.keySet -- teamIdSet
    if(extraTeams.nonEmpty){
      sys.error(s"Some unexpected teams: $extraTeams")
    }
    def existingTeamId(s: String): TeamId = teamsByIds(s)
    new Projects(
      projectMap = {
        val projectsConfig = configuration.getObject("yssdc.projects").getOrElse(sys.error("yssdc.projects is not set")).toConfig
        projectsConfig.entrySet().map( k => k.getKey -> projectsConfig.getString(k.getKey)).toMap
      },
      teamLeaders = teamLeaders,
      projectToTeams = configuration.getObject("yssdc.projectsToTeams").get.mapValues{_.unwrapped().asInstanceOf[java.util.List[String]].map(c =>
        existingTeamId(c)
      ).toSet}.toMap.map(identity) // Calling .toMap is needed for immutable Map.
    )
  }

  private def parseApiApplication(value: Config): ApiApplication = {
    import scala.collection.JavaConversions._
    val authenticatedApiApplication = new AuthenticatedApiApplication(
      value.getStringList("resources").map(resName =>
        ApiResources.byName(resName).getOrElse(sys.error(s"unknown resource $resName"))
      ).toSet)
    value.getString("tokenType") match {
      case "plain" => new ApiApplication.Plain(value.getString("token"), authenticatedApiApplication)
    }
  }

  private def parseApiConfig(configuration: Configuration): ApiConfig = {
    import scala.collection.JavaConversions._
    new ApiConfig(
      configuration.getObject("yssdc.api.apps") match {
        case None => Map.empty[String, ApiApplication]
        case Some(obj) => Map(
          (
            for{
              (key, value) <- obj
            } yield key -> parseApiApplication(value.asInstanceOf[ConfigObject].toConfig)
          ).toSeq: _*
        )
      }
    )
  }

  override def bindings(environment: Environment, configuration: Configuration): Seq[Binding[_]] = Seq(
    bind[String].qualifiedWith("bamboo-server-url").toInstance(configuration.getString("yssdc.bamboo.url").getOrElse(sys.error("Key yssdc.bamboo.url is not set"))),
    configuration.getString("yssdc.reports.provider") match{
      case Some("bamboo") => bind[Downloader].to[BambooDownloader]
      // not ready yet: case Some("files") => bind[Downloader].to[LocalFilesDownloader]
      case other => sys.error(s"unknown provider: $other")
    },
    bind[MissingGavExclusions].qualifiedWith("missing-GAV-exclusions").toInstance(MissingGavExclusions(
      configuration.getStringSeq("yssdc.exclusions.missingGAV.bySha1").getOrElse(Seq()).toSet.map(Exclusion))
    ),
    bind[ExecutionContext].qualifiedWith("email-sending").toInstance(ExecutionContext.fromExecutor(Executors.newSingleThreadExecutor())),
    bind[LogSmellChecks].qualifiedWith("log-smells").toInstance(LogSmellChecks(configuration.underlying.getAs[Map[String, LogSmell]]("yssdc.logSmells").getOrElse(Map()))),
    bind[Projects].to(parseProjects(configuration)),
    bind[ApiConfig].to(parseApiConfig(configuration))
  ) ++
    configuration.underlying.getAs[Absolutizer]("app").map(a => bind[Absolutizer].toInstance(a)) ++
    configuration.getString("play.cache.path").map(cachePath => bind[CacheApi].toInstance(new FileCacheApi(Paths.get(cachePath)))) ++
    configuration.getString("yssdc.reports.bamboo.sessionId").map{s => bambooAuthentication.toInstance(new SessionIdAtlassianAuthentication(s))} ++
    configuration.getString("yssdc.reports.bamboo.user").map{u => bambooAuthentication.toInstance(new CredentialsAtlassianAuthentication(u, configuration.getString("yssdc.reports.bamboo.password").get))} ++
    configuration.getString("yssdc.reports.path").map{s => bind[String].qualifiedWith("reports-path").toInstance(s)}

}

case class LogSmellChecks(checks: Map[String, LogSmell])

case class LogSmell(pattern: String, message: String){
  val regex = pattern.r
  def severity = WarningSeverity.Warning
}
