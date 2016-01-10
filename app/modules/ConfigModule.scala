package modules

import java.io._
import java.net.URLEncoder
import java.nio.file.{Files, Path, Paths}

import akka.util.ClassLoaderObjectInputStream
import com.ysoft.odc._
import controllers.MissingGavExclusions
import play.api.cache.CacheApi
import play.api.inject.{Binding, Module}
import play.api.{Configuration, Environment, Logger}

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
  * @param path
  */
class FileCacheApi(path: Path) extends CacheApi{
  private def cacheFile(name: String) = path.resolve("X-"+URLEncoder.encode(name, "utf-8"))
  override def remove(key: String): Unit = Files.deleteIfExists(cacheFile(key))

  private def serialize(value: Any, duration: Duration) = {
    val out = new ByteArrayOutputStream()
    import com.github.nscala_time.time.Imports._
    new ObjectOutputStream(out).writeObject((value, if(duration.isFinite()) Some(DateTime.now.plus(duration.toMillis)) else None))
    out.toByteArray
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
    Files.write(cacheFile(key), serialize(value, expiration))
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
  
  override def bindings(environment: Environment, configuration: Configuration): Seq[Binding[_]] = Seq(
    bind[String].qualifiedWith("bamboo-server-url").toInstance(configuration.getString("yssdc.bamboo.url").getOrElse(sys.error("Key yssdc.bamboo.url is not set"))),
    configuration.getString("yssdc.reports.provider") match{
      case Some("bamboo") => bind[Downloader].to[BambooDownloader]
      // not ready yet: case Some("files") => bind[Downloader].to[LocalFilesDownloader]
      case other => sys.error(s"unknown provider: $other")
    },
    bind[MissingGavExclusions].qualifiedWith("missing-GAV-exclusions").toInstance(MissingGavExclusions(
      configuration.getStringSeq("yssdc.exclusions.missingGAV.bySha1").getOrElse(Seq()).toSet.map(Exclusion))
    )
  ) ++
    configuration.getString("play.cache.path").map(cachePath => bind[CacheApi].toInstance(new FileCacheApi(Paths.get(cachePath)))) ++
    configuration.getString("yssdc.reports.bamboo.sessionId").map{s => bind[BambooAuthentication].toInstance(new SessionIdBambooAuthentication(s))} ++
    configuration.getString("yssdc.reports.bamboo.user").map{u => bind[BambooAuthentication].toInstance(new CredentialsBambooAuthentication(u, configuration.getString("yssdc.reports.bamboo.password").get))} ++
    configuration.getString("yssdc.reports.path").map{s => bind[String].qualifiedWith("reports-path").toInstance(s)}

}
