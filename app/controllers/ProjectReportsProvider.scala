package controllers

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.ysoft.odc.Downloader
import play.api.cache.CacheApi

import scala.concurrent.{ExecutionContext, Future}
import scala.reflect.ClassTag
import scala.util.Success

class ProjectReportsProvider @Inject() (
                                         downloader: Downloader,
                                         cache: CacheApi,
                                         projects: Projects
                                         )(implicit executionContext: ExecutionContext){

  private def bambooCacheKey(versions: Map[String, Int]) = "bamboo/results/" + versions.toSeq.sorted.map{case (k, v) => k.getBytes("utf-8").mkString("-") + ":" + v}.mkString("|")

  def purgeCache(versions: Map[String, Int]) = cache.remove(bambooCacheKey(versions))

  private def getOrElseFuture[T: ClassTag]
    (name: String, expiration: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration.Inf)
    (f: => Future[T])
    (implicit executionContext: ExecutionContext): Future[T] =
  {
    cache.get[T](name).map(Future.successful).getOrElse(
      f.map{ value =>
        cache.set(name, value, expiration)
        value
      }
    )
  }

  def resultsForVersions(versions: Map[String, Int]) = {
    def get = {val time = DateTime.now; downloader.downloadProjectReports(projects.projectSet, versions).map(time -> _)}
    val allFuture = getOrElseFuture(bambooCacheKey(versions)){println("CACHE MISS"); get}
    (allFuture.map(_._1), allFuture.map(_._2))
  }

}
