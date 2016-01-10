package com.ysoft.odc
import scala.concurrent.Future

/**
 * Created by user on 10/30/15.
 */
trait Downloader {

  def downloadProjectReports(projects: Set[String], requiredVersions: Map[String, Int]): Future[(Map[String, (Build, ArtifactItem, ArtifactFile)], Map[String, Throwable])]
}
