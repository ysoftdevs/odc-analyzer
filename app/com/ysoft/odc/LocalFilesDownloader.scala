package com.ysoft.odc

import javax.inject.Named

import com.google.inject.Inject

import scala.concurrent.Future

class LocalFilesDownloader @Inject() (@Named("reports-path") path: String) extends Downloader{
  override def downloadProjectReports(projects: Set[String], requiredVersions: Map[String, Int]): Future[(Map[String, (Build, ArtifactItem, ArtifactFile)], Map[String, Throwable])] = {
    if(requiredVersions != Map()){
      sys.error("Versions are not supported there")
    }
    projects.map{pn => ???}
    ???
  }
}
