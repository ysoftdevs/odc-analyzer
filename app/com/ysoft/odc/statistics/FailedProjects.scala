package com.ysoft.odc.statistics

import controllers.ReportInfo

final class FailedProjects(val failedProjectsSet: Set[String]){
  def isFailed(projectFullId: String): Boolean = {
    val projectBareId = projectFullId.takeWhile(_ != '/')
    failedProjectsSet contains projectBareId
  }

}

object FailedProjects {
  private[statistics] def combineFails(failedReportDownloads: Map[String, Throwable], parsingFailures: Map[ReportInfo, Throwable]): FailedProjects = {
    /*
    Fail can happen at multiple places:
    1. Build cannot be downloaded (auth error, connection error, …) or is failed (failedReportDownloads)
    2. Build is successful and can be downloaded, but it cannot be parsed (parsingFailures)
    */
    val failedProjectsSet = failedReportDownloads.keySet ++ parsingFailures.keySet.map(_.projectId)
    new FailedProjects(failedProjectsSet)
  }
}
