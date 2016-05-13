package com.ysoft.odc.statistics

import controllers.ReportInfo

final class FailedProjects(val failedProjectsSet: Set[ReportInfo]){

  val failedProjectIdsSet = failedProjectsSet.map(_.projectId)

  def nonEmpty: Boolean = failedProjectsSet.nonEmpty

  def isFailed(projectFullId: String): Boolean = {
    val projectBareId = projectFullId.takeWhile(_ != '/')
    failedProjectIdsSet contains projectBareId
  }

}

object FailedProjects {
  def combineFails(failedReportDownloads: Map[ReportInfo, Throwable], parsingFailures: Map[ReportInfo, Throwable]): FailedProjects = {
    /*
    Fail can happen at multiple places:
    1. Build cannot be downloaded (auth error, connection error, …) or is failed (failedReportDownloads)
    2. Build is successful and can be downloaded, but it cannot be parsed (parsingFailures)
    */
    val failedProjectsSet = failedReportDownloads.keySet ++ parsingFailures.keySet
    new FailedProjects(failedProjectsSet)
  }
}
