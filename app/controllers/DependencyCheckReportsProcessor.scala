package controllers

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.google.inject.name.Named
import com.ysoft.odc.Checks._
import com.ysoft.odc._
import com.ysoft.odc.statistics.FailedProjects
import modules.{LogSmell, LogSmellChecks}
import org.joda.time.DateTimeConstants
import play.api.Logger
import play.api.i18n.{I18nSupport, MessagesApi}
import play.api.mvc.RequestHeader
import play.twirl.api.{Html, HtmlFormat}
import views.html.DefaultRequest

import scala.concurrent.{ExecutionContext, Future}

final case class MissingGavExclusions(exclusionsSet: Set[Exclusion]){
  def isExcluded(groupedDependency: GroupedDependency) = exclusionsSet.exists(_.matches(groupedDependency))
}

final class DependencyCheckReportsProcessor @Inject() (
                                                  @Named("bamboo-server-url") val server: String,
                                                  dependencyCheckReportsParser: DependencyCheckReportsParser,
                                                  @Named("missing-GAV-exclusions") missingGAVExclusions: MissingGavExclusions,
                                                  @Named("log-smells") logSmells: LogSmellChecks,
                                                  val messagesApi: MessagesApi
                                                  ) extends I18nSupport {

  private def parseDateTime(dt: String): DateTime = {
    if(dt.forall(_.isDigit)){
      new DateTime(dt.toLong)  // TODO: timezone (I don't care much, though)
    }else{
      val formatter = DateTimeFormat.forPattern("dd/MM/yyyy HH:mm:ss") // TODO: timezone (I don't care much, though)
      formatter.parseDateTime(dt)
    }
  }

  @deprecated("use HTML output instead", "SNAPSHOT") private val showDependencies: (Seq[GroupedDependency]) => Seq[String] = {
    _.map { s =>
      s.dependencies.map { case (dep, projects) => s"${dep.fileName} @ ${projects.toSeq.sorted.map(friendlyProjectNameString).mkString(", ")}" }.mkString(", ") + " " + s.hashes
    }
  }

  private def buildLink(reportInfo: ReportInfo): String = s"$server/browse/${reportInfo.projectId}"

  def processResults(
    resultsFuture: Future[(Map[String, (Build, ArtifactItem, ArtifactFile)], Map[String, Throwable])],
    requiredVersions: Map[String, Int]
  )(implicit requestHeader: DefaultRequest, snoozesInfo: SnoozesInfo, executionContext: ExecutionContext) = try{
    for((successfulResults, failedResults) <- resultsFuture) yield{
      val reportResult = dependencyCheckReportsParser.parseReports(successfulResults, failedResults)
      import reportResult.{allDependencies, failedAnalysises, flatReports, groupedDependencies, vulnerableDependencies, projectsReportInfo}
      val now = DateTime.now
      val oldReportThreshold = now - 1.day
      val cveTimestampThreshold = now - (if(now.dayOfWeek().get == DateTimeConstants.MONDAY) 4.days else 2.days )
      val ScanChecks: Seq[Map[ReportInfo, Analysis] => Option[Warning]] = Seq(
        differentValues("scan infos", "scan-info", WarningSeverity.Warning)(_.groupBy(_._2.scanInfo).mapValues(_.keys.toIndexedSeq.sorted)),
        badValues("old-reports", "old reports", WarningSeverity.Warning)((_, a) => if(a.reportDate < oldReportThreshold) Some(Html(a.reportDate.toString)) else None),
        badValues("bad-cve-data", "old or no CVE data", WarningSeverity.Warning){(_, analysis) =>
          (analysis.scanInfo.xml \\ "timestamp").map(_.text).filterNot(_ == "").map(parseDateTime) match {
            case Seq() => Some(Html("no data"))
            case timestamps =>
              val newestTimestamp = timestamps.max
              val oldestTimestamp = timestamps.min
              if(newestTimestamp < cveTimestampThreshold) Some(Html(newestTimestamp.toString))
              else None
          }
        }
      )
      val GroupedDependenciesChecks = Seq[Seq[GroupedDependency] => Option[Warning]](
        badGroupedDependencies("unidentified-dependencies", "unidentified dependencies", WarningSeverity.Info)(_.filter(_.dependencies.exists(_._1.identifiers.isEmpty)))(show = showDependencies, exclusions = missingGAVExclusions.exclusionsSet),
        badGroupedDependencies("different-identifier-sets", "different identifier sets", WarningSeverity.Info)(_.filter(_.dependencies.groupBy(_._1.identifiers).size > 1).toIndexedSeq)(),
        badGroupedDependencies("different-evidence", "different evidence", WarningSeverity.Info)(_.filter(_.dependencies.groupBy(_._1.evidenceCollected).size > 1).toIndexedSeq)(show = x => Some(views.html.warnings.groupedDependencies(x))),
        badGroupedDependencies("missing-gav", "missing GAV", WarningSeverity.Info)(_.filter(_.identifiers.filter(_.identifierType == "maven").isEmpty))(show = showDependencies, exclusions = missingGAVExclusions.exclusionsSet)
      )

      val unknownIdentifierTypes = allDependencies.flatMap(_._1.identifiers.map(_.identifierType)).toSet -- Set("maven", "cpe")
      val logChecks = Seq[(String => Boolean, ProjectWarningBuilder)](
        (
          log => log.lines.exists(l => (l.toLowerCase startsWith "error") || (l.toLowerCase contains "[error]")),
          ProjectWarningBuilder("results-with-error-messages", views.html.warnings.resultsWithErrorMessages(), WarningSeverity.Error)
        )
      ) ++ logSmells.checks.toSeq.map { case (id, s) =>
        (
          (log: String) => log.lines.exists(l => s.regex.pattern.matcher(l).find),
          ProjectWarningBuilder(id, HtmlFormat.escape(s.message), s.severity)
        )
      }
      val logWarnings: Seq[Warning] = logChecks.flatMap{case (logCheck, warningBuilder) =>
        val resultsWithErrorMessages = successfulResults.par.filter{case (k, (_, _, log)) => logCheck(log.dataString)}
        if(resultsWithErrorMessages.nonEmpty) Some(warningBuilder.forProjects(new FailedProjects(resultsWithErrorMessages.keys.map(projectsReportInfo.reportIdToReportInfo).seq.toSet), buildLink)) else None
      }
      val extraWarnings = Seq[Option[Warning]](
        if(unknownIdentifierTypes.size > 0) Some(IdentifiedWarning("unknown-identifier-types", views.html.warnings.unknownIdentifierType(unknownIdentifierTypes), WarningSeverity.Info)) else None,
        if(failedResults.isEmpty) None else Some(IdentifiedWarning("failed-results", views.html.warnings.failedResults(failedResults), WarningSeverity.Error)),
        if(requiredVersions.isEmpty) None else Some(IdentifiedWarning("required-versions", views.html.warnings.textWarning("You have manually requested results for some older version."), WarningSeverity.Warning)),
        if(failedAnalysises.isEmpty) None else Some(IdentifiedWarning("failed-analysises", views.html.warnings.textWarning(s"Some reports failed to parse: ${failedAnalysises.keySet}"), WarningSeverity.Error))
      ).flatten

      val scanWarnings = ScanChecks.flatMap(_(flatReports))
      val groupedDependenciesWarnings = GroupedDependenciesChecks.flatMap(_(groupedDependencies))
      val allWarnings = scanWarnings ++ groupedDependenciesWarnings ++ logWarnings ++ extraWarnings

      // TODO: log analysis
      // TODO: related dependencies
      (vulnerableDependencies, allWarnings.map(_.optimize), groupedDependencies)
    }
  }finally{
    Logger.debug("Reports processed")
  }


}
