package controllers

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.google.inject.name.Named
import com.ysoft.odc.Checks._
import com.ysoft.odc._
import org.joda.time.DateTimeConstants
import play.api.Logger
import play.api.i18n.{I18nSupport, MessagesApi}
import play.api.mvc.RequestHeader
import play.twirl.api.Html
import views.html.DefaultRequest

import scala.concurrent.{ExecutionContext, Future}

final case class MissingGavExclusions(exclusionsSet: Set[Exclusion]){
  def isExcluded(groupedDependency: GroupedDependency) = exclusionsSet.exists(_.matches(groupedDependency))
}

final class DependencyCheckReportsProcessor @Inject() (
                                                  @Named("bamboo-server-url") val server: String,
                                                  dependencyCheckReportsParser: DependencyCheckReportsParser,
                                                  @Named("missing-GAV-exclusions") missingGAVExclusions: MissingGavExclusions,
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


  def processResults(
    resultsFuture: Future[(Map[String, (Build, ArtifactItem, ArtifactFile)], Map[String, Throwable])],
    requiredVersions: Map[String, Int]
  )(implicit requestHeader: DefaultRequest, snoozesInfo: SnoozesInfo, executionContext: ExecutionContext) = try{
    for((successfulResults, failedResults) <- resultsFuture) yield{
      val reportResult = dependencyCheckReportsParser.parseReports(successfulResults)
      import reportResult.{allDependencies, failedAnalysises, flatReports, groupedDependencies, vulnerableDependencies}
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
      val failedReports = successfulResults.filter(x => x._2._1.state != "Successful" || x._2._1.buildState != "Successful")
      val extraWarnings = Seq[Option[Warning]](
        if(failedReports.size > 0) Some(IdentifiedWarning("failed-reports", views.html.warnings.failedReports(failedReports.values.map{case (b, _ ,_) => b}.toSet, server), WarningSeverity.Error)) else None,
        if(unknownIdentifierTypes.size > 0) Some(IdentifiedWarning("unknown-identifier-types", views.html.warnings.unknownIdentifierType(unknownIdentifierTypes), WarningSeverity.Info)) else None,
        {
          val emptyResults = successfulResults.filter{case (k, (_, dir, _)) => dir.flatFiles.size < 1}
          if(emptyResults.nonEmpty) Some(IdentifiedWarning("empty-results", views.html.warnings.emptyResults(emptyResults.values.map{case (build, _, _) => build}.toSeq, server), WarningSeverity.Warning)) else None
        },
        {
          val resultsWithErrorMessages = successfulResults.filter{case (k, (_, _, log)) => log.dataString.lines.exists(l => (l.toLowerCase startsWith "error") || (l.toLowerCase contains "[error]"))}
          if(resultsWithErrorMessages.nonEmpty) Some(IdentifiedWarning("results-with-error-messages", views.html.warnings.resultsWithErrorMessages(resultsWithErrorMessages.values.map{case (build, _, _) => build}.toSeq, server), WarningSeverity.Error)) else None
        },
        if(failedResults.isEmpty) None else Some(IdentifiedWarning("failed-results", views.html.warnings.failedResults(failedResults), WarningSeverity.Error)),
        if(requiredVersions.isEmpty) None else Some(IdentifiedWarning("required-versions", views.html.warnings.textWarning("You have manually requested results for some older version."), WarningSeverity.Warning)),
        if(failedAnalysises.isEmpty) None else Some(IdentifiedWarning("failed-analysises", views.html.warnings.textWarning(s"Some reports failed to parse: ${failedAnalysises.keySet}"), WarningSeverity.Error))
      ).flatten

      val scanWarnings = ScanChecks.flatMap(_(flatReports))
      val groupedDependenciesWarnings = GroupedDependenciesChecks.flatMap(_(groupedDependencies))
      val allWarnings = scanWarnings ++ groupedDependenciesWarnings ++ extraWarnings

      // TODO: log analysis
      // TODO: related dependencies
      (vulnerableDependencies, allWarnings.map(_.optimize), groupedDependencies)
    }
  }finally{
    Logger.debug("Reports processed")
  }


}
