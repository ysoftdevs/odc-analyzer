package factories

import com.github.nscala_time.time.Imports.DateTime
import com.ysoft.odc._
import controllers.DependencyCheckReportsParser.Result
import controllers.{Projects, ProjectsWithReports, ReportInfo, TeamId}
import org.apache.commons.codec.digest.DigestUtils

//noinspection TypeAnnotation
object ReportsFactory{

  def buildFlatReport(projectId: String): (String, () => (ReportInfo, Analysis)) = {
    val thuck = () => { // needs laziness in order to prevent dependency cycle
      val reportInfo = projectsReportInfo.parseUnfriendlyName(projectId)
      reportInfo -> Analysis(
        scanInfo = SerializableXml("<a></a>"),
        name = projectId,
        reportDate = DateTime.lastDay,
        dependencies = Seq(
          buildDependency(projectId)
        ),
        groupId = "com.ysoft.something",
        artifactId = "someArtifact",
        version = "3.1.4.1.5.9.2.6.5.3.6"
      )
    }
    projectId -> thuck
  }

  def buildDependency(projectId: String) = {
    val fakeFileContent = projectId
    Dependency(
      fileName = s"dep-for-$projectId",
      filePath = s"dep-for-$projectId",
      md5 = DigestUtils.md5Hex(fakeFileContent),
      sha1 = DigestUtils.sha1Hex(fakeFileContent),
      sha256 = DigestUtils.sha256Hex(fakeFileContent),
      description = s"Some fake dependency for project $projectId",
      evidenceCollected = Set(),
      identifiers = Seq(buildFakeIdentifier(projectId)),
      suppressedIdentifiers = Seq(),
      license = "something",
      vulnerabilities = Seq(),
      suppressedVulnerabilities = Seq(),
      relatedDependencies = Seq(),
      isVirtual = false
    )
  }

  def buildFakeIdentifier(projectId: String) = {
    Identifier(s"fake:dep-for-$projectId:1.0-SNAPSHOT", Confidence.High, "", "maven")
  }

  val pm = Map(
    "a"->"project a",
    "b"->"project b",
    "c"->"project c",
    "d"->"project d",
    "e"->"project e",
    "f"->"project f",
    "g"->"project g",
    "h"->"project h",
    "i"->"project i",
    "j"->"project j",
    "k"->"project k",
    "l"->"project l",
    "m"->"project m",
    "n"->"project n",
    "o"->"project o"
  )

  val projectToTeams = Map(
    "project a: *" -> Set("TEAM A"),
    "project b: subX" -> Set("TEAM A"),
    "project b: subY" -> Set("TEAM B"),
    "project b" -> Set("TEAM A"),
    "project c: *" -> Set("TEAM A"),
    "project d: *" -> Set("TEAM A"),
    "project e: *" -> Set("TEAM A"),
    "project f: *" -> Set("TEAM A"),
    "project g: *" -> Set("TEAM A"),
    "project h: *" -> Set("TEAM B"),
    "project i: *" -> Set("TEAM B"),
    "project j: *" -> Set("TEAM B"),
    "project k: *" -> Set("TEAM B"),
    "project l: *" -> Set("TEAM B"),
    "project m: *" -> Set("TEAM B"),
    "project n: *" -> Set("TEAM B"),
    "project o: *" -> Set("TEAM B")
  )

  val teamLeaders = Map(TeamId("TEAM A") -> "John Smith", TeamId("TEAM B") -> "Jane")

  val projects = new Projects(
    projectMap = pm,
    teamLeaders = teamLeaders,
    projectToTeams = projectToTeams.mapValues(_.map(TeamId))
  )

  val bareFlatReportsFactories = pm.keySet.flatMap{ projectId =>
    Seq(
      buildFlatReport(projectId),
      buildFlatReport(projectId+"/subX"),
      buildFlatReport(projectId+"/subY")
    )
  }

  val projectsReportInfo = new ProjectsWithReports(projects, bareFlatReportsFactories.map(_._1))

  val bareFlatReports = bareFlatReportsFactories.map(_._2()).toMap // Prevents forward reference issues

  val res = Result(
    bareFlatReports = bareFlatReports,
    bareFailedAnalysises = Map(),
    projectsReportInfo = projectsReportInfo,
    failedReportDownloads = Map()
  )

  val team1 = projects.teamById("TEAM A")

}
