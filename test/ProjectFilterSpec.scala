import controllers.ProjectFilter
import org.specs2.mutable.Specification

//noinspection ScalaUnnecessaryParentheses
class ProjectFilterSpec extends Specification {
  import factories.ReportsFactory._

  private val f1 = ProjectFilter(res.projectsReportInfo.reportIdToReportInfo("a")) // with subprojects
  // TODO: filter root
  // TODO: filter subproject

  private val s1 = f1.subReports(res).get

  "It should have all dependencies for project a and its subprojects" >> {
    "like a" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a").toLibraryIdentifierOption.get)}
    "like a/subX" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a/subX").toLibraryIdentifierOption.get)}
    "like a/subY" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a/subY").toLibraryIdentifierOption.get)}
  }

  "It should now have other dependencies" >> {
    "like b" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("b").toLibraryIdentifierOption.get)}
    "like b/subX" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("b/subX").toLibraryIdentifierOption.get)}
    "like b/subY" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("b/subY").toLibraryIdentifierOption.get)}
  }

}
