import controllers._
import org.specs2.mutable.Specification


//noinspection ScalaUnnecessaryParentheses
class TeamFilterSpec extends Specification {
  import factories.ReportsFactory._

  private val f1 = TeamFilter(team1)
  private val s1 = f1.subReports(res).get

  "The Team A should" >> {
    "have dependencies related to them (assigned through a full project)" >> {
      "like a" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a").toLibraryIdentifierOption.get)}
      "like a/subX" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a/subX").toLibraryIdentifierOption.get)}
      "like a/subY" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a/subY").toLibraryIdentifierOption.get)}
    }
    "not have dependencies unrelated to them (assigned through a full project)" >> {
      "like m" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("m").toLibraryIdentifierOption.get)}
      "like m/subX" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("m/subX").toLibraryIdentifierOption.get)}
      "like m/subY" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("m/subY").toLibraryIdentifierOption.get)}
    }
    "have dependencies related to them (assigned through a subproject)" >> {
      "like b" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("b").toLibraryIdentifierOption.get)}
      "like b/subX" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("b/subX").toLibraryIdentifierOption.get)}
    }
    "not have dependencies unrelated to them (assigned through a full project)" >> {
      "like b/subY" >> {s1.groupedDependenciesByPlainLibraryIdentifier.keySet should not contain(buildFakeIdentifier("b/subY").toLibraryIdentifierOption.get)}
    }
  }

}
