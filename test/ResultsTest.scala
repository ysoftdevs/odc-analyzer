import org.specs2.mutable.Specification

//noinspection ScalaUnnecessaryParentheses
class ResultsTest extends Specification {
  import factories.ReportsFactory._

  "The resultset should" >> {
    "have dependencies related to project a" >> {
      "like a" >> {res.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a").toLibraryIdentifierOption.get)}
      "libe a/subX" >> {res.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a/subX").toLibraryIdentifierOption.get)}
      "like a/subY" >> {res.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("a/subY").toLibraryIdentifierOption.get)}
    }
    "have dependencies related to project m" >> {
      "like m" >> {res.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("m").toLibraryIdentifierOption.get)}
      "libe m/subX" >> {res.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("m/subX").toLibraryIdentifierOption.get)}
      "like m/subY" >> {res.groupedDependenciesByPlainLibraryIdentifier.keySet should contain(buildFakeIdentifier("m/subY").toLibraryIdentifierOption.get)}
    }
    "have groupedDependencies" >> {
      res.groupedDependencies shouldNotEqual null
    }

  }

}
