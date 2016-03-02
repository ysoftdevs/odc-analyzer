name := """odc-analyzer"""

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.7"

resolvers += "Atlassian Releases" at "https://maven.atlassian.com/public/"

libraryDependencies ++= Seq(
  //jdbc,
  cache,
  ws,
  filters
  //specs2 % Test
)

//resolvers += "scalaz-bintray" at https?"http://dl.bintray.com/scalaz/releases"

libraryDependencies += "com.lihaoyi" %% "upickle" % "0.3.4"

//libraryDependencies += "com.typesafe.play" %% "play-ws" % "2.4.2"

libraryDependencies += "com.jsuereth" %% "scala-arm" % "1.4"

libraryDependencies += "org.ccil.cowan.tagsoup" % "tagsoup" % "1.2.1"

libraryDependencies += "com.typesafe.play" %% "play-slick" % "1.1.1"

libraryDependencies += "com.typesafe.play" %% "play-slick-evolutions" % "1.1.1"

libraryDependencies += "com.github.tototoshi" %% "slick-joda-mapper" % "2.0.0"

//libraryDependencies += "nu.validator.htmlparser" % "htmlparser" % "1.2.1"

//libraryDependencies += "com.lihaoyi" %% "pprint" % "0.3.4"

libraryDependencies += "com.github.nscala-time" %% "nscala-time" % "2.0.0"

// libraryDependencies += "org.mariadb.jdbc" % "mariadb-java-client" % "1.1.9"

libraryDependencies += "org.postgresql" % "postgresql" % "9.4-1201-jdbc41"

libraryDependencies += "org.mariadb.jdbc" % "mariadb-java-client" % "1.3.3"

libraryDependencies += "org.webjars" % "bootstrap" % "3.3.5"

libraryDependencies += "org.webjars" % "jquery" % "2.1.4"

libraryDependencies += "org.webjars" % "bootstrap-datepicker" % "1.4.0"

libraryDependencies += "org.webjars" % "tablesorter" % "2.17.8"

libraryDependencies += "org.webjars.bower" % "StickyTableHeaders" % "0.1.17"

//libraryDependencies += "org.webjars.bower" % "plottable" % "1.5.0"

//libraryDependencies += "org.webjars" % "d3js" % "3.5.6"

libraryDependencies += "org.webjars" % "jqplot" % "1.0.8r1250"

//libraryDependencies += "com.github.mumoshu" %% "play2-memcached-play24" % "0.7.0"

libraryDependencies ++= Seq(
  "com.mohiva" %% "play-silhouette" % "3.0.4",
  "com.mohiva" %% "play-silhouette-testkit" % "3.0.4" % "test"
)

libraryDependencies += "org.webjars.bower" % "jquery.scrollTo" % "2.1.2"

libraryDependencies += "net.codingwell" %% "scala-guice" % "4.0.0"

libraryDependencies += "net.ceedubs" %% "ficus" % "1.1.2"

libraryDependencies += "org.owasp" % "dependency-check-core" % "1.3.0"

libraryDependencies += "com.typesafe.play" %% "play-mailer" % "3.0.1"

libraryDependencies += "com.google.caliper" % "caliper" % "1.0-beta-2"

libraryDependencies += "org.apache.httpcomponents" % "httpclient" % "4.3.6" // evict the vulnerable version

routesImport += "binders.QueryBinders._"

// Uncomment to use Akka
//libraryDependencies += "com.typesafe.akka" %% "akka-actor" % "2.3.11"

// Play provides two styles of routers, one expects its actions to be injected, the
// other, legacy style, accesses its actions statically.
routesGenerator := InjectedRoutesGenerator


scalacOptions ++= Seq(
  "-deprecation", // Emit warning and location for usages of deprecated APIs.
  "-feature", // Emit warning and location for usages of features that should be imported explicitly.
  "-unchecked", // Enable additional warnings where generated code depends on assumptions.
  //"-Xfatal-warnings", // Fail the compilation if there are any warnings.
  "-Xlint", // Enable recommended additional warnings.
  "-Ywarn-adapted-args", // Warn if an argument list is modified to match the receiver.
  "-Ywarn-dead-code", // Warn when dead code is identified.
  "-Ywarn-inaccessible", // Warn about inaccessible types in method signatures.
  "-Ywarn-nullary-override", // Warn when non-nullary overrides nullary, e.g. def foo() over def foo.
  "-Ywarn-numeric-widen" // Warn when numerics are widened.
)