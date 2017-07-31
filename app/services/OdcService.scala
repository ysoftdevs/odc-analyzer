package services

import java.io.File.separatorChar
import java.io._
import java.lang.{Boolean => JBoolean}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file._
import java.nio.file.attribute.BasicFileAttributes
import java.sql.{Array => _}
import java.util.{Properties, Map => JMap}

import _root_.org.apache.commons.lang3.SystemUtils
import _root_.org.owasp.dependencycheck.dependency.{VulnerableSoftware => OdcVulnerableSoftware}
import com.google.inject.Inject
import com.ysoft.odc.{GroupedDependency, Identifier, OdcParser}
import controllers.DependencyCheckReportsParser
import play.api.Application
import play.api.libs.concurrent.Akka

import scala.concurrent.{ExecutionContext, Future}

case class OdcDbConnectionConfig(driverClass: String, driverJar: String, url: String, user: String, password: String)

case class OdcConfig(odcPath: String, extraArgs: Seq[String] = Seq(), workingDirectory: String = ".", propertyFile: Option[String])

case class SingleLibraryScanResult(mainDependency: GroupedDependency, transitiveDependencies: Seq[GroupedDependency], includesTransitive: Boolean)

class OdcService @Inject() (odcConfig: OdcConfig, odcDbConnectionConfig: OdcDbConnectionConfig)(implicit application: Application){
  private implicit val executionContext: ExecutionContext = Akka.system.dispatchers.lookup("contexts.odc-workers")
  private def suffix = if(SystemUtils.IS_OS_WINDOWS) "bat" else "sh"
  private def odcBin = new File(new File(odcConfig.odcPath), "bin"+separatorChar+"dependency-check."+suffix).getAbsolutePath
  private def mavenBin = "mvn"
  private val OutputFormat = "XML"
  private val DependencyNotFoundPrefix = "[ERROR] Failed to execute goal on project odc-adhoc-project: Could not resolve dependencies for project com.ysoft:odc-adhoc-project:jar:1.0-SNAPSHOT: Could not find artifact "

  private def mavenLogChecks(log: String) = {
    if(log.lines contains "[INFO] No dependencies were identified that could be analyzed by dependency-check"){
      sys.error("Dependency not identified. Log: "+log)
    }
    for(missingDependencyMessage <- log.lines.find(_.startsWith(DependencyNotFoundPrefix))){
      val missingDependency = missingDependencyMessage.drop(DependencyNotFoundPrefix.length).takeWhile(_ != ' ')
      throw DependencyNotFoundException(missingDependency)
    }
  }

  def scanMaven(groupId: String, artifactId: String, version: String): Future[SingleLibraryScanResult] = scanInternal(
    createOdcCommand = createMavenOdcCommand,
    isMainLibraryOption = Some(_.exists(id => id.identifierType == "maven" && id.name == s"$groupId:$artifactId:$version")),
    logChecks = mavenLogChecks
  ){ dir =>
    val pomXml = <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.ysoft</groupId>
      <artifactId>odc-adhoc-project</artifactId>
      <version>1.0-SNAPSHOT</version>
      <build>
        <plugins>
          <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <configuration>
              <outputDirectory>{"${outputDirectory}"}</outputDirectory>
            </configuration>
            <executions>
              <execution>
                <goals>
                  <goal>check</goal>
                </goals>
              </execution>
            </executions>
          </plugin>
        </plugins>
      </build>
      <dependencies>
        <dependency>
          <groupId>{groupId}</groupId>
          <artifactId>{artifactId}</artifactId>
          <version>{version}</version>
        </dependency>
      </dependencies>
    </project>
    Files.write(dir.resolve("pom.xml"), pomXml.toString.getBytes(UTF_8))
  }

  private def consumeStream(in: InputStream): Array[Byte] = {
    val baos = new ByteArrayOutputStream()
    val buff = new Array[Byte](1024)
    var size: Int = 0
    while({size = in.read(buff); size != -1}) {
      baos.write(buff, 0, size)
    }
    baos.toByteArray
  }

  private def scanInternal(
    createOdcCommand: (String, Path, String) => Seq[String] = createStandardOdcCommand,
    isMainLibraryOption: Option[Seq[Identifier] => Boolean],
    logChecks: String => Unit = s => ()
  )(
    f: Path => Unit
  ): Future[SingleLibraryScanResult] = Future{
    withTmpDir { scanDir =>
      val scandirPrefix = s"$scanDir$separatorChar"
      val reportFilename = s"${scandirPrefix}report.xml"
      val path = scanDir.resolve("scanned-dir")
      Files.createDirectory(path)
      f(path)
      val cmd: Seq[String] = createOdcCommand(scandirPrefix, path, reportFilename)
      val process = new ProcessBuilder(cmd: _*).
        directory(new File(odcConfig.workingDirectory)).
        redirectErrorStream(true).
        start()
      val in = process.getInputStream
      // We consume all output in order not to hang; we mix stderr and stdout together
      val outArray = consumeStream(in)
      val res = process.waitFor()
      lazy val log = new String(outArray)
      logChecks(log)
      if(res != 0){
        sys.error(s"Non-zero return value: $res; output: $log")
      }
      val result = DependencyCheckReportsParser.forAdHocScan(OdcParser.parseXmlReport(Files.readAllBytes(Paths.get(reportFilename))))
      val (Seq(mainLibrary), otherLibraries) = result.allDependencies.partition{case (dep, _) => isMainLibraryOption.fold(true)(f => f(dep.identifiers) || dep.relatedDependencies.map(_.identifiers).exists(f))}
      SingleLibraryScanResult(
        mainDependency = GroupedDependency(Seq(mainLibrary)),
        transitiveDependencies = otherLibraries.map(dep => GroupedDependency(Seq(dep))),
        includesTransitive = isMainLibraryOption.isDefined
      )
    }
  }

  private def odcVersion: String = {
    import sys.process._
    Seq(odcBin, "--version").!!.trim.reverse.takeWhile(_!=' ').reverse
  }

  private def createHintfulOdcCommand(scandirPrefix: String, path: Path, reportFilename: String): Seq[String] = {
    val newPropertyFile = s"${scandirPrefix}odc.properties"
    val p = new Properties()
    for(origPropFile <- odcConfig.propertyFile){
      val in = new FileInputStream(Paths.get(odcConfig.workingDirectory).resolve(origPropFile).toFile)
      try{
        p.load(in)
      }finally{
        in.close()
      }
    }
    import scala.collection.JavaConversions._
    p.put("hints.file", s"${scandirPrefix}hints.xml")
    p.putAll(dbProps)
    val out = new FileOutputStream(Paths.get(newPropertyFile).toFile)
    try{
      p.store(out, "no comment")
    }finally {
      out.close()
    }
    val cmdBase = Seq(
      odcBin,
      "-s", path.toString,
      "--project", "AdHocProject",
      "--noupdate",
      "-f", OutputFormat,
      "-l", s"${scandirPrefix}verbose.log",
      "--out", reportFilename,
      "-P", newPropertyFile
    )
    cmdBase ++ odcConfig.extraArgs
  }

  private def createStandardOdcCommand(scandirPrefix: String, path: Path, reportFilename: String): Seq[String] = {
    val cmdBase = Seq(
      odcBin,
      "-s", path.toString,
      "--project", "AdHocProject",
      "--noupdate",
      "-f", OutputFormat,
      "-l", s"${scandirPrefix}verbose.log",
      "--out", reportFilename
    ) ++ odcConfig.propertyFile.fold(Seq[String]())(Seq("-P", _))
    cmdBase ++ odcConfig.extraArgs
  }

  private def createMavenOdcCommand(scandirPrefix: String, path: Path, reportFilename: String): Seq[String] = {
    val cmdBase = Seq(
      mavenBin,
      "--file", s"${path}${separatorChar}pom.xml",
      "-X",
      "-U", // force update
      s"org.owasp:dependency-check-maven:$odcVersion:check",
      "-Dautoupdate=false",
      s"-Dformat=$OutputFormat",
      s"-DlogFile=${scandirPrefix}verbose.log",
      s"-DoutputDirectory=$reportFilename"
    )
    cmdBase ++ propsArgs ++ propsToArgs(dbProps) // TODO: fix credentials leak via /proc
  }

  private def dbProps = Map(
    "data.driver_path" -> odcDbConnectionConfig.driverJar,
    "data.driver_name" -> odcDbConnectionConfig.driverClass,
    "data.connection_string" -> odcDbConnectionConfig.url,
    "data.user" -> odcDbConnectionConfig.user,
    "data.password" -> odcDbConnectionConfig.password
  )

  private def propsToArgs(props: Traversable[(String, String)]): Traversable[String] = for((key, value) <- props) yield s"-D$key=$value"

  private def propsArgs = odcConfig.propertyFile.fold(Seq[String]()){ propertyFile =>
    val props = new Properties()
    val in = new FileInputStream(Paths.get(odcConfig.workingDirectory).resolve(propertyFile).toFile)
    try {
      props.load(in)
    } finally {
      in.close()
    }
    import scala.collection.JavaConversions._
    propsToArgs(props.toSeq).toSeq
  }


  private def withTmpDir[T](f: Path => T): T = {
    val tmpDir = Files.createTempDirectory("odc")
    try {
      f(tmpDir)
    } finally {
      rmdir(tmpDir)
    }
  }

  private def rmdir(dir: Path) = {
    Files.walkFileTree(dir, new SimpleFileVisitor[Path] {
      override def visitFile(f: Path, basicFileAttributes: BasicFileAttributes): FileVisitResult = {
        Files.delete(f)
        FileVisitResult.CONTINUE
      }

      override def postVisitDirectory(dir: Path, e: IOException): FileVisitResult = {
        Files.delete(dir)
        FileVisitResult.CONTINUE
      }
    })
  }

  override def toString = s"OdcService($odcConfig, $executionContext)"
}
