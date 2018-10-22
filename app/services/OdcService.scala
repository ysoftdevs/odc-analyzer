package services

import java.io.File.separatorChar
import java.io._
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file._
import java.nio.file.attribute.BasicFileAttributes
import java.util.{Properties, UUID}

import _root_.org.apache.commons.lang3.SystemUtils
import com.google.inject.Inject
import com.ysoft.odc.{AbstractDependency, GroupedDependency, OdcParser}
import controllers.DependencyCheckReportsParser
import play.api.libs.concurrent.Akka
import play.api.{Application, Logger}

import scala.concurrent.{ExecutionContext, Future}

case class OdcDbConnectionConfig(driverClass: String, driverJar: String, url: String, user: String, password: String)

case class OdcConfig(
  odcPath: String,
  extraArgs: Seq[String] = Seq(),
  workingDirectory: String = ".",
  propertyFile: Option[String],
  cleanTmpDir: Boolean = true,
  dotNetNugetSource: Option[String],
  useDotNetCore: Boolean = false
)

abstract sealed class Limitation(val severity: String){
  def message: String
  def requiresAttention: Boolean
}

object Limitation{
  case class Notice(message: String) extends Limitation("info"){
    override def requiresAttention: Boolean = false
  }
  case class Warning(message: String) extends Limitation("warning"){
    override def requiresAttention: Boolean = true
  }
}

case class PreparationResult(limitations: Seq[Limitation] = Seq(), profilesOption: Option[(Seq[String], GroupedDependency => Seq[String])] = None, includesTransitive: Boolean)

case class SingleLibraryScanResult(mainDependencies: Seq[GroupedDependency], transitiveDependencies: Seq[GroupedDependency], includesTransitive: Boolean, limitations: Seq[Limitation], profilesOption: Option[(Seq[String], GroupedDependency => Seq[String])]) {
  def allDependencies: Seq[GroupedDependency] = mainDependencies ++ transitiveDependencies
}

class OdcInstallation(val workingDirectory: Path, odcPath: Path){
  private def suffix = if(SystemUtils.IS_OS_WINDOWS) "bat" else "sh"
  def odcBin: String = odcPath.resolve("bin").resolve("dependency-check."+suffix).toFile.getAbsolutePath
  def odcVersion: String = {
    import sys.process._
    Seq(odcBin, "--version").!!.trim.reverse.takeWhile(_!=' ').reverse
  }
  def pluginFiles: Seq[File] = odcPath.resolve("plugins").toFile.listFiles().toSeq
}

class OdcService @Inject() (odcConfig: OdcConfig, odcDbConnectionConfig: OdcDbConnectionConfig)(implicit application: Application){
  private implicit val executionContext: ExecutionContext = Akka.system.dispatchers.lookup("contexts.odc-workers")
  private def mavenBin = "mvn"
  private def nugetBin = "nuget"
  private val OutputFormat = "XML"
  private val DependencyNotFoundPrefix = "[ERROR] Failed to execute goal on project odc-adhoc-project: Could not resolve dependencies for project com.ysoft:odc-adhoc-project:jar:1.0-SNAPSHOT: Could not find artifact "
  private def resolveOdcInstallation = {
    val workingDirectory = Paths.get(odcConfig.workingDirectory).toRealPath()
    new OdcInstallation(
      workingDirectory = workingDirectory,
      odcPath = workingDirectory.resolve(odcConfig.odcPath).toRealPath()) // makes the path fixed, so it does not switch versions when a symlink is changed
  }

  private def mavenLogChecks(log: String) = {
    if(log.lines contains "[INFO] No dependencies were identified that could be analyzed by dependency-check"){
      sys.error("Dependency not identified. Log: "+log)
    }
    for(missingDependencyMessage <- log.lines.find(_.startsWith(DependencyNotFoundPrefix))){
      val missingDependency = missingDependencyMessage.drop(DependencyNotFoundPrefix.length).takeWhile(_ != ' ')
      throw DependencyNotFoundException(missingDependency)
    }
  }

  def isManualWebJarIdentifier(name: String): Boolean = name.startsWith("org.webjars:")
  def isBowerWebJarIdentifier(name: String): Boolean = name.startsWith("org.webjars.bower:")
  def isNpmWebJarIdentifier(name: String): Boolean = name.startsWith("org.webjars.npm:")
  def isUnknownWebJarIdentifier(name: String): Boolean = name.startsWith("org.webjars.") && !(isNpmWebJarIdentifier(name) ||isManualWebJarIdentifier(name) || isBowerWebJarIdentifier(name))

  def addMavenLibsLimitations(result: SingleLibraryScanResult): SingleLibraryScanResult = {
    def hasMavenIdentifier(f: String => Boolean) = result.allDependencies.exists(dep => dep.mavenIdentifiers.exists(identifier => f(identifier.name)))
    val hasManualWebJar = hasMavenIdentifier(isManualWebJarIdentifier)
    val hasBowerWebJar = hasMavenIdentifier(isBowerWebJarIdentifier)
    val hasUnknownWebJar = hasMavenIdentifier(isUnknownWebJarIdentifier)
    val hasUnrecommendedWebJar = hasManualWebJar || hasBowerWebJar || hasUnknownWebJar
    val additionalLimitations = if(hasUnrecommendedWebJar)
      Seq(Limitation.Warning(
        "You seem to use some WebJar other than NPM. Please consider using a NPM variant of the WebJar if possible. "+
          "NPM has currently the best support and ODC is most likely to find vulnerabilities (if they are present) there."+
          (if(hasBowerWebJar) " Bower is deprecated." else "")+
          (if(hasManualWebJar) " Classic WebJars require manual work of maintainer, so they might be harder to update." else "")+
          (if(hasUnknownWebJar) " You seem to use some kind of WebJar this tool does not know (NPM/Bower/Classic)." else "")
      )) else Seq()
    result.copy(limitations = result.limitations ++ additionalLimitations)
  }

  def scanMaven(groupId: String, artifactId: String, version: String, depType: String): Future[SingleLibraryScanResult] = {
    val allowMultiple = depType != ""
    def pomXml(odcInstallation: OdcInstallation) = <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
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
            <dependencies>
              {odcInstallation.pluginFiles.map{x =>
                <dependency>
                  <groupId>com.ysoft</groupId>
                  <artifactId>ad-hoc-artifact-{UUID.randomUUID().toString}</artifactId>
                  <version>1.0-SNAPSHOT</version>
                  <scope>system</scope>
                  <systemPath>{x.toString}</systemPath>
                </dependency>
              }}
            </dependencies>
          </plugin>
        </plugins>
      </build>
      <dependencies>
        <dependency>
          <groupId>{groupId}</groupId>
          <artifactId>{artifactId}</artifactId>
          <version>{version}</version>
          {if (depType != "") <type>{depType}</type>}
        </dependency>
      </dependencies>
    </project>
    scanInternal(
      createOdcCommand = createMavenOdcCommand,
      isMainLibraryOption = Some(isMainMavenLib(groupId, artifactId, version, allowMultiple)(_)),
      logChecks = mavenLogChecks,
      enableMultipleMainLibraries = allowMultiple
    ) { (odcInstallation, dir) =>
      Files.write(dir.resolve("pom.xml"), pomXml(odcInstallation).toString.getBytes(UTF_8))
      PreparationResult(includesTransitive = true)
    }.map(addMavenLibsLimitations)
  }

  private def isMainMavenLib(groupId: String, artifactId: String, version: String, allowMultiple: Boolean)(dep: AbstractDependency): Boolean = {
    allowMultiple || dep.identifiers.exists(id => id.identifierType == "maven" && id.name == s"$groupId:$artifactId:$version")
  }

  private def nugetRestore(odcInstallation: OdcInstallation, dir: Path, packagesConfigFile: Path, packageName: String, version: String): Unit = {
    val packagesConfig = <packages>
      <package id={packageName} version={version}/>
    </packages>
    Files.write(packagesConfigFile, packagesConfig.toString().getBytes(UTF_8))
    val cmd = Seq(
      nugetBin,
      "restore",
      packagesConfigFile.toString,
      "-PackagesDirectory",
      dir.toString
    ) ++ odcConfig.dotNetNugetSource.fold(Seq[String]())(source => Seq("-source", source))
    val process = new ProcessBuilder(cmd: _*).
      directory(odcInstallation.workingDirectory.toFile).
      redirectErrorStream(true).
      start()
    val rawLog = consumeStream(process.getInputStream)
    val res = process.waitFor()
    if (res != 0) {
      val log = new String(rawLog)
      val NotFoundRegex = """Unable to find version '([^']+)' of package '([^']+)'.""".r
      log.lines.toStream.head match {
        case NotFoundRegex(version, packageName) => throw DependencyNotFoundException(s"$packageName:$version")
        case _ => sys.error(s"Bad return code from NuGet: $res. Output: $log")
      }
    }
  }

  private def dotnetRestore(odcInstallation: OdcInstallation, dir: Path, csprojFile: Path, packageName: String, version: String, targetFramework: String): Unit = {
    val csproj = <Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup>
        <TargetFramework>{targetFramework}</TargetFramework>
      </PropertyGroup>
      <ItemGroup>
        <PackageReference Include={packageName} Version={version} />
      </ItemGroup>
    </Project>
    Files.write(csprojFile, csproj.toString().getBytes(UTF_8))
    val cmd = Seq(
      "dotnet",
      "restore",
      csprojFile.toString,
      "--packages",
      dir.toString
    ) ++ odcConfig.dotNetNugetSource.fold(Seq[String]())(source => Seq("--source", source))
    val process = new ProcessBuilder(cmd: _*).
      directory(odcInstallation.workingDirectory.toFile).
      redirectErrorStream(true).
      start()
    val rawLog = consumeStream(process.getInputStream)
    val res = process.waitFor()
    if(res != 0){
      val log = new String(rawLog) // we probably should use the default encoding when it comes from a process through a pipe…
      sys.error(s"Bad return code from DotNet restore: $res. Output: $log")
    }
  }

  def findDotNetProfiles(dir: Path)(gd: GroupedDependency): Seq[String] = {
    // each .NET framework profile has a separate directory starting with "framework-". We just parse that to get profile from path.
    val pathPrefix = dir.toString + File.separatorChar
    gd.paths.toSeq.map{path =>
      if(path startsWith pathPrefix){
        path.substring(pathPrefix.length).takeWhile(_ != File.separatorChar)
      }else{
        sys.error(s"Unexpected path: $path")
      }
    }.collect{
      case s if s startsWith "framework-" => s.substring("framework-".length)
    }.distinct
  }

  def scanDotNet(packageName: String, version: String): Future[SingleLibraryScanResult] = scanInternal(
    createOdcCommand = createStandardOdcCommand,
    isMainLibraryOption = Some(dep => {
      val fileNameCanon = dep.fileName.toLowerCase()
      (fileNameCanon == s"$packageName.dll".toLowerCase()) ||
        (fileNameCanon == s"$packageName.$version.nupkg".toLowerCase()) ||
        (fileNameCanon == s"$packageName:$version".toLowerCase()) ||
        (fileNameCanon == s"$packageName.$version.nupkg: $packageName.nuspec".toLowerCase())
    }
    ),
    enableMultipleMainLibraries = true,
    limitations = Seq(Limitation.Notice("Scans for .NET libraries usually contain multiple DLL variants of the same library, because multiple targets (e.g., .NETFramework 4.0, .NETFramework 4.5, .NETStandard 1.0, Portable Class Library, …) are scanned."))
  ){(odcInstallation, dir) =>
    import scala.collection.JavaConverters._
    val packagesConfigFile = dir.resolve("packages.config")
    val plainDir = dir.resolve("plain")
    Files.createDirectory(plainDir)
    nugetRestore(odcInstallation, plainDir, packagesConfigFile, packageName, version)
    if(odcConfig.useDotNetCore) {
      val libDir = Files.list(plainDir).iterator().asScala.toIndexedSeq match {
        case Seq(single) => single.resolve("lib")
        case Seq() => sys.error("missing directory after resolution")
        case other => sys.error(s"Seems like some unexpected files: $other")
      }
      if (Files.exists(libDir)) {
        val profiles = Files.list(libDir).iterator().asScala.toIndexedSeq.map(_.getFileName.toString)
        for (targetFramework <- profiles) {
          val csprojFile = dir.resolve("ad-hoc-project-" + targetFramework + ".csproj")
          val tfDir = dir.resolve("framework-" + targetFramework)
          Files.createDirectory(tfDir)
          dotnetRestore(odcInstallation, tfDir, csprojFile, packageName, version, targetFramework)
        }
        PreparationResult(profilesOption = Some((profiles, findDotNetProfiles(dir))), includesTransitive = true)
      } else {
        // In this case, we don't have a set of TFMs for scanning. We would have to resolve dependencies for all of them.
        // We cannot pick just one of them until we are sure that some of dependencies cannot have some other TMF-dependent dependencies.
        PreparationResult(limitations = Seq(Limitation.Warning("Transitive dependencies are not scanned, because it is not supported for .NET libraries without a limited set of target frameworks.")), includesTransitive = false)
      }
    }else{
      // fallback to old mode without transitive dependencies
      PreparationResult(includesTransitive = false, limitations = Seq(Limitation.Warning("Transitive dependencies are not scanned, because odc.useDotNetCore is not enabled. See config.")))
    }
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
    createOdcCommand: (OdcInstallation, String, Path, String) => Seq[String] = createStandardOdcCommand,
    isMainLibraryOption: Option[AbstractDependency => Boolean],
    logChecks: String => Unit = s => (),
    enableMultipleMainLibraries: Boolean = false,
    limitations: Seq[Limitation] = Seq.empty
  )(
    f: (OdcInstallation, Path) => PreparationResult
  ): Future[SingleLibraryScanResult] = Future{
    withTmpDir { scanDir =>
      val odcInstallation = resolveOdcInstallation
      val scandirPrefix = s"$scanDir$separatorChar"
      val reportFilename = s"${scandirPrefix}report.xml"
      val path = scanDir.resolve("scanned-dir")
      Files.createDirectory(path)
      val preparationResult = f(odcInstallation, path)
      val cmd: Seq[String] = createOdcCommand(odcInstallation, scandirPrefix, path, reportFilename)
      val process = new ProcessBuilder(cmd: _*).
        directory(odcInstallation.workingDirectory.toFile).
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
      val (mainLibraries, otherLibraries) = result.allDependencies.partition{case (dep, _) =>
        isMainLibraryOption.fold(true)(f => f(dep) || dep.relatedDependencies.exists(f))
      }
      mainLibraries.size match {
        case 0 => sys.error("No library is selected as the main library")
        case 1 => // that's OK
        case _ if enableMultipleMainLibraries => // that's OK
        case _ if !enableMultipleMainLibraries => sys.error(s"multiple (${mainLibraries.size}) libraries selected as the main library: "+mainLibraries)
      }
      val mainDependencies = mainLibraries.map(dep => GroupedDependency(Seq(dep)))
      val transitiveDependencies = otherLibraries.map(dep => GroupedDependency(Seq(dep)))
      SingleLibraryScanResult(
        mainDependencies = mainDependencies,
        transitiveDependencies = transitiveDependencies,
        includesTransitive = preparationResult.includesTransitive,
        limitations = limitations ++ preparationResult.limitations,
        profilesOption = preparationResult.profilesOption
      )
    }
  }

  private def createHintfulOdcCommand(odcInstallation: OdcInstallation, scandirPrefix: String, path: Path, reportFilename: String): Seq[String] = {
    val newPropertyFile = s"${scandirPrefix}odc.properties"
    createModifiedProps(odcInstallation, newPropertyFile, Map("hints.file" -> s"${scandirPrefix}hints.xml"))
    val cmdBase = Seq(
      odcInstallation.odcBin,
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

  private def createModifiedProps(odcInstallation: OdcInstallation, newPropertyFile: String, additionalProps: Map[String, String] = Map()) = {
    val p = new Properties()
    for (origPropFile <- odcConfig.propertyFile) {
      val in = new FileInputStream(odcInstallation.workingDirectory.resolve(origPropFile).toFile)
      try {
        p.load(in)
      } finally {
        in.close()
      }
    }
    import scala.collection.JavaConversions._
    p.putAll(dbProps)
    p.putAll(additionalProps)
    val out = new FileOutputStream(Paths.get(newPropertyFile).toFile)
    try {
      p.store(out, "no comment")
    } finally {
      out.close()
    }
  }

  private def createStandardOdcCommand(odcInstallation: OdcInstallation, scandirPrefix: String, path: Path, reportFilename: String): Seq[String] = {
    val newPropertyFile = s"${scandirPrefix}odc.properties"
    createModifiedProps(odcInstallation, newPropertyFile)
    val cmdBase = Seq(
      odcInstallation.odcBin,
      "-s", path.toString,
      "--project", "AdHocProject",
      "--noupdate",
      "-f", OutputFormat,
      "-l", s"${scandirPrefix}verbose.log",
      "--out", reportFilename,
      "-P", newPropertyFile.toString
    )
    cmdBase ++ odcConfig.extraArgs
  }

  private def createMavenOdcCommand(odcInstallation: OdcInstallation, scandirPrefix: String, path: Path, reportFilename: String): Seq[String] = {
    val cmdBase = Seq(
      mavenBin,
      "--file", s"${path}${separatorChar}pom.xml",
      "-X",
      "-U", // force update
      s"org.owasp:dependency-check-maven:${odcInstallation.odcVersion}:check",
      "-Dautoupdate=false",
      s"-Dformat=$OutputFormat",
      s"-DlogFile=${scandirPrefix}verbose.log",
      s"-DoutputDirectory=$reportFilename"
    )
    cmdBase ++ propsArgs(odcInstallation) ++ propsToArgs(dbProps) // TODO: fix credentials leak via /proc
  }

  private def dbProps = Map(
    "data.driver_path" -> odcDbConnectionConfig.driverJar,
    "data.driver_name" -> odcDbConnectionConfig.driverClass,
    "data.connection_string" -> odcDbConnectionConfig.url,
    "data.user" -> odcDbConnectionConfig.user,
    "data.password" -> odcDbConnectionConfig.password
  )

  private def propsToArgs(props: Traversable[(String, String)]): Traversable[String] = for((key, value) <- props) yield s"-D$key=$value"

  private def propsArgs(odcInstallation: OdcInstallation) = odcConfig.propertyFile.fold(Seq[String]()){ propertyFile =>
    val props = new Properties()
    val in = new FileInputStream(odcInstallation.workingDirectory.resolve(propertyFile).toFile)
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
      if(odcConfig.cleanTmpDir){
        rmdir(tmpDir)
      }else{
        Logger.info(s"tmpdir for the scan: $tmpDir")
      }
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
