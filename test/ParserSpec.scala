import java.io.{ByteArrayOutputStream, InputStream}

import org.specs2.mutable.Specification
import com.ysoft.odc._

class ParserSpec  extends Specification {
  private def readStream(in: InputStream): Array[Byte] = {
    val buff = new Array[Byte](1024)
    val out = new ByteArrayOutputStream()
    var n = 0
    while({
      n = in.read(buff)
      n != -1
    }){
      out.write(buff, 0, n)
    }
    out.toByteArray
  }

  private def parseReport(reportResourceName: String) = {
    val reportBytes: Array[Byte] = readStream(getClass.getResourceAsStream(reportResourceName))
    OdcParser.parseXmlReport(reportBytes)
  }

  private def findDependency(identifierType: String, name: String)(implicit report: Analysis) = {
    val found = report.dependencies.filter(_.identifiers.exists(i => i.identifierType == identifierType && i.name == name))
    found.size match {
      case 0 => sys.error(s"Dependency $identifierType: $name not found")
      case 1 => (found.toSeq)(0)
      case _ => sys.error(s"Multiple dependencies $identifierType: $name found: $found")
    }
  }

  private def shouldHaveIdentifier(dep: Dependency, identifierType: String, name: String) = s"should have identifier $identifierType: $name" >> {
    (dep.identifiers.exists((i: Identifier) => (i.identifierType == identifierType) && (i.name == name))) should beTrue
  }


  "Maven report" >> {
    implicit val report = parseReport("dependency-check-report-maven.xml")
    "groupId" >> {report.groupId shouldEqual "com.ysoft.security"}
    println(report.dependencies.map(_.identifiers).mkString("\n\n"))
    "commons-collections" >> {
      val dep = findDependency("maven", "commons-collections:commons-collections:3.2.1")
      dep.vulnerabilities.size shouldEqual 3
      //shouldHaveIdentifier(dep, "cpe", "cpe:/a:apache:commons_collections:3.2.1")
    }
    "commons-cli" >> {
      val dep = findDependency("maven", "commons-cli:commons-cli:1.4")
      dep.vulnerabilities.size shouldEqual 0
      //shouldHaveIdentifier(dep, "cpe", "cpe:/a:cli_project:cli:1.4")
    }
    "jackson-databind" >> {
      val dep = findDependency("maven", "com.fasterxml.jackson.core:jackson-databind:2.9.7")
      dep.vulnerabilities.size shouldEqual 15
      //shouldHaveIdentifier(dep, "cpe", "cpe:/a:fasterxml:jackson:2.9.7")
      //shouldHaveIdentifier(dep, "cpe", "cpe:/a:fasterxml:jackson-databind:2.9.7")
    }
  }
}
