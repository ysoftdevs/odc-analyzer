package services

import java.lang.{Boolean => JBoolean}
import java.util.{Map => JMap}

import _root_.org.owasp.dependencycheck.data.nvdcve.CveDB
import _root_.org.owasp.dependencycheck.dependency.VulnerableSoftware
import _root_.org.owasp.dependencycheck.utils.{DependencyVersion, DependencyVersionUtil, Settings}
import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import models.odc.OdcProperty
import models.odc.tables._
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}
import play.db.NamedDatabase

import scala.concurrent.{ExecutionContext, Future}

class OdcService @Inject()(@NamedDatabase("odc") protected val dbConfigProvider: DatabaseConfigProvider)(implicit executionContext: ExecutionContext) extends HasDatabaseConfigProvider[models.odc.profile.type]{

  import dbConfig.driver.api._

  def getVulnerableSoftware(id: Int): Future[Seq[com.ysoft.odc.VulnerableSoftware]] = {
    db.run(softwareVulnerabilities.joinLeft(cpeEntries).on((sv, ce) => sv.cpeEntryId === ce.id).filter{case (sv, ceo) => sv.vulnerabilityId === id}.result).map{rawRefs =>
      rawRefs.map{
        case (softVuln, Some((_, cpeEntry))) => com.ysoft.odc.VulnerableSoftware(allPreviousVersion = softVuln.includesAllPreviousVersions, name=cpeEntry.cpe)
      }
    }
  }

  def getReferences(id: Int): Future[Seq[com.ysoft.odc.Reference]] = db.run(references.filter(_.cveId === id).map(_.base).result)

  def getVulnerabilityDetails(id: Int): Future[Option[com.ysoft.odc.Vulnerability]] = {
    for {
      bareVulnOption <- db.run(vulnerabilities.filter(_.id === id).map(_.base).result).map(_.headOption)
      vulnerableSoftware <- getVulnerableSoftware(id)
      references <- getReferences(id)
    } yield bareVulnOption.map{bareVuln =>
      com.ysoft.odc.Vulnerability(
        name = bareVuln.cve,
        cweOption = bareVuln.cweOption,
        cvss = bareVuln.cvss,
        description = bareVuln.description,
        vulnerableSoftware = vulnerableSoftware,
        references = references
      )
    }
  }

  private def parseCpe(cpe: String) = {
    val sw = new VulnerableSoftware()
    sw.parseName(cpe)
    sw
  }

  def parseVersion(version: String): DependencyVersion = {
    DependencyVersionUtil.parseVersion(version)
  }

  /*def parseCpeVersion(cpe: String): DependencyVersion = { // strongly inspired by org.owasp.dependencycheck.data.nvdcve.CveDB.parseDependencyVersion(cpe: VulnerableSoftware): DependencyVersion
    def StringOption(s: String) = Option(s).filterNot(_.isEmpty)
    val sw = parseCpe(cpe)
    StringOption(sw.getVersion) match {
      case None ⇒ new DependencyVersion("-")
      case Some(bareVersionString) ⇒
        DependencyVersionUtil.parseVersion(
          StringOption(sw.getUpdate) match {
            case None ⇒ bareVersionString
            case Some(update) ⇒ s"$bareVersionString.$update"
          }
        )
    }
  }*/

  def findRelevantCpes(versionlessCpe: String, version: String) = {
    println(s"versionlessCpe: $versionlessCpe")
    val Seq("cpe", "/a", vendor, product, rest @ _*) = versionlessCpe.split(':').toSeq
    val cpesFuture = db.run(
      cpeEntries.filter(c =>
        c.vendor === vendor && c.product === product
      ).result
    )
    for(cpes <- cpesFuture){println(s"cpes: $cpes")}
    val cpesMapFuture = cpesFuture.map(_.toMap)
    val cpeIdsFuture = cpesFuture.map(_.map(_._1))
    val parsedVersion = parseVersion(version)
    val res = for{
      cpeIds <- cpeIdsFuture
      relevantVulnerabilities <- db.run(
        softwareVulnerabilities.join(vulnerabilities).on( (sv, v) => sv.vulnerabilityId === v.id)
          .filter{case (sv, v) => sv.cpeEntryId inSet cpeIds}.map{case (sv, v) ⇒ sv}.result
      ).map(_.groupBy(_.vulnerabilityId).mapValues(_.toSet))
      cpesMap <- cpesMapFuture
      //relevantVulnerabilities <- db.run(vulnerabilities.filter(_.id inSet relevantVulnerabilityIds).result)
    } yield relevantVulnerabilities.filter{case (vulnId, sv) => Option(CveDbHelper.matchSofware(
      vulnerableSoftware = sv.map(sv => cpesMap(sv.cpeEntryId).cpe -> sv.includesAllPreviousVersions).toMap,
      vendor = vendor,
      product = product,
      identifiedVersion = parsedVersion
    )).isDefined}
    res.map(_.values.toSet.flatten)
  }

  def loadUpdateProperties(): Future[Map[String, Long]] = db.run(properties.filter(_.id like "NVD CVE%").result).map(_.map{case OdcProperty(id, value) => (id, value.toLong)}.toMap)

  def loadLastDbUpdate(): Future[DateTime] = loadUpdateProperties().map(vals => new DateTime(vals.values.max)) // TODO: timezone (I don't care much, though)

}


private[services] object CveDbHelper {


  def matchSofware(vulnerableSoftware: Map[String, Boolean], vendor: String, product: String, identifiedVersion: DependencyVersion) = {
    if(Settings.getInstance() == null){
      Settings.initialize()// Initiallize ODC environment on first use; Needed for each thread.
    }
    val cd = new CveDB()
    import scala.collection.JavaConversions._
    val method = cd.getClass.getDeclaredMethod("getMatchingSoftware", classOf[JMap[String, JBoolean]], classOf[String], classOf[String], classOf[DependencyVersion])
    method.setAccessible(true)
    method.invoke(cd, mapAsJavaMap(vulnerableSoftware).asInstanceOf[JMap[String, JBoolean]], vendor, product, identifiedVersion)
  }
}

