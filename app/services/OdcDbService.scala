package services

import java.lang.{Boolean => JBoolean}
import java.sql.{Array => _, _}
import java.util.{Properties, Map => JMap}

import _root_.org.owasp.dependencycheck.data.nvdcve.CveDB
import _root_.org.owasp.dependencycheck.dependency.{VulnerableSoftware => OdcVulnerableSoftware}
import _root_.org.owasp.dependencycheck.utils.{DependencyVersion, DependencyVersionUtil, Settings}
import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.mockrunner.mock.jdbc.MockConnection
import models.VulnerabilityOverview
import models.odc.tables._
import models.odc.{OdcProperty, Vulnerabilities}
import play.api.Logger
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}
import play.db.NamedDatabase

import scala.concurrent.{ExecutionContext, Future}

class OdcDbService @Inject()(@NamedDatabase("odc") protected val dbConfigProvider: DatabaseConfigProvider)(implicit executionContext: ExecutionContext) extends HasDatabaseConfigProvider[models.odc.profile.type]{

  import dbConfig.driver.api._

//  private def getVulnerableSoftware(id: Int): Future[Seq[com.ysoft.odc.VulnerableSoftware]] = {
//    db.run(softwareVulnerabilities.joinLeft(cpeEntries).on((sv, ce) => sv.cpeEntryId === ce.id).filter{case (sv, ceo) => sv.vulnerabilityId === id}.result).map{rawRefs =>
//      rawRefs.map{
//        case (softVuln, Some((_, cpeEntry))) => com.ysoft.odc.VulnerableSoftware(/*allPreviousVersion = softVuln.includesAllPreviousVersions, */name=cpeEntry.cpe)
//      }
//    }
//  }

  private def getReferences(id: Int): Future[Seq[com.ysoft.odc.Reference]] = db.run(references.filter(_.cveId === id).map(_.base).result)

  def getVulnerabilityDetails(id: Int): Future[Option[com.ysoft.odc.Vulnerability]] = getVulnerabilityDetails(_.id === id)

  def getVulnerabilityDetails(name: String): Future[Option[com.ysoft.odc.Vulnerability]] = getVulnerabilityDetails(_.cve === name)

  def getVulnerabilityDescription(name: String): Future[VulnerabilityOverview] = getVulnerabilityDetails(name).map(VulnerabilityOverview(name, _))

  private def getVulnerabilityDetails(cond: Vulnerabilities => Rep[Boolean]): Future[Option[com.ysoft.odc.Vulnerability]] = {
    db.run(vulnerabilities.filter(cond).result).map(_.headOption) flatMap { bareVulnOption =>
      bareVulnOption.fold[Future[Option[com.ysoft.odc.Vulnerability]]](Future.successful(None)) { case (id, bareVuln) =>
        for {
//          vulnerableSoftware <- getVulnerableSoftware(id)
          references <- getReferences(id)
        } yield Some(
          com.ysoft.odc.Vulnerability(
            name = bareVuln.cve,
            //cweOption = bareVuln.cweOption,
            cvss = bareVuln.cvss,
            description = bareVuln.description,
            //vulnerableSoftware = vulnerableSoftware,
            references = references
          )
        )
      }
    }
  }

  private def parseCpe(cpe: String) = {
    val sw = new OdcVulnerableSoftware()
    sw.parseName(cpe)
    sw
  }

  private def parseVersion(version: String): DependencyVersion = {
    DependencyVersionUtil.parseVersion(version)
  }

//  def findRelevantCpes(versionlessCpe: String, version: String) = {
//    println(s"versionlessCpe: $versionlessCpe")
//    val Seq("cpe", "/a", vendor, product, rest @ _*) = versionlessCpe.split(':').toSeq
//    val cpesFuture = db.run(
//      cpeEntries.filter(c =>
//        c.vendor === vendor && c.product === product
//      ).result
//    )
//    for(cpes <- cpesFuture){println(s"cpes: $cpes")}
//    val cpesMapFuture = cpesFuture.map(_.toMap)
//    val cpeIdsFuture = cpesFuture.map(_.map(_._1))
//    val parsedVersion = parseVersion(version)
//    val res = for{
//      cpeIds <- cpeIdsFuture
//      relevantVulnerabilities <- db.run(
//        softwareVulnerabilities.join(vulnerabilities).on( (sv, v) => sv.vulnerabilityId === v.id)
//          .filter{case (sv, v) => sv.cpeEntryId inSet cpeIds}.map{case (sv, v) ⇒ sv}.result
//      ).map(_.groupBy(_.vulnerabilityId).mapValues(_.toSet))
//      cpesMap <- cpesMapFuture
//      //relevantVulnerabilities <- db.run(vulnerabilities.filter(_.id inSet relevantVulnerabilityIds).result)
//    } yield relevantVulnerabilities.filter{case (vulnId, sv) => Option(CveDbHelper.matchSofware(
//      vulnerableSoftware = sv.map(sv => cpesMap(sv.cpeEntryId).cpe -> sv.includesAllPreviousVersions).toMap,
//      vendor = vendor,
//      product = product,
//      identifiedVersion = parsedVersion
//    )).isDefined}
//    res.map(_.values.toSet.flatten)
//  }

  private def loadUpdateProperties(): Future[Map[String, Long]] = db.run(properties.filter(_.id like "NVD CVE%").result).map(_.map{case OdcProperty(id, value) => (id, value.toLong)}.toMap)

  def loadLastDbUpdate(): Future[DateTime] = loadUpdateProperties().map { vals => new DateTime(vals.values.max*1000) } // TODO: timezone (I don't care much, though)

}

private[services] object CveDbHelper {

  class DummyDriver extends Driver{
    override def acceptsURL(url: String): Boolean = {url.startsWith("jdbc:dummy:")}
    override def jdbcCompliant(): Boolean = false
    override def connect(url: String, info: Properties): Connection = new MockConnection()
    override def getParentLogger = throw new SQLFeatureNotSupportedException()
    override def getPropertyInfo(url: String, info: Properties): Array[DriverPropertyInfo] = {Array()}
    override def getMinorVersion: Int = 1
    override def getMajorVersion: Int = 1
  }

  org.apache.geronimo.jdbc.DelegatingDriver.registerDriver(new DummyDriver())

  def matchSofware(vulnerableSoftware: Map[String, Boolean], vendor: String, product: String, identifiedVersion: DependencyVersion) = {
    if(Settings.getInstance() == null){
      Settings.initialize()// Initiallize ODC environment on first use; Needed for each thread.
      Settings.setString(Settings.KEYS.DB_CONNECTION_STRING, "jdbc:dummy:")
      // Workaround: At first initialization, it will complain that the DB is empty. On next initializations, it will not complain.
      try{new CveDB()}catch {case e: Throwable => Logger.info("A workaround-related exception, safe to ignore", e)}
    }
    val cd = new CveDB()
    import scala.collection.JavaConversions._
    val method = cd.getClass.getDeclaredMethod("getMatchingSoftware", classOf[JMap[String, JBoolean]], classOf[String], classOf[String], classOf[DependencyVersion])
    method.setAccessible(true)
    method.invoke(cd, mapAsJavaMap(vulnerableSoftware).asInstanceOf[JMap[String, JBoolean]], vendor, product, identifiedVersion)
  }
}

