package com.ysoft.odc

import com.github.nscala_time.time.Imports._
import com.ysoft.memory.ObjectPool
import com.ysoft.odc.Confidence.Confidence
import controllers.ReportInfo
import models.{LibraryType, PlainLibraryIdentifier}

import scala.xml._


final case class SerializableXml private (xmlString: String) extends Serializable{
  def xml = SecureXml.loadString(xmlString) // TODO: cache

  override def equals(obj: scala.Any): Boolean = obj match {
    case SerializableXml(s/*, _*/) => s == this.xmlString
    case other => false
  }

  override def hashCode(): Int = 42+xmlString.hashCode

}

object SerializableXml{
  def apply(xml: Node): SerializableXml = SerializableXml(xml.toString())
  def apply(xml: NodeSeq): SerializableXml = SerializableXml(xml.toString())
}

final case class Analysis(scanInfo: SerializableXml, name: String, reportDate: DateTime, dependencies: Seq[Dependency])

final case class Hashes(sha1: String, md5: String){
  override def toString: String = s"Hashes(sha1=$sha1, md5=$md5)"
  def hashTuples: Seq[(String, String)] = Seq("sha1" -> sha1, "md5" -> md5)
  def serialized = s"$sha1-$md5"
}

object Hashes {
  def unserialize(str: String): com.ysoft.odc.Hashes =  str.split('-') match {
    case Array(sha1, md5) => Hashes(sha1 = sha1, md5 = md5)
  }
}

final case class Exclusion(sha1: String) extends AnyVal {
  def matches(dependency: Dependency): Boolean = dependency.sha1 == sha1
  def matches(group: GroupedDependency): Boolean = group.sha1 == sha1
}

final case class Evidence(source: String, name: String, value: String, confidence: String, evidenceType: String)

final case class Dependency(
  fileName: String,
  filePath: String,
  md5: String,
  sha1: String,
  description: String,
  evidenceCollected: Set[Evidence],
  identifiers: Seq[Identifier],
  suppressedIdentifiers: Seq[Identifier],
  license: String,
  vulnerabilities: Seq[Vulnerability],
  suppressedVulnerabilities: Seq[Vulnerability],
  relatedDependencies: Seq[RelatedDependency]
){

  def hashes = Hashes(sha1 = sha1, md5 = md5)

  def plainLibraryIdentifiers: Set[PlainLibraryIdentifier] = identifiers.flatMap(_.toLibraryIdentifierOption).toSet


  /*
  Method equals seems to be a CPU hog there. I am not sure if we can do something reasonable about it.
  We can compare by this.hashes, but, in such case, dependencies that differ in evidence will be considered the same if their JAR hashes are the same, which would break some sanity checks.
   */

}
final case class RelatedDependency(
  fileName: String,
  filePath: String,
  md5: String,
  sha1: String,
  description: String,
  identifiers: Seq[Identifier],
  suppressedIdentifiers: Seq[Identifier],
  license: String,
  vulnerabilities: Seq[Vulnerability],
  suppressedVulnerabilities: Seq[Vulnerability]
){
}

/**
 * A group of dependencies having the same fingerprints
 *
 * @param dependencies
 */
final case class GroupedDependency(dependencies: Map[Dependency, Set[ReportInfo]]) {
  def parsedDescriptions: Seq[Seq[Seq[String]]] = descriptions.toSeq.sorted.map(_.trim.split("\n\n").filterNot(_=="").toSeq.map(_.split("\n").toSeq))
  def isVulnerable: Boolean = vulnerabilities.nonEmpty
  def maxCvssScore = (Seq(None) ++ vulnerabilities.map(_.cvssScore)).max
  def descriptions = dependencies.keySet.map(_.description)
  def projects = dependencies.values.flatten.toSet
  def fileNames = dependencies.keySet.map(_.fileName)
  val hashes: Hashes = dependencies.keys.head.hashes // valid since all deps in a group have the same hashes
  def sha1: String = hashes.sha1
  def identifiers: Set[Identifier] = dependencies.keySet.flatMap(_.identifiers)
  def evidenceCollected: Set[Evidence] = dependencies.keySet.flatMap(_.evidenceCollected)
  def suppressedIdentifiers: Set[Identifier] = dependencies.keySet.flatMap(_.suppressedIdentifiers)
  def mavenIdentifiers = identifiers.filter(_.identifierType == "maven")
  def cpeIdentifiers = identifiers.filter(_.identifierType == "cpe")
  def vulnerabilities: Set[Vulnerability] = dependencies.keySet.flatMap(_.vulnerabilities)
  def suppressedVulnerabilities: Set[Vulnerability] = dependencies.keySet.flatMap(_.suppressedVulnerabilities)
  def plainLibraryIdentifiers: Set[PlainLibraryIdentifier] = identifiers.flatMap(_.toLibraryIdentifierOption)
  def hasCpe: Boolean = cpeIdentifiers.nonEmpty
  def identifiersWithFilenames(threshold: Confidence) = {
    def fileNameIdentifiers = fileNames.toIndexedSeq.sorted.map(filename => Identifier(
      identifierType = "file",
      name = filename,
      confidence = Confidence.Highest,
      url = ""
    ))
    val identifiersSeq =
      if(identifiers.exists(_.confidence >= threshold)) identifiers
      else fileNameIdentifiers ++ identifiers // If we don't know any reliable identifier, add filenames
    identifiersSeq.toIndexedSeq.sortBy(_.name)
  }
}

object GroupedDependency{
  private val groupToSet = (_: Seq[(Dependency, ReportInfo)]).map(_._2).toSet // reduces number of lambda instances
  def apply(deps: Seq[(Dependency, ReportInfo)]): GroupedDependency = {
    GroupedDependency(deps.groupBy(_._1).mapValues(groupToSet))
  } // TODO: the groupBy seems to be a CPU hog (because of GroupedDependency.equals); The mapValues is lazy, so its repeated might also be a performance hog, but I doubt that values are used frequently.
}

object Confidence extends Enumeration {
  type Confidence = Value
  // Order is important
  val Low = Value("LOW")
  val Medium = Value("MEDIUM")
  val High = Value("HIGH")
  val Highest = Value("HIGHEST")

}

final case class Reference(source: String, url: String, name: String)

final case class VulnerableSoftware(allPreviousVersion: Boolean, name: String){
  def containsVersion = name.count(_==':') >= 4
  def isVersionless = !containsVersion
}

final case class CvssRating(score: Option[Double], authenticationr: Option[String], availabilityImpact: Option[String], accessVector: Option[String], integrityImpact: Option[String], accessComplexity: Option[String], confidentialImpact: Option[String])

final case class CWE private(name: String) /*extends AnyVal*/{ // extends AnyVal prevents pooling
  override def toString = name
  def brief = name.takeWhile(_ != ' ')
  def numberOption: Option[Int] = if(brief startsWith "CWE-") try {
    Some(brief.substring(4).toInt)
  } catch {
    case _: NumberFormatException => None
  } else None
}

object CWE{
  private val cwePool = new ObjectPool()
  def forIdentifierWithDescription(name: String) = cwePool(new CWE(name))
}

final class RichBoolean(val value: Boolean) extends AnyVal{
  @inline def ==> (right: => Boolean): Boolean = !value || right
}
object RichBoolean{
  @inline implicit def toRichBoolean(value: Boolean) = new RichBoolean(value)
}

final case class Vulnerability(name: String, cweOption: Option[CWE], cvss: CvssRating, description: String, vulnerableSoftware: Seq[VulnerableSoftware], references: Seq[Reference]){
  import RichBoolean.toRichBoolean
  def cvssScore = cvss.score
  def likelyMatchesOnlyWithoutVersion(dependencyIdentifiers: Set[Identifier]) = dependencyIdentifiers.forall { id =>
    // Rather a quick hack. Maybe it would be better to do this check in ODC.
    val versionlessCpeIdentifierOption = id.toCpeIdentifierOption.map(_.split(':').take(4).mkString(":"))
    versionlessCpeIdentifierOption.fold(true){ versionlessCpeIdentifier =>
      vulnerableSoftware.forall(vs => vs.name.startsWith(versionlessCpeIdentifier) ==> vs.isVersionless)
    }
  }
}

final case class Identifier(name: String, confidence: Confidence.Confidence, url: String, identifierType: String) {
  def toLibraryIdentifierOption: Option[PlainLibraryIdentifier] = {
    if(identifierType == "maven"){
      val groupId::artifactId::_ = name.split(':').toList
      Some(PlainLibraryIdentifier(libraryType = LibraryType.Maven, libraryIdentifier = s"$groupId:$artifactId"))
    }else{
      None
    }
  }
  def toCpeIdentifierOption: Option[String] = identifierType match {
    case "cpe" => Some(name)
    case _ => None
  }
  //def isClassifiedInSet(set: Set[PlainLibraryIdentifier]): Boolean = toLibraryIdentifierOption.exists(set contains _)
}

object OdcParser {

  private val vulnPool = new ObjectPool()
  private val evidencePool = new ObjectPool()
  private val relatedDependencyPool = new ObjectPool()
  private val dependencyPool = new ObjectPool()
  private val identifierPool = new ObjectPool()
  private val vulnerableSoftwarePool = new ObjectPool()

  def filterWhitespace(node: Node) = node.nonEmptyChildren.filter{
    case t: scala.xml.Text if t.text.trim == "" => false
    case t: scala.xml.PCData if t.text.trim == "" => false
    case _ => true
  }

  def checkElements(node: Node, knownElements: Set[String]) {
    val subelementNames = filterWhitespace(node).map(_.label).toSet
    val unknownElements = subelementNames -- knownElements
    if(unknownElements.nonEmpty){
      sys.error("Unknown elements for "+node.label+": "+unknownElements)
    }
  }

  private def getAttributes(data: MetaData): List[String] = data match {
    case Null => Nil
    case Attribute(key, _, next) => key :: getAttributes(next)
  }

  def checkParams(node: Node, knownParams: Set[String]) {
    val paramNames = getAttributes(node.attributes).toSet
    val unknownParams = paramNames -- knownParams
    if(unknownParams.nonEmpty){
      sys.error("Unknown params for "+node.label+": "+unknownParams)
    }
  }


  def parseVulnerableSoftware(node: Node): VulnerableSoftware = {
    checkElements(node, Set("#PCDATA"))
    checkParams(node, Set("allPreviousVersion"))
    if(node.label != "software"){
      sys.error(s"Unexpected element for vulnerableSoftware: ${node.label}")
    }
    vulnerableSoftwarePool(VulnerableSoftware(
      name = node.text,
      allPreviousVersion = node.attribute("allPreviousVersion").map(_.text).map(Map("true"->true, "false"->false)).getOrElse(false)
    ))
  }

  def parseReference(node: Node): Reference = {
    checkElements(node, Set("source", "url", "name"))
    checkParams(node, Set())
    if(node.label != "reference"){
      sys.error(s"Unexpected element for reference: ${node.label}")
    }
    Reference(
      source = (node \ "source").text,
      url = (node \ "url").text,
      name = (node \ "name").text
    )
  }

  def parseVulnerability(node: Node, expectedLabel: String = "vulnerability"): Vulnerability = {
    checkElements(node, Set("name", "severity", "cwe", "cvssScore", "description", "references", "vulnerableSoftware", "cvssAuthenticationr", "cvssAvailabilityImpact", "cvssAccessVector", "cvssIntegrityImpact", "cvssAccessComplexity", "cvssConfidentialImpact"))
    if(node.label != expectedLabel){
      sys.error(s"Unexpected element for vuln: ${node.label}")
    }
    def t(ns: NodeSeq) = {
      ns match {
        case Seq() => None
        case Seq(one) =>
          one.attributes match {
            case Null =>
              one.child match {
                case Seq(hopefullyTextChild) =>
                  hopefullyTextChild match {
                    case Text(data) => Some(data)
                  }
              }
          }
      }
    }
    vulnPool(Vulnerability(
      name = (node \ "name").text,
      //severity = (node \ "severity"), <- severity is useless, as it is computed from cvssScore :D
      cweOption = (node \ "cwe").headOption.map(_.text).map(CWE.forIdentifierWithDescription),
      description = (node \ "description").text,
      cvss = CvssRating(
        score = (node \ "cvssScore").headOption.map(_.text.toDouble),
        authenticationr = t(node \ "cvssAuthenticationr"),
        availabilityImpact = t(node \ "cvssAvailabilityImpact"),
        accessVector = t(node \ "cvssAccessVector"),
        integrityImpact = t(node \ "cvssIntegrityImpact"),
        accessComplexity = t(node \ "cvssAccessComplexity"),
        confidentialImpact = t(node \ "cvssConfidentialImpact")
      ),
      references = (node \ "references").flatMap(filterWhitespace).map(parseReference(_)),
      vulnerableSoftware = (node \ "vulnerableSoftware").flatMap(filterWhitespace).map(parseVulnerableSoftware)
    ))
  }

  def parseIdentifier(node: Node, expectedLabel: String, parseConfidence: Boolean = true): Identifier = {
    if(node.label != expectedLabel){
      sys.error("Unexpected label for identifier: "+node.label)
    }
    checkElements(node, Set("name", "url"))
    checkParams(node, Set("type", "confidence"))
    val ExtractPattern = """\((.*)\)""".r
    identifierPool(Identifier(
      name = (node \ "name").text match {
        case ExtractPattern(text) => text
      },
      url = (node \ "url").text,
      identifierType = node.attribute("type").get.text,
      confidence = if(parseConfidence) Confidence.withName(node.attribute("confidence").get.text) else Confidence.Medium
    ))
  }

  def parseDependency(node: Node): Dependency = {
    checkElements(node, Set("fileName", "filePath", "md5", "sha1", "description", "evidenceCollected", "identifiers", "license", "vulnerabilities", "relatedDependencies"))
    checkParams(node, Set())
    val (vulnerabilities: Seq[Node], suppressedVulnerabilities: Seq[Node]) = (node \ "vulnerabilities").headOption.map(filterWhitespace).getOrElse(Seq()).partition(_.label == "vulnerability")
    val (identifiers, suppressedIdentifiers) = (node \ "identifiers").headOption.map(filterWhitespace).getOrElse(Seq()).partition(_.label == "identifier")
    dependencyPool(Dependency(
      fileName = (node \ "fileName").text,
      filePath = (node \ "filePath").text,
      md5 = (node \ "md5").text,
      sha1 = (node \ "sha1").text,
      description = (node \ "description").text,
      evidenceCollected = filterWhitespace((node \ "evidenceCollected").head).map(parseEvidence).toSet,
      identifiers = identifiers.map(parseIdentifier(_, "identifier")),
      suppressedIdentifiers = suppressedIdentifiers.map(parseIdentifier(_, "suppressedIdentifier")),
      license = (node \ "license").text,
      vulnerabilities = vulnerabilities.map(parseVulnerability(_)),
      suppressedVulnerabilities = suppressedVulnerabilities.map(parseVulnerability(_, "suppressedVulnerability")),
      relatedDependencies = (node \ "relatedDependencies" \ "relatedDependency").map(parseRelatedDependency)
    ))
  }

  def parseRelatedDependency(node: Node): RelatedDependency = {
    checkElements(node, Set("fileName", "filePath", "md5", "sha1", "description", "evidenceCollected", "identifier", "license", "vulnerabilities", "relatedDependencies"))
    checkParams(node, Set())
    val (vulnerabilities: Seq[Node], suppressedVulnerabilities: Seq[Node]) = (node \ "vulnerabilities").headOption.map(filterWhitespace).getOrElse(Seq()).partition(_.label == "vulnerability")
    relatedDependencyPool(RelatedDependency(
      fileName = (node \ "fileName").text,
      filePath = (node \ "filePath").text,
      md5 = (node \ "md5").text,
      sha1 = (node \ "sha1").text,
      description = (node \ "description").text,
      identifiers = (node \ "identifier").map(parseIdentifier(_, "identifier", parseConfidence = false)),
      suppressedIdentifiers = (node \ "suppressedIdentifier").map(parseIdentifier(_, "suppressedIdentifier", parseConfidence = false)),
      license = (node \ "license").text,
      vulnerabilities = vulnerabilities.map(parseVulnerability(_)),
      suppressedVulnerabilities = suppressedVulnerabilities.map(parseVulnerability(_, "suppressedVulnerability"))
    ))
  }

  def parseEvidence(node: Node): Evidence = {
    if(node.label != "evidence"){
      sys.error(s"Unexpected element for evidence: ${node.label}")
    }
    checkElements(node, Set("source", "name", "value"))
    checkParams(node, Set("confidence", "type"))
    evidencePool(Evidence(
      source = (node \ "source").text,
      name = (node \ "name").text,
      value = (node \ "value").text,
      confidence = node.attribute("confidence").map(_.text).get,
      evidenceType = node.attribute("type").map(_.text).get
    ))
  }

  def parseDependencies(nodes: NodeSeq): Seq[Dependency] = nodes.map(parseDependency(_))

  def parseXmlReport(data: Array[Byte]) = {
    val xml = SecureXml.loadString(new String(data, "utf-8"))
    Analysis(
      scanInfo = SerializableXml((xml \ "scanInfo").head),
      name = (xml \ "projectInfo" \ "name").text,
      reportDate = DateTime.parse((xml \ "projectInfo" \ "reportDate").text),
      dependencies = parseDependencies(xml \ "dependencies" \ "dependency").toIndexedSeq
    )
  }

}
