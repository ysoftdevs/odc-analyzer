package views.html

import com.ysoft.odc.{GroupedDependency, Vulnerability}
object SuppressionXml {

  def forCpe(dep: GroupedDependency, cpe: String) = suppressionXmlPre(dep, <cpe>{cpe}</cpe>)

  def forVuln(dep: GroupedDependency, vuln: Vulnerability) = suppressionXmlPre(dep, <cve>{vuln.name}</cve>)

}
