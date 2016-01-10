package models

import slick.lifted.TableQuery

package object odc {

  val profile = slick.driver.MySQLDriver

  object tables {
    val cpeEntries = TableQuery[CpeEntries]
    val softwareVulnerabilities = TableQuery[SoftwareVulnerabilities]
    val vulnerabilities = TableQuery[Vulnerabilities]
    val references = TableQuery[References]
    val properties = TableQuery[OdcProperties]
  }

}
