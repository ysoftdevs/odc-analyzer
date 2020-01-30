package com.ysoft.odc.statistics

import controllers.DependencyCheckReportsParser.Result
import controllers._
import models.Library

case class LibDepStatistics(libraries: Set[(Int, Library)], dependencies: Set[GroupedDependency], failedProjects: FailedProjects){
  def vulnerableRatio = vulnerableDependencies.size.toDouble / dependencies.size.toDouble
  lazy val vulnerabilities: Set[Vulnerability] = dependencies.flatMap(_.vulnerabilities)
  lazy val vulnerabilitiesByName = vulnerabilities.map(v => v.name -> v).toMap
  lazy val vulnerabilityNames = vulnerabilities.map(_.name)
  lazy val vulnerabilitiesToDependencies: Map[Vulnerability, Set[GroupedDependency]] = vulnerableDependencies.flatMap(dep =>
    dep.vulnerabilities.map(vuln => (vuln, dep))
  ).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
  vulnerableDependencies.flatMap(dep => dep.vulnerabilities.map(_ -> dep)).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
  vulnerableDependencies.flatMap(dep => dep.vulnerabilities.map(_ -> dep)).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
  lazy val vulnerableDependencies = dependencies.filter(_.isVulnerable)
  lazy val (dependenciesWithCpe, dependenciesWithoutCpe) = dependencies.partition(_.hasCpe)
  lazy val cpeRatio = dependenciesWithCpe.size.toDouble / dependencies.size.toDouble
  //lazy val weaknesses = vulnerabilities.flatMap(_.cweOption)
  //lazy val weaknessesFrequency = LibDepStatistics.computeWeaknessesFrequency(vulnerabilities)
}

object LibDepStatistics{
  //private def computeWeaknessesFrequency(vulnerabilities: Set[Vulnerability]) = vulnerabilities.toSeq.map(_.cweOption).groupBy(identity).mapValues(_.size).map(identity).withDefaultValue(0)
  def apply(libraries: Set[(Int, Library)], dependencies: Set[GroupedDependency], parsedReports: Result): LibDepStatistics = LibDepStatistics(
    libraries = libraries,
    dependencies = dependencies,
    failedProjects = parsedReports.failedProjects
  )
}
