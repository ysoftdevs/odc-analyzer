package com.ysoft.odc

import controllers.WarningSeverity.WarningSeverity
import controllers.{IdentifiedWarning, ReportInfo, Warning}
import play.twirl.api.{Html, HtmlFormat}

object Checks {

  def differentValues(id: String, name: String, severity: WarningSeverity)(f: Map[ReportInfo, Analysis] => Traversable[_]) = { (data: Map[ReportInfo, Analysis]) =>
    val variants = f(data)
    if(variants.size > 1){
      Some(IdentifiedWarning(id, HtmlFormat.escape(s"different $name!"), severity))
    }else{
      None
    }
  }

  def badValues(id: String, name: String, severity: WarningSeverity)(f: (ReportInfo, Analysis) => Option[Html]): Map[ReportInfo, Analysis] => Option[Warning] = { (data: Map[ReportInfo, Analysis]) =>
    val badValues = data.collect(Function.unlift{case (analysisName, analysis) => f(analysisName, analysis).map(analysisName -> _)}).toSeq
    if(badValues.size > 0) Some(IdentifiedWarning(id, views.html.warnings.badValues(name, badValues), severity))
    else None
  }

  def badGroupedDependencies[C <: Traversable[_]](id: String, name: String, severity: WarningSeverity)(f: Seq[GroupedDependency] => C)(show: C => Traversable[_] = {(x: C) => x}, exclusions: Set[Exclusion] = Set()): (Seq[GroupedDependency] => Option[Warning]) = { (data: Seq[GroupedDependency]) =>
    val badItems = f(data.filterNot(ds => exclusions.exists(_.matches(ds))))
    if(badItems.size > 0){
      Some(IdentifiedWarning(id, views.html.warnings.badGroupedDependencies(name, badItems.size, show(badItems)), severity))
    }else{
      None
    }
  }

}
