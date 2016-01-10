package controllers

import controllers.WarningSeverity.WarningSeverity
import play.twirl.api.Html

object WarningSeverity extends Enumeration {
  type WarningSeverity = Value
  // Order is important
  val Info = Value("info")
  val Warning = Value("warning")
  val Error = Value("error")
}

sealed abstract class Warning {
  def html: Html
  def id: String
  def allowSnoozes = true
  def severity: WarningSeverity
}

final case class IdentifiedWarning(id: String, html: Html, severity: WarningSeverity) extends Warning