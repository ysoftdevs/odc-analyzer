package com.ysoft.html

import play.twirl.api.{Html, HtmlFormat}

object HtmlWithText{

  def justText(s: String): HtmlWithText = HtmlWithText(html = HtmlFormat.empty, text = s)
  def justHtml(h: Html): HtmlWithText = HtmlWithText(html = h, text = "")
  def justHtml(h: String): HtmlWithText = justHtml(Html(h))
  def plainText(s: String): HtmlWithText = HtmlWithText(text = s, html = HtmlFormat.escape(s))

  implicit class RichHtmlWithTextTraversable(val traversable: Traversable[HtmlWithText]) extends AnyVal {
    def mkHtmlWithText(textSep: String, htmlSep: Html): HtmlWithText = HtmlWithText(
      text = traversable.map(_.text).mkString("\n"),
      html = Html(traversable.map(_.html).mkString(htmlSep.toString()))
    )
    def mkHtmlWithText(sep: HtmlWithText): HtmlWithText = mkHtmlWithText(sep.text, sep.html)

  }

}
case class HtmlWithText(html: Html, text: String){
  def +(other: HtmlWithText) = HtmlWithText(
    html = Html(this.html.toString + other.html.toString),
    text = this.text + other.text
  )
}
