package com.ysoft.odc

import javax.xml.parsers.SAXParserFactory

import scala.xml.{Elem, XML}

// copied from https://github.com/scala/scala-xml/issues/17 and slightly modified

object SecureXml {
  def loadString(xml: String): Elem = {
    val spf = SAXParserFactory.newInstance()
    spf.setFeature("http://xml.org/sax/features/external-general-entities", false)
    spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    val saxParser = spf.newSAXParser()
    XML.withSAXParser(saxParser).loadString(xml)
  }
}