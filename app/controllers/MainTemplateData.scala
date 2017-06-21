package controllers

import modules.TemplateCustomization

object MainTemplateData{
  implicit def createMainTemplateData(implicit templateCustomization: TemplateCustomization): MainTemplateData = MainTemplateData(templateCustomization)
}

case class MainTemplateData(templateCustomization: TemplateCustomization)