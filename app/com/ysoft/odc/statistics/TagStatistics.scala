package com.ysoft.odc.statistics

import models.LibraryTag

case class TagStatistics(tagRecord: (Int, LibraryTag), stats: LibDepStatistics){
  def tag: LibraryTag = tagRecord._2
  def tagId: Int = tagRecord._1
}
