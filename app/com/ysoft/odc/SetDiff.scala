package com.ysoft.odc

class SetDiff[T](val oldSet: Set[T], val newSet: Set[T]) {
  lazy val added = newSet -- oldSet
  lazy val removed = oldSet -- newSet
  lazy val isEmpty = newSet == oldSet
  def nonEmpty = !isEmpty

  def map[U](f: T => U): SetDiff[U] = new SetDiff[U](
    oldSet = oldSet.map(f),
    newSet = newSet.map(f)
  )

}
