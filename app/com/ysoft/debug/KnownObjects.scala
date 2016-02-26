package com.ysoft.debug

import java.util

import com.google.caliper.memory.ObjectVisitor.Traversal
import play.api.Logger

// We use Java collections because they can have the initial size configured
case class KnownObjects(
  objSet: java.util.HashSet[Any] = new util.HashSet[Any](),
  identitiesSet: java.util.Set[Any] = java.util.Collections.newSetFromMap(new util.IdentityHashMap[Any, java.lang.Boolean]())
){
  def visit(obj: AnyRef) = {
    val seen = !identitiesSet.add(obj)
    if(seen){
      Traversal.SKIP
    }else{
      objSet.add(obj)
      Traversal.EXPLORE
    }
  }

  def stats = (identitiesSet.size, objSet.size)

}
