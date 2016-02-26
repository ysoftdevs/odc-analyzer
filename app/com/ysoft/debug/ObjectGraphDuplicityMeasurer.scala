package com.ysoft.debug

import java.util

import com.google.caliper.memory.ObjectVisitor.Traversal
import com.google.caliper.memory.{Chain, ObjectExplorer, ObjectVisitor}

import scala.collection.mutable

object ObjectGraphDuplicityMeasurer {

  def measureUnique(obj: AnyRef) = {
    ObjectExplorer.exploreObject(obj, new ObjectVisitor[((Int, Int), Map[Class[_], (Int, Int)])](){
      val all = KnownObjects(
        objSet = new util.HashSet[Any](),
        identitiesSet = java.util.Collections.newSetFromMap(new util.IdentityHashMap[Any, java.lang.Boolean]())
      )

      val classMap = mutable.Map[Class[_], KnownObjects]()
      def forClass(cl: Class[_]) = classMap.contains(cl) match{
        case true => classMap(cl)
        case false =>
          val kn = KnownObjects()
          classMap(cl) = kn
          kn
      }

      override def visit(chain: Chain): Traversal = {
        val value = chain.getValue
        if(chain.isPrimitive || value == null || classOf[Enum[_]].isAssignableFrom(chain.getValueType) || value.isInstanceOf[Class[_]] ){
          Traversal.SKIP
        }else{
          val res = all.visit(value)
          forClass(value.getClass).visit(value)
          res
        }
      }

      override def result() = (all.stats, classMap.toMap.mapValues(_.stats).map(identity))

    })
  }

}
