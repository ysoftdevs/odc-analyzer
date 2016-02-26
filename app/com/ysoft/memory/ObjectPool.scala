package com.ysoft.memory

import java.lang.ref.{WeakReference => JWeakReference}
import java.util

class ObjectPool{

  private val objects = new util.WeakHashMap[Any, JWeakReference[Any]]()//new MapMaker().concurrencyLevel(1).weakKeys().weakValues().makeMap[Any, Any]()

  def apply[T](obj: T): T = synchronized{
    // The code is intentionally low-level for performance reasons. No Option[_] used for performance reasons, no scala.ref._ wrapper is used for memory overhead reasons.
    val res = objects.get(obj) match {
      case null => null
      case weakObj => weakObj.get()
    }
    if(res == null){
      objects.put(obj, new JWeakReference[Any](obj))
      obj
    }else{
      res.asInstanceOf[T]
    }
  }

}
