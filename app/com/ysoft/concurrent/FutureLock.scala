package com.ysoft.concurrent

import java.util.concurrent.atomic.AtomicBoolean

import scala.concurrent.{ExecutionContext, Future}

trait FutureLock[T] {
  def whenLocked(cannotLock: => Future[T])(implicit executionContext: ExecutionContext): Future[T]
}

object FutureLock {

  def futureLock[T](lock: AtomicBoolean)(f: => Future[T]): FutureLock[T] = new FutureLock[T]() {
    override def whenLocked(cannotLock: => Future[T])(implicit executionContext: ExecutionContext): Future[T] = {
      if (lock.compareAndSet(/*expect = */ false, /*update = */ true)) {
        try {
          f.andThen { case _ =>
            val wasLocked = lock.getAndSet(false)
            if (!wasLocked) {
              throw new RuntimeException("The lock was not being held when trying to unlock")
            }
          }
        } catch {
          case e: Throwable =>
            // So, the Exception was raised before creation of the Future. As a result, the Future will not relase the lock.
            // In other words, its our responsibility to release the lock:
            val wasLocked = lock.getAndSet(false)
            if (!wasLocked) {
              throw new RuntimeException("The lock was not being held when throwing the following exception", e)
            }
            throw e
        }
      } else {
        cannotLock
      }
    }
  }


}
