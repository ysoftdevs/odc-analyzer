package services

import scala.concurrent.{ExecutionContext, Future}

trait Throttler {
  def throttle[T](f: => Future[T]): Future[T]
}

final class SingleFutureExecutionThrottler() (implicit executionContext: ExecutionContext) extends Throttler{
  private var nextFuture: Future[_] = Future.successful(null)

  def throttle[T](f: => Future[T]): Future[T] = synchronized{
    val newFuture = nextFuture.recover{ case _ => null}.flatMap(_ => f)
    nextFuture = newFuture
    newFuture
  }

}

final class NoThrottler() (implicit executionContext: ExecutionContext) extends Throttler{
  def throttle[T](f: => Future[T]): Future[T] = f
}
