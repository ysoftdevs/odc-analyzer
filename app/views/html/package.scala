package views

import models.User

package object html {
  type SortedMap[A, B] = scala.collection.SortedMap[A, B]
  type UserAwareRequest[T] = controllers.AuthenticatedController#UserAwareRequest[T]
  type DefaultRequest = UserAwareRequest[_]
}
