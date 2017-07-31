package services

case class DependencyNotFoundException(val dependency: String) extends Exception(s"Dependency $dependency is not found"){

}
