package controllers

final case class TeamId(id: String) extends AnyVal {
  def name = id
}

final case class Team(id: String, name: String, leader: String, projectNames: Set[String])

// TODO: rename to something more sane. It is maybe rather FilteringData now.
final case class ProjectsWithSelection(filter: Filter, projectsWithReports: ProjectsWithReports, teams: Set[Team]) {
  def isProjectSpecified: Boolean = filter.filters
  def selectorString = filter.selector
  def projectNameText: String = filter.descriptionText
}
