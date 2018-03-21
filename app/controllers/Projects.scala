package controllers

class Projects (
  val projectMap: Map[String, String],
  private val teamLeaders: Map[TeamId, String],
  val projectToTeams: Map[String, Set[TeamId]]
) {
  val projectSet: Set[String] = projectMap.keySet

  private val projectAndTeams = projectToTeams.toSeq.flatMap{case (project, teams) => teams.map(team => (project, team))}

  private val teamsToProjects = projectAndTeams.groupBy(_._2).mapValues(_.map(_._1).toSet).map(identity)

  private val teamsById: Map[String, Team] = for{
    (team, projectNames) <- teamsToProjects
  } yield team.id -> Team(
    id = team.id,
    name = team.name,
    leader = teamLeaders(team),
    projectNames = projectNames
  )

  def teamById(id: String): Team = teamsById(id)
  def getTeamById(id: String): Option[Team] = teamsById.get(id)

  def teamSet: Set[Team] = teamsById.values.toSet

  def teamsByProjectId(projectId: String): Set[TeamId] = projectToTeams.filter{case (projectSpecification, _) =>
    val projectName = projectMap(projectId)
    (projectSpecification == projectName) || (projectSpecification startsWith s"$projectName:")
  }.values.flatten.toSet

}
