package controllers

import javax.inject.Inject

import play.api.Configuration

class Projects @Inject() (configuration: Configuration) {
  import scala.collection.JavaConversions._
  val projectMap = {
    val projectsConfig = configuration.getObject("yssdc.projects").getOrElse(sys.error("yssdc.projects is not set")).toConfig
    projectsConfig.entrySet().map( k => k.getKey -> projectsConfig.getString(k.getKey)).toMap
  }
  val projectSet = projectMap.keySet
  private val teamIdSet = configuration.getStringSeq("yssdc.teams").getOrElse(sys.error("yssdc.teams is not set")).map(TeamId).toSet
  private val teamsByIds = teamIdSet.map(t => t.id -> t).toMap
  private val teamLeaders = {
    import scala.collection.JavaConversions._
    configuration.getObject("yssdc.teamLeaders").getOrElse(sys.error("yssdc.teamLeaders is not set")).map{case(k, v) =>
      TeamId(k) -> v.unwrapped().asInstanceOf[String]
    }
  }
  {
    val extraTeams = teamLeaders.keySet -- teamIdSet
    if(extraTeams.nonEmpty){
      sys.error(s"Some unexpected teams: $extraTeams")
    }
  }

  private def existingTeamId(s: String): TeamId = teamsByIds(s)

  private val projectToTeams = configuration.getObject("yssdc.projectsToTeams").get.mapValues{_.unwrapped().asInstanceOf[java.util.List[String]].map(c =>
    existingTeamId(c)
  ).toSet}.map(identity)

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

  def teamById(id: String) = teamsById(id)

  def teamSet = teamsById.values.toSet

}
