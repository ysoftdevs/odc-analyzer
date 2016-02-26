package controllers

import java.sql.BatchUpdateException

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.google.inject.name.Named
import models._
import play.api.Logger
import play.api.data.Forms._
import play.api.data._
import play.api.db.slick.{DatabaseConfigProvider, HasDatabaseConfigProvider}
import play.api.http.ContentTypes
import play.api.i18n.MessagesApi
import play.api.libs.json._
import play.api.mvc._
import play.api.routing.JavaScriptReverseRouter
import play.twirl.api.Txt
import services.{LibrariesService, LibraryTagAssignmentsService, TagsService}
import views.html.DefaultRequest

import scala.collection.immutable.SortedMap
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

object ApplicationFormats{
  implicit val libraryTagPairFormat = Json.format[LibraryTagPair]
  implicit val libraryTagAssignmentFormat = Json.format[LibraryTagAssignment]
  //implicit val libraryTypeFormat = Json.format[LibraryType]
  //implicit val plainLibraryIdentifierFormat = Json.format[PlainLibraryIdentifier]
  //implicit val libraryFormat = Json.format[Library]
  implicit val libraryTagFormat = Json.format[LibraryTag]
}

object export {
  import ApplicationFormats._
  final case class AssignedTag(name: String, contextDependent: Boolean)
  final case class TaggedLibrary(identifier: String, classified: Boolean, tags: Seq[AssignedTag]){
    def toLibrary = Library(plainLibraryIdentifier = PlainLibraryIdentifier.fromString(identifier), classified = classified)
  }
  final case class Export(libraryMapping: Seq[TaggedLibrary], tags: Seq[LibraryTag])
  implicit val assignedTagFormats = Json.format[AssignedTag]
  implicit val taggedLibraryFormats = Json.format[TaggedLibrary]
  implicit val exportFormats = Json.format[Export]
}


class Application @Inject() (
                              reportsParser: DependencyCheckReportsParser,
                              reportsProcessor: DependencyCheckReportsProcessor,
                              projectReportsProvider: ProjectReportsProvider,
                              @Named("missing-GAV-exclusions") missingGAVExclusions: MissingGavExclusions,
                              tagsService: TagsService,
                              librariesService: LibrariesService,
                              libraryTagAssignmentsService: LibraryTagAssignmentsService,
                              protected val dbConfigProvider: DatabaseConfigProvider,
                              val messagesApi: MessagesApi,
                              val env: AuthEnv
) extends AuthenticatedController with HasDatabaseConfigProvider[models.profile.type]{

  import ApplicationFormats._
  import dbConfig.driver.api._
  import models.tables.snoozesTable
  import reportsProcessor.processResults
  import secureRequestConversion._

  val dateFormatter = DateTimeFormat.forPattern("dd-MM-yyyy")
  val emptySnoozeForm = Form(mapping(
    "until" -> text.transform(LocalDate.parse(_, dateFormatter), (_: LocalDate).toString(dateFormatter)).verifying("Must be a date in the future", _ > LocalDate.now),
    //"snoozed_object_identifier" -> text,
    "reason" -> text(minLength = 3, maxLength = 255)
  )(ObjectSnooze.apply)(ObjectSnooze.unapply))

  def loadSnoozes() = {
    val now = LocalDate.now
    import models.jodaSupport._
    for{
      bareSnoozes <- db.run(snoozesTable.filter(_.until > now).result) : Future[Seq[(Int, Snooze)]]
      snoozes = bareSnoozes.groupBy(_._2.snoozedObjectId).mapValues(ss => SnoozeInfo(emptySnoozeForm, ss.sortBy(_._2.until))).map(identity)
    } yield snoozes.withDefaultValue(SnoozeInfo(emptySnoozeForm, Seq()))
  }

  def purgeCache(versions: Map[String, Int], next: String) = Action {
    projectReportsProvider.purgeCache(versions)
    next match {
      case "index" => Redirect(routes.Application.index(versions))
      case _ => Ok(Txt("CACHE PURGED"))
    }
  }

  def index(versions: Map[String, Int]) = ReadAction.async{ implicit req =>
    loadSnoozes() flatMap { snoozes =>
      indexPage(versions)(snoozes, securedRequestToUserAwareRequest(req))
    }
  }

  def indexPage(requiredVersions: Map[String, Int])(implicit snoozes: SnoozesInfo, requestHeader: DefaultRequest) = {
    val (lastRefreshTimeFuture, resultsFuture) = projectReportsProvider.resultsForVersions(requiredVersions)
    processResults(resultsFuture, requiredVersions).flatMap{ case (vulnerableDependencies, allWarnings, groupedDependencies) =>
      Logger.debug("indexPage: Got results")
      //val unclassifiedDependencies = groupedDependencies.filterNot(ds => MissingGAVExclusions.exists(_.matches(ds))).filterNot(_.identifiers.exists(_.isClassifiedInSet(classifiedSet)))
      for{
        knownDependencies <- librariesService.allBase
        _ = Logger.debug("indexPage: #1")
        includedDependencies = groupedDependencies.filterNot(missingGAVExclusions.isExcluded)
        _ = Logger.debug("indexPage: #2")
        unknownDependencies = includedDependencies.flatMap(_.identifiers.flatMap(_.toLibraryIdentifierOption)).toSet -- knownDependencies.map(_.plainLibraryIdentifier).toSet
        _ = Logger.debug("indexPage: #3")
        _ <- librariesService.insertMany(unknownDependencies.map(Library(_, classified = false)))
        _ = Logger.debug("indexPage: #3")
        unclassifiedDependencies <- librariesService.unclassified
        _ = Logger.debug("indexPage: #4")
        allTags <- tagsService.all
        _ = Logger.debug("indexPage: #6")
        allTagsMap = allTags.toMap
        _ = Logger.debug("indexPage: #7")
        tagsWithWarning = allTags.collect(Function.unlift{case (id, t: LibraryTag) => t.warningOrder.map(_ => (id, t))}).sortBy(_._2.warningOrder)
        _ = Logger.debug("indexPage: #8")
        librariesForTagsWithWarningUnsorted <- librariesService.librariesForTags(tagsWithWarning.map(_._1))
        _ = Logger.debug("indexPage: #9")
        librariesForTagsWithWarning = SortedMap(librariesForTagsWithWarningUnsorted.groupBy(_._1).toSeq.map{case (tagId, lr) => (tagId, allTagsMap(tagId)) -> lr.map(_._2) } : _*)(Ordering.by(t => (t._2.warningOrder, t._1)))
        _ = Logger.debug("indexPage: #10")
        relatedDependenciesTags <- librariesService.byTags(unclassifiedDependencies.map(_._1).toSet ++ librariesForTagsWithWarning.values.flatten.map(_._1).toSet)
        _ = Logger.debug("indexPage: #11")
        lastRefreshTime <- lastRefreshTimeFuture
      } yield {
        Logger.debug("indexPage: Got all ingredients")
        /*val (global, classes) = ObjectGraphDuplicityMeasurer.measureUnique((vulnerableDependencies, allWarnings, groupedDependencies))
        Logger.debug("(all,unique): "+global)
        Logger.debug(classes.toIndexedSeq.sortBy(x => (x._2, x._1.getName)).mkString("\n"))
        Logger.debug("footprint: "+ObjectGraphMeasurer.measure((vulnerableDependencies, allWarnings, groupedDependencies)))
        //Logger.debug("footprint: "+ObjectGraphMeasurer.measure(Array((vulnerableDependencies, allWarnings, groupedDependencies))))*/
        Ok(views.html.index(
          vulnerableDependencies = vulnerableDependencies,
          warnings = allWarnings,
          librariesForTagsWithWarning = librariesForTagsWithWarning,
          unclassifiedDependencies = unclassifiedDependencies,
          groupedDependencies = groupedDependencies,
          dependenciesForLibraries = groupedDependencies.flatMap(group =>
            group.identifiers.flatMap(_.toLibraryIdentifierOption).map(_ -> group)
          ).groupBy(_._1).mapValues(_.map(_._2).toSet).map(identity),
          allTags = allTags,
          relatedDependenciesTags = relatedDependenciesTags,
          lastRefreshTime = lastRefreshTime,
          versions = requiredVersions
        ))
      }
    } recover {
      case e: BatchUpdateException =>
        throw e.getNextException
    }
  }

  implicit class AddAdjustToMap[K, V](m: Map[K, V]){
    def adjust(k: K)(f: V => V) = m.updated(k, f(m(k)))
  }

  def snooze(id: String, versions: Map[String, Int]) = AdminAction.async { implicit req =>
    loadSnoozes().flatMap{ loadedSnoozes =>
      val snoozes = loadedSnoozes.adjust(id){_.adjustForm(_.bindFromRequest()(req))}
      snoozes(id).form.fold(
        f => indexPage(Map())(snoozes, securedRequestToUserAwareRequest(req)),
        snooze => for {
          _ <- db.run(snoozesTable.map(_.base) += snooze.toSnooze(id))
        } yield Redirect(routes.Application.index(versions).withFragment(id))
      )
    }
  }

  def unsnooze(snoozeId: Int, versions: Map[String, Int]) = AdminAction.async { implicit req =>
    (db.run(snoozesTable.filter(_.id === snoozeId).map(_.base).result).map(_.headOption): Future[Option[Snooze]]).flatMap {
      case Some(snooze) =>
        for(_ <- db.run(snoozesTable.filter(_.id === snoozeId).delete)) yield Redirect(routes.Application.index(versions).withFragment(snooze.snoozedObjectId))
      case None => Future.successful(NotFound(Txt("Unknown snoozeId")))
    }
  }

  // TODO: move import/export to a separate controller
  def tagsExport = Action.async {
    import export._
    for{
      tags <- tagsService.all.map(_.toMap)
      lta <- libraryTagAssignmentsService.byLibrary
      libs <- librariesService.touched(lta.keySet)
    } yield {
      val libraryMapping = (libs: Seq[(Int, Library)]).sortBy(_._2.plainLibraryIdentifier.toString).map { case (id, l) =>
        val assignments: Seq[LibraryTagAssignment] = lta(id)
        TaggedLibrary(
          identifier = s"${l.plainLibraryIdentifier}",
          classified = l.classified,
          tags = assignments.map(a => AssignedTag(name = tags(a.tagId).name, contextDependent = a.contextDependent)).sortBy(_.name.toLowerCase)
        )
      }
      Ok(Json.prettyPrint(Json.toJson(
        Export(libraryMapping = libraryMapping, tags = tags.values.toSeq.sortBy(_.name.toLowerCase))
      ))).as(ContentTypes.JSON)
    }
  }

  val tagsImportForm = Form(mapping("data" -> text)(identity)(Some(_)))

  def tagsImport = AdminAction { implicit req =>
    Ok(views.html.tagsImport(tagsImportForm))
  }

  def tagsImportAction = AdminAction.async { implicit req =>
    tagsImportForm.bindFromRequest()(req).fold(
      formWithErrors => ???,
      data =>
        export.exportFormats.reads(Json.parse(data)).fold(
          invalid => Future.successful(BadRequest(Txt("ERROR: "+invalid))),
          data => {
            def importTags() = tagsService.insertMany(data.tags)
            def getTagsByName(): Future[Map[String, Int]] = tagsService.all.map(_.groupBy(_._2.name).mapValues { case Seq((id, _)) => id }.map(identity))
            def importLibraries(): Future[Unit] = Future.sequence(
              data.libraryMapping.map{ taggedLibrary =>
                librariesService.insert(taggedLibrary.toLibrary).flatMap{ libraryId =>
                  importLibraryTagAssignment(libraryId, taggedLibrary)
                }
              }
            ).map( (x: Seq[Unit]) => ()) // I don't care about the result
            def importLibraryTagAssignment(libraryId: Int, taggedLibrary: export.TaggedLibrary): Future[Unit] = getTagsByName().flatMap { tagIdsByName =>
              Future.sequence(taggedLibrary.tags.map{ assignedTag =>
                val tagId = tagIdsByName(assignedTag.name)
                libraryTagAssignmentsService.insert(LibraryTagAssignment(LibraryTagPair(libraryId = libraryId, tagId = tagId), assignedTag.contextDependent)).map(_ => ())
              }).map( (x: Seq[Unit]) => ()) // I don't care about the result
            }
            for {
              _ <- importTags()
              _ <- importLibraries()
            } yield Ok(Txt("OK"))
          }
        )

    )
  }

  def dependencies(requiredClassification: Option[Boolean], requiredTags: Seq[Int], noTag: Boolean) = ReadAction.async { implicit request =>
    val requiredTagsSet = requiredTags.toSet
    for{
      selectedDependencies <- db.run(librariesService.filtered(requiredClassification = requiredClassification, requiredTagsOption = if(noTag) None else Some(requiredTagsSet)).result)
      dependencyTags <- librariesService.byTags(selectedDependencies.map(_._1).toSet)
      allTags <- tagsService.all
    }yield{
      Ok(views.html.dependencies(
        requiredClassification = requiredClassification,
        selectedDependencies = selectedDependencies,
        allTags = allTags,
        dependencyTags = dependencyTags,
        requiredTagSet = requiredTagsSet,
        noTag = noTag,
        tagsLink = (newTags: Set[Int]) => routes.Application.dependencies(requiredClassification, newTags.toSeq.sorted, noTag),
        noTagLink = newNoTag => routes.Application.dependencies(requiredClassification, requiredTagsSet.toSeq.sorted, newNoTag),
        classificationLink = newClassification => routes.Application.dependencies(newClassification, requiredTagsSet.toSeq.sorted, noTag)
      ))
    }
  }

  def removeTag() = AdminAction.async(BodyParsers.parse.json) { request =>
    request.body.validate[LibraryTagPair].fold(
      err => Future.successful(BadRequest(Txt(err.toString()))),
      libraryTagPair => for(_ <- libraryTagAssignmentsService.remove(libraryTagPair)) yield Ok(Txt("OK"))
    )
  }

  def addTag() = AdminAction.async(BodyParsers.parse.json) { request =>
    request.body.validate[LibraryTagAssignment].fold(
      err => Future.successful(BadRequest(Txt(err.toString()))),
      tagAssignment => for(_ <- libraryTagAssignmentsService.insert(tagAssignment)) yield {Ok(Txt("OK"))}
    )
  }

  def setClassified(classified: Boolean) = AdminAction.async(BodyParsers.parse.json) {request =>
    val libraryId = request.body.as[Int]
    for(_ <- librariesService.setClassified(libraryId, classified)) yield Ok(Txt("OK"))
  }

  def javascriptRoutes = Action { implicit request =>
    Ok(
      JavaScriptReverseRouter("Routes")(
        routes.javascript.Application.setClassified,
        routes.javascript.Application.addTag
      )
    ).as("text/javascript")
  }

  def testHttps(allowRedirect: Boolean) = Action { Ok(Txt(if(allowRedirect)
    """
      |(function(){
      | var newUrl = window.location.href.replace(/^http:/, "https:");
      | if(newUrl != window.location.href){
      |   window.location.replace(newUrl);
      | }
      |})();
      |""".stripMargin else "")).withHeaders("Content-type" -> "text/javascript; charset=utf-8") }

}
