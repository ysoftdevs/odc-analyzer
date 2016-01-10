package models

import models.profile.MappedJdbcType
import models.profile.api._
import slick.lifted.Tag

abstract sealed class LibraryType(val name: String){
  override final def toString: String = name
}
object LibraryType{
  case object Maven extends LibraryType("maven")
  case object DotNet extends LibraryType("dotnet")
  val All = Set(Maven, DotNet)
  val ByName = All.map(x => x.name -> x).toMap
  implicit val libraryTypeMapper = MappedJdbcType.base[LibraryType, String](_.name, LibraryType.ByName)
}

final case class Library(plainLibraryIdentifier: PlainLibraryIdentifier, classified: Boolean)

final case class PlainLibraryIdentifier(libraryType: LibraryType, libraryIdentifier: String){
  override def toString: String = s"$libraryType:$libraryIdentifier"
}

object PlainLibraryIdentifier extends ((LibraryType, String) => PlainLibraryIdentifier) {
  def fromString(id: String) = {
    val (libraryType, libraryNameWithColon) = id.span(_ != ':')
    if(libraryNameWithColon(0) != ':'){
      sys.error("Expected colon")
    }
    val libraryName = libraryNameWithColon.drop(1)
    PlainLibraryIdentifier(
      libraryType = LibraryType.ByName(libraryType),
      libraryIdentifier = libraryName
    )
  }
}

class Libraries(tag: Tag) extends Table[(Int, Library)](tag, "library") {
  import LibraryType.libraryTypeMapper
  def id = column[Int]("id", O.PrimaryKey)
  def libraryType = column[LibraryType]("library_type")
  def libraryIdentifier = column[String]("identifier")
  def classified = column[Boolean]("classified")

  def plainLibraryIdentifierUnmapped = (libraryType, libraryIdentifier)
  def plainLibraryIdentifier = plainLibraryIdentifierUnmapped <> (PlainLibraryIdentifier.tupled, PlainLibraryIdentifier.unapply)

  def base = (plainLibraryIdentifier, classified) <> (Library.tupled, Library.unapply)
  def * = (id, base)

}

