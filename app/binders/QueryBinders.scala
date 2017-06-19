package binders

import java.net.URLDecoder.decode
import java.net.URLEncoder.encode

import com.ysoft.odc.Hashes
import play.api.mvc.{JavascriptLiteral, PathBindable, QueryStringBindable}

object QueryBinders {

  /*private def bindableSet[T](implicit seqBinder: QueryStringBindable[Seq[T]]): QueryStringBindable[Set[T]] = seqBinder.transform(
    _.toSet,
    _.toSeq
  )

  implicit def bindableSetOfInt(implicit seqBinder: QueryStringBindable[Seq[Int]]): QueryStringBindable[Set[Int]] = bindableSet[Int]*/

  import play.api.libs.json._
  private val formats = implicitly[Format[Map[String, Int]]]

  implicit def bindableMapStringToInt: QueryStringBindable[Map[String, Int]] = {
    QueryStringBindable.bindableString.transform(s => formats.reads(Json.parse(s)).getOrElse(Map()), map => formats.writes(map).toString())
  }

  implicit val hashedBindable = QueryStringBindable.bindableString.transform[Hashes](
    str => str.split('-') match {
      case Array(sha1, md5) => Hashes(sha1 = sha1, md5 = md5)
    },
    hashes => hashes.serialized
  )

  implicit object MapStringIntJavascriptLiteral extends JavascriptLiteral[Map[String, Int]] {
    override def to(value: Map[String, Int]): String = formats.writes(value).toString()
  }

  implicit val StringOptionPathBindable: PathBindable[Option[String]] = implicitly[PathBindable[String]].transform(
    {
      case "" => None
      case x => Some(decode(x, "utf-8"))
    },
    _.map(encode(_, "utf-8")).getOrElse("")
  )

  //implicit def somePathBindable[T : PathBindable]: PathBindable[Some[T]] = implicitly[PathBindable[T]].transform(Some(_), _.x)

}
