package modules

import com.google.inject.{AbstractModule, Provides}
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import net.codingwell.scalaguice.ScalaModule
import play.api.{Application, Configuration}
import services.{OdcConfig, OdcDbConnectionConfig, OdcService}

class OdcModule extends AbstractModule with ScalaModule{
  override def configure(): Unit = {}

  private val Drivers = Map(
    "slick.driver.MySQLDriver$" -> "org.mariadb.jdbc.Driver",
    "slick.driver.PostgresDriver$" -> "org.postgresql.Driver"
  )

  @Provides
  def provideOdcServiceOption(conf: Configuration, application: Application): Option[OdcService] = {
    lazy val dbConfig = {
      val driverClass = Drivers(conf.getString("slick.dbs.odc.driver").get)
      val driverJar = Class.forName(driverClass).getProtectionDomain.getCodeSource.getLocation.getPath
      OdcDbConnectionConfig(
        driverClass = driverClass,
        driverJar = driverJar,
        url = conf.getString("slick.dbs.odc.db.url").get,
        user = conf.getString("slick.dbs.odc.db.user").get,
        password = conf.getString("slick.dbs.odc.db.password").get
      )
    }
    conf.underlying.getAs[OdcConfig]("odc").map(config => new OdcService(config, dbConfig)(application))
  }

}
