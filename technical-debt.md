# Technical debt

All the technical debt should be documented here.

## Checking for new versions
This code calls some OWASP Dependency Check API. However:

* I don't think that the API can be considered as public.
* The ODC now connects to an empty H2 database, although the database is not used at all.

## Caching

* Caching might require large amount of RAM. In some cases, this might cause OOMs.
* Expensive computation might be performed multiple times when another cache-miss is done before the computation is done. In order to resolve this issue, we need proper “get or compute” semantics. This might be solved by switching to spray-caching, which will however probably need a custom backend. [Guava Cache](https://guava-libraries.googlecode.com/files/JavaCachingwithGuava.pdf) seems to address the issue, except that it does not have an idiomatic Java API and it does not use Futures. While [ScalaCache](https://github.com/cb372/scalacache) can use Guava Cache as its backend, it does not seem to keep the “get or compute” semantics. Maybe the best option is to implement Guava Cache based backend for spray-caching.
* Cache does not explicitly expire. The current workaround is using the cron job for periodic refresh.
* Manual cache control makes it inconsistent when multiple instances behind a load-balancer are used. (Note that if you require such setup, you will probably want to do few adjustments. We are OK with consulting such changes and accepting some reasonable pull-request for supporting such functionality, but we don't want to implement it ourselves, because we don't need such setup.)

## Long-running operations

When data is being refreshed from the build server, it might take a long time. There is no user-friendly indication of such operation. In some cases, it might even cause infamous 502 proxy timeout errors.

Workaround: Use the cron task for periodic refresh.

## Support for other build servers than Bamboo

The ODC Analyzer was originally designed to download data from Bamboo and other build servers were not taken into the account. The code has been refactored since then. We are OK to help with further refactoring that might be needed to add support for other build servers. This will probably not be much work.

## Authentication

External authentication uses the e-mail as identifier and ignores username. Maybe this should be made more flexible.

Note that this was a quick hack that allows e-mail notifications.

## Naming
* Library × Identifier × PlainLibraryIdentifier – should be renamed
    * Identifier is the most verbose one, it comes from OWASP Dependency Check.
    * Library is a record stored in our database.
    * PlainLibraryIdentifier is just version-less (e.g. `"$groupId:$artifactId"`) library identifier.
* Some other naming issues are described in code under TODOs.

## Few automated tests

The small number automated tests is mainly caused by economical view. It is useful to write cheap tests for likely defects. However, it seems that most issues come from integration with external environment and it is hard to write automated tests for that, while typical candidates for unit tests is a code that does not break very much.

Few parts of the code are now automatically tested.

### Some candidates for automated tests:

* Exporting vulnerabilities to external systems (like mail and issue tracker).
* Parsing output from ODC. (Maybe some integration test would be useful in order to check compatibility with newer ODC version. In contrast, unit tests are likely to be rather useless in this area.)
* Authentication – this is area for future refactoring.
