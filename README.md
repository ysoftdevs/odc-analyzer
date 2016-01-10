## Database

I decided to use PostgreSQL, because

* It is easy to set up
* It is reasonably strict by default. For example, when you try to insert a 256-character string in varchar(64), you get an error. (In MySQL, it gets silently truncated by default!)


## TODO

### Naming
* Library × Identifier × PlainLibraryIdentifier – should be renamed
    * Identifier is the most verbose one, it comes from OWASP Dependency Check.
    * Library is a record stored in our database.
    * PlainLibraryIdentifier is just version-less (e.g. `"$groupId:$artifactId"`) library identifier.
