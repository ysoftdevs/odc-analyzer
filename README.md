This tool manages reports from OWASP Dependency Check. Features include:

* providing list of projects affected by a particular vulnerability
* providing list of projects containing a particular library
* grouping projects by team
* upgrade advisor: checking if a newer version of a library has some known vulnerability
* library tagging

## License

Copyright (c) 2015-2016, <copyright holder>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Y Soft Corporation nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Requirements

* Java 8
* PostgreSQL
* MySQL (updated ODC vulnerability database)
* Bamboo server (read-only access to reports)

Bamboo server runs OWASP Dependency Check scans and provides reports. These reports are needed to be configured separately (this tool does not configure it).

## Config

The application is a standard Play framework application and [its deployment documentation](https://www.playframework.com/documentation/2.4.x/Production) applied there. Database, Bamboo server, list of project, authentication and so on can be configured in Play configuration file. There are two example files provided:

* ./production.conf-example
* ./conf/application.conf.-example – for development

## Database

### App database

I decided to use PostgreSQL, because:

* It is easy to set up
* It is reasonably strict by default. For example, when you try to insert a 256-character string in varchar(64), you get an error. (In MySQL, it gets silently truncated by default!)
* It can handle subqueries well. (At time of the choice, the most up-to-date Slick version was 3.0.*, which used to generate much subqueries.)

### Vulnerability Database

The application also needs read-only access to vulnerability database maintained by OWASP Dependency Check. ODC currently supports H2 and MySQL. However, there are multiple issues with H2 for this usage. The first one issue is concurrent access. The concurrent access probably could have been somehow configured, but ODC uses different case for MySQL and H2 table names and column names. This makes it hard to support both at the same time.

## Development notes

### Naming
* Library × Identifier × PlainLibraryIdentifier – should be renamed
    * Identifier is the most verbose one, it comes from OWASP Dependency Check.
    * Library is a record stored in our database.
    * PlainLibraryIdentifier is just version-less (e.g. `"$groupId:$artifactId"`) library identifier.
