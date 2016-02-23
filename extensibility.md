# Extensibility

## Using other issue tracker than JIRA

The code is ready for that. You simply can:

1. implement corresponding interface (i.e. `services.IssueTrackerService`)
2. implement config parsing
3. send a pull-request :)

Note that issue tracking is a fresh feature and there might be some interface changes in the future in order to implement new features.

## Adding another export than issue trackers and e-mail

This might be an easy task, but it depends how are the outputs structured. E-mail notifications and issue tracker export uses much common code and new platform for export might also utilize this common code.

## Using other build server than Bamboo

There might be some (rather minor) issues, because our code might be slightly bound to Bamboo. We wish to help with refactoring needed for adding another build server if our code is too specific for Bamboo somewhere.

## Using other vulnerability database than NVD

In such case, you will probably want extend OWASP Dependency Check first. Once this is done, little or no work has to be done in this analyzer:

* Other vulnerability database might theoretically add some new fields. In such case, it would be useful to parse them from the report and display them.
* In some rare cases, ODC Analyzer provides an external link to NVD. This might be useful to refactor.

## Using other scanner than OWASP Dependency Check

We don't believe we will extend it in this way. However, if you have a good reason for adding other scanner than ODC, we might consider it. Adding such scanner might, however, depend on its output format. If it is similar enough to XML output from OWASP Dependency Check, it is more likely to be added.

## Adding a classes in Java

While most codebase is in Scala, it is acceptable to use Java (or maybe even other JVM language like Groovy, Ceylon, Kotlin, …) for some cases. General rules:

* One functionality should be implemented in one language.
* We don't want to introduce much external libraries (including standard libraries) for minor functionality.

OK:

* to implement export to another issue tracker in Java
* to have export to one issue tracker implemented in one language and export to other issue tracker in another issue tracker in another language

Discouraged:

* to mix multiple languages in implementation of export to one issue tracker

None of there rules is strict, but they are general rule-of-thumb.
