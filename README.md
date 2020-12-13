# Soteria

Jakarta Security Compatible Implementation (CI)

[Website](https://eclipse-ee4j.github.io/soteria)

Building
--------

Soteria can be built by executing the following from the project root:

``mvn clean package``

The API and combined API/implementation jars can then be found in /api and /impl respectively.

Sample applications
-------------------

In /test a number of sample applications are located that each demonstrate a specific feature of Jakarta Security. The folder is called
/test since these double as integration tests.

The sample applications are build when the main build as shown above is executed. By default these applications are build for a
target server that is *not* assumed to already provide a Jakarta Security implementation (like a compatible Jakarta EE server would). In that case the Soteria jars are included in the application archive.

Alternatively the sample applications can be build for a server that does provide a Jakarta Security implementation. In that case the Soteria jars are not included in the application archive. This can be done using the ``provided`` profile as follows:

``mvn clean package -Pprovided``

There are 4 CI targets provided to test Soteria against:

* payara
* wildfly
* tomee
* openliberty

Testing against any of these is done by activating the maven profile with the same name. E.g.

``mvn clean install -Ptomee,bundled``

Testing against glassfish (which provides soteria integration):
``mvn clean verify -Pglassfish,provided``

Compatibility
-------------

Soteria currently runs fully on any of these [Jakarta EE Compatible Products](https://jakarta.ee/compatibility/).

It runs mostly on TomEE 8.0.5 or above. "Mostly" means here that some features don't work because of bugs in the servers. These bugs are likely going to be fixed in newer versions.
