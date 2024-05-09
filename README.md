# Soteria

Jakarta Security Compatible Implementation (CI)

[Website](https://eclipse-ee4j.github.io/soteria)

Building
--------

Soteria can be built by executing the following from the project root:

``mvn clean package``

The implementation and an SPI implementation for Weld can then be found in /impl and /spi respectively.

Sample applications
-------------------

Sample application have been integrated with the [Jakarta Security TCK](https://github.com/jakartaee/security/tree/master/tck).

Compatibility
-------------

Soteria is used by GlassFish, WildFly, WebLogic and JEUS. It can be added to Tomcat.