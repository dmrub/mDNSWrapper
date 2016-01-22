mDNSWrapper
===========

A wrapper library for accessing [mDNS](https://en.wikipedia.org/wiki/Multicast_DNS) functionality of [Zeroconf](https://en.wikipedia.org/wiki/Zero-configuration_networking) networking in a cross-platform way.

### Components

* MDNSManager.hpp
  * MDNS::MDNSService class represents service information to be registered with mDNS server
  * MDNS::MDNSServiceBrowser class provides callback methods to be implemented by the user and registered to receive notifications from mDNS server
  * MDNS::MDNSManager class provides API to access mDNS functionality

### Dependencies

* C++11
* [Apple Bonjour SDK](https://developer.apple.com/bonjour/) on Windows
* [Avahi](http://www.avahi.org/) or [Apple Bonjour Library](https://developer.apple.com/bonjour/) on Linux

### Building

Compile with a C++11 compilant compiler:
```
cmake .
make
```

### Contact

Dmitri Rubinstein,
German Research Center for Artificial Intelligence (DFKI), Saarbruecken

e-mail: dmitri.rubinstein@dfki.de
