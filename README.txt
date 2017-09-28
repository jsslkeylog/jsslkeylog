jSSLKeyLog
==========


Introduction
~~~~~~~~~~~~

jSSLKeyLog is a Java Agent Library that logs SSL session keys of connections 
created by a Java application to a log file understood by Wireshark (see 
https://developer.mozilla.org/en-US/docs/NSS_Key_Log_Format), so that "Follow
SSL stream" can be used to debug SSL connection issues as if the connection
was not encrypted. It works with both Java server and client software.


System requirements
~~~~~~~~~~~~~~~~~~~

This program requires Java 1.7 or higher. Download it from www.java.com.
In case you want to use it with Java 1.5 or 1.6, use version 1.1 of this
program instead. 

The agent library was tested with Java 1.7 to 1.9; as it accesses internal
API directly, it might not work in more recent versions without updating.


Usage
~~~~~

- First download jSSLKeyLog and extract it.

- Locate the command line used to start the Java program (usually hidden in
  some script or batch file) you want to monitor, it will usually look like

  java ... -jar file.jar ...
  or
  java ... some.class.Name ...
  
- Now add an additional parameter directly after the java command name, 
  which is 
  
  -javaagent:jSSLKeyLog.jar=/path/to/your_logfile.log
  
  so that the complete command looks like this:
  
  java -javaagent:jSSLKeyLog.jar=/path/to/your_logfile.log ... -jar file.jar

- You can give an absolute or relative path to jSSLKeyLog.jar and to your
  logfile.

- If you use a double == between name of the Jar file and the name of
  your log file, extra verbose comments (containing timestamps and
  local/remote host/ip) will be written before the individual entries.

- The logfile will be written while the program is running. Now just point
  Wireshark to that logfile and happy SSL decoding!
  
- Note that for decoding ECDSA ciphers, at least Wireshark 1.11.3 (as of
  now, a development version, but probably already stable when you are
  reading this) is required.

License
~~~~~~~

Copyright (c) 2012, 2014, 2017 Michael Schierl

jSSLKeyLog is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version. See license.txt.


Contact me
~~~~~~~~~~

Please send bug reports and suggestions to <schierlm@users.sourceforge.net>.


ChangeLog
~~~~~~~~~

+++ 2017-09-28 Released version 1.2 +++

- Added support for Java 9

+++ 2014-04-23 Released version 1.1 +++

- Added verbose logging mode
- Added support for Java 8

+++ 2012-10-03 Released version 1.0 +++

- First public release
