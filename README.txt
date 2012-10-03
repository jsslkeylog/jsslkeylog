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

This program requires Java 1.5 or higher. Download it from www.java.com.

The agent library was tested with Java 1.5 to 1.7; as it accesses internal
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

- The logfile will be written while the program is running. Now just point
  Wireshark to that logfile and happy SSL decoding!
  

License
~~~~~~~

Copyright (c) 2012 Michael Schierl

jSSLKeyLog is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version. See license.txt.


Contact me
~~~~~~~~~~

Please send bug reports and suggestions to <schierlm@users.sourceforge.net>.


ChangeLog
~~~~~~~~~

+++ 2012-10-03 Released version 1.0 +++

- First public release
