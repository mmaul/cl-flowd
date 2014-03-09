cl-flowd
========

Common Lisp Netflow log reader for flowd logs. 

The core of this code originally appeared in the small-cl-source@common-lisp.net
mailling list. The original author is Ingvar Mattison. The code has been
updated to work with modern flowd Netflow log files and extended functionality.

The functions prefixed with -v2 are for working with older flowd datastores.
For modern installations of flowd the non prefixed versions of these functions 
should be used

API Documentaion
================
See source or quickdocs

Flowd Collector Info
====================
This library uses Netflow collector Flowd which is available at:
http://www.mindrot.org/projects/flowd/

The current version of flowd in the google code repo does not compile.
Use http://flowd.googlecode.com/files/flowd-0.9.1.tar.gz as it predates
introduction of privledge seperation feature which is where the current
issue lies. The issue has been raised with the maintainer. 

Regardless flowd is a simple and effective Netflow collection solution.


Example
=======

This dumps the contents of the flowd log as text to the console similar
to the flow-reader, reader.py and reader.pl programs

    (with-open-log (flog "/var/log/flowd/flowd.bin") 
      (do ((f (read-flow flog) 
           (read-flow flog))) 
           ((eql f nil)) 
           (format-flow t (read-flow flog))))
