;;;; cl-flowd.asd

(asdf:defsystem #:cl-flowd
  :serial t
  :description "Native Lisp interface to Netflow data stores created by
                the Netflow collect flowd (http://www.mindrot.org/projects/flowd/)"
  :author "Mike Maul <mike.maul@gmail.com>"
  :version "0.5.0"
  :license "BSD"
  :depends-on (#:cl-annot)
  :components ((:file "package")
               (:file "flowd")))

