;;; Portions of this code relating to deserilizing flowd stores >
;;; version 2 are (C) Mike Maul 2014 
;;;
;;; This code is available under the BSD license, please preserve the
;;; relevant copyright notices.
;;;
;;;   This is (C) Ingvar Mattsson, 2004
;;;    <ingvar <at> hexapodia.net>
;;;   This code uses the file format specification outlined in store.h
;;;   in the netflow logger daemon downloadable from
;;;     http://www.mindrot.org/flowd.html
;;;
;;;   This code is available under the BSD license, please preserve the
;;;   relevant copyright notices.
;;;
;;;   The store.h file is:
;;;     Copyright (c) 2004 Damien Miller <djm <at> mindrot.org>
;;;    
;;;     Permission to use, copy, modify, and distribute this software for any
;;;     purpose with or without fee is hereby granted, provided that the above
;;;     copyright notice and this permission notice appear in all copies.
;;;  
;;;    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
;;;    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
;;;    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
;;;    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
;;;    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
;;;    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
;;;    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
;;;  

(in-package :cl-flowd)
(annot:enable-annot-syntax)

(defvar *ipv4-netmasks*
 (apply #'vector
 (loop for n from 0 to 32
     for mask = 0 then (logior #x80000000 (ash mask -1))
      collect mask)))

(defconstant +store-magic+ #x012cf047)
(defconstant +store-version+ 2)
(defconstant +store-field-tag+                 (ash 1 0))
(defconstant +store-field-recv-time+           (ash 1 1))
(defconstant +store-field-proto-flags-tos+     (ash 1 2))
(defconstant +store-field-agent-addr4+         (ash 1 3))
(defconstant +store-field-agent-addr6+         (ash 1 4))
(defconstant +store-field-src-addr4+           (ash 1 5))
(defconstant +store-field-src-addr6+           (ash 1 6))
(defconstant +store-field-dst-addr4+           (ash 1 7))
(defconstant +store-field-dst-addr6+           (ash 1 8))
(defconstant +store-field-gateway-addr4+       (ash 1 9))
(defconstant +store-field-gateway-addr6+       (ash 1 10))
(defconstant +store-field-srcdst-port+         (ash 1 11))
(defconstant +store-field-packets+             (ash 1 12))
(defconstant +store-field-octets+              (ash 1 13))
(defconstant +store-field-if-indices+          (ash 1 14))
(defconstant +store-field-agent-info+          (ash 1 15))
(defconstant +store-field-flow-times+          (ash 1 16))
(defconstant +store-field-as-info+             (ash 1 17))
(defconstant +store-field-flow-engine-info+    (ash 1 18))
(defconstant +store-field-crc32+               (ash 1 30))
(defconstant +store-field-all+                 (1- (ash 1 19)))

@export-class
(defclass store-header-v2 ()
 ((magic-v2 :reader store-header-v2.magic :initarg :magic)
 (version-v2 :reader store-header-v2.version :initarg :version)
 (start-time-v2 :reader store-header-v2.start-time :initarg :start-time)
 (flags :reader store-header-v2.flags :initarg :flags)
 (stream :reader store-header-v2.stream :initarg :stream)
 ))

@export-class
(defclass store-header ()
  ((version :reader version :initarg :version)
   (len-words :reader len-words :initarg :len-words)
   (reserved :reader reserved :initarg :reserved)
   (fields :reader fields :initarg :fields)
   (stream :reader stream :initarg :stream)
   ))

@export-class
(defclass flow ()
  ((fields :accessor fields :initarg :fields :initform nil)
   (tag :accessor tag :initarg :tag :initform nil)
   (recv-time :accessor recv-time :initarg :recv-time :initform nil)
   (recv-time-usecs :accessor recv-time-usecs :initarg :recv-time-usecs
                    :initform nil)
   (tcp-flags :accessor tcp-flags :initarg :tcp-flags :initform nil)
   (protocol :accessor protocol :initarg :protocol :initform nil)
   (tos :accessor tos :initarg :tos :initform nil) 
   (agent-addr :accessor agent-addr :initarg :agent-addr :initform nil)
   (src-addr :accessor src-addr :initarg :src-addr :initform nil)
   (dst-addr :accessor dst-addr :initarg :dst-addr :initform nil)
   (gateway-addr :accessor gateway-addr :initarg :gateway-addr :initform nil)
   (src-port :accessor src-port :initarg :src-port :initform nil)
   (dst-port :accessor dst-port :initarg :dst-port :initform nil)
   (packets :accessor packets :initarg :packets :initform nil)
   (octets :accessor octets :initarg :octets :initform nil)   
   (if-index-in :accessor if-index-in :initarg :if-index-in :initform nil)
   (if-index-out :accessor if-index-out :initarg :if-index-out :initform nil)
   (sys-uptime-ms :accessor sys-uptime-ms :initarg :sys-uptime-ms :initform nil)
   (time-sec :accessor time-sec :initarg :time-sec :initform nil)
   (time-nanosec :accessor time-nanosec :initarg :time-nanosec :initform nil)
   (netflow-version :accessor netflow-version :initarg :netflow-version :initform nil)
   (flow-start :accessor flow-start :initarg :flow-start :initform nil)
   (flow-finish :accessor flow-finish :initarg :flow-finish :initform nil)
   (src-as :accessor src-as :initarg :src-as :initform nil)
   (dst-as :accessor dst-as :initarg :dst-as :initform nil)
   (src-mask :accessor src-mask :initarg :src-mask :initform nil)
   (dst-mask :accessor dst-mask :initarg :dst-mask :initform nil)
   (engine-type :accessor engine-type :initarg :engine-type :initform nil)
   (engine-id :accessor engine-id :initarg :engine-id :initform nil)
   (flow-sequence :accessor flow-sequence :initarg :flow-sequence :initform nil)
   ))

@export-class
(defclass flow-v2 ()
  ((fields :accessor flow-v2.fields :initarg :fields :initform nil)
   (tag :accessor flow-v2.tag :initarg :tag :initform nil)
   (recv-time-usecs :accessor flow-v2.recv-time :initarg :recv-time :initform nil)
   (tcp-flags :accessor flow-v2.tcp-flags :initarg :tcp-flags :initform nil)
   (protocol :accessor flow-v2.protocol :initarg :protocol :initform nil)
   (tos :accessor flow-v2.tos :initarg :tos :initform nil) 
   (agent-addr :accessor flow-v2.agent-addr :initarg :agent-addr :initform nil)
   (src-addr :accessor flow-v2.src-addr :initarg :src-addr :initform nil)
   (dst-addr :accessor flow-v2.dst-addr :initarg :dst-addr :initform nil)
   (gateway-addr :accessor flow-v2.gateway-addr :initarg :gateway-addr :initform nil)
   (src-port :accessor flow-v2.src-port :initarg :src-port :initform nil)
   (dst-port :accessor flow-v2.dst-port :initarg :dst-port :initform nil)
   (packets :accessor flow-v2.packets :initarg :packets :initform nil)
   (octets :accessor flow-v2.octets :initarg :octets :initform nil)   
   (if-index-in :accessor flow-v2.if-index-in :initarg :if-index-in :initform nil)
   (if-index-out :accessor flow-v2.if-index-out :initarg :if-index-out :initform nil)
   (sys-uptime-ms :accessor flow-v2.sys-uptime-ms :initarg :sys-uptime-ms :initform nil)
   (time-sec :accessor flow-v2.time-sec :initarg :time-sec :initform nil)
   (time-nanosec :accessor flow-v2.time-nanosec :initarg :time-nanosec :initform nil)
   (netflow-version :accessor flow-v2.netflow-version :initarg :netflow-version :initform nil)
   (flow-start :accessor flow-v2.flow-start :initarg :flow-start :initform nil)
   (flow-finish :accessor flow-v2.flow-finish :initarg :flow-finish :initform nil)
   (src-as :accessor flow-v2.src-as :initarg :src-as :initform nil)
   (dst-as :accessor flow-v2.dst-as :initarg :dst-as :initform nil)
   (src-mask :accessor flow-v2.src-mask :initarg :src-mask :initform nil)
   (dst-mask :accessor flow-v2.dst-mask :initarg :dst-mask :initform nil)
   (engine-type :accessor flow-v2.engine-type :initarg :engine-type :initform nil)
   (engine-id :accessor flow-v2.engine-id :initarg :engine-id :initform nil)
   (flow-sequence :accessor flow-v2.flow-sequence :initarg :flow-sequence :initform nil)
   ))



(defclass ipaddr ()
  ((address :accessor address :initarg :address)))

(defclass ipv4 (ipaddr) ())
(defclass ipv6 (ipaddr) ())

(defun make-ipv4 (addr)
  "This function is currently a no-op"
  ;;(make-instance 'ipv4 :address addr)
  (identity addr)
  )

(defun make-ipv6 (addr)
  "This function is currently a no-op"
  ;;(make-instance 'ipv6 :address addr)
  (identity addr)
  )

(defmacro when-flagged (flag &body body)
  "Checks if a given flag is set. The flag field is expected to be named
FIELDS and is for use inside READ-FLOW only!"
  `(when (not (zerop (logand fields ,flag)))
    ,@body))

(defun read-n-bytes (stream n)
  "Read from STREAM a total of N bytes, mung them together as a single
integer. Expects 8-bit bytes."
  (let ((acc 0))
    (loop for r from 1 to n
	  do (setf acc (logior (ash acc 8) (read-byte stream))))
    acc))


@export
(defun read-flow (stream &optional flow-obj)
  "(read-flow <flow-header> &optional flow-object)

This function reads one flow entry from a log file (return value from
OPEN-LOG) and returns it. If a flow object is passed in as an optional
parameter, this flow object is re-used for storage instead of allocating
a new instance."
  (let ((flow-header (read-header stream)))
    (let ((fields (fields flow-header)))
      (let ((flow (if flow-obj
		      flow-obj
                      (make-instance 'flow)))
	    pad)
        (handler-case
            (let ((bcount 0))
                   (when-flagged +store-field-tag+
                     (setf (tag flow) (read-n-bytes stream 4))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-recv-time+
                     (setf (recv-time flow) (read-n-bytes stream 4))
                     (setf (recv-time-usecs flow) (read-n-bytes stream 4))
                     (setf bcount (+ bcount 8)))
                   (when-flagged +store-field-proto-flags-tos+
                     (setf (tcp-flags flow) (read-n-bytes stream 1))
                     (setf (protocol flow) (read-n-bytes stream 1))
                     (setf (tos flow) (read-n-bytes stream 1))
                     (setf pad (read-n-bytes stream 1))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-agent-addr4+
                     (setf (agent-addr flow) (make-ipv4 (read-n-bytes stream 4)))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-agent-addr6+
                     (setf (agent-addr flow) (make-ipv6 (read-n-bytes stream 16)))
                     (setf bcount (+ bcount 16)))
                   (when-flagged +store-field-src-addr4+
                     (setf (src-addr flow) (make-ipv4 (read-n-bytes stream 4)))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-src-addr6+
                     (setf (src-addr flow) (make-ipv6 (read-n-bytes stream 16)))
                     (setf bcount (+ bcount 16)))
                   (when-flagged +store-field-dst-addr4+
                     (setf (dst-addr flow) (make-ipv4 (read-n-bytes stream 4)))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-dst-addr6+
                     (setf (dst-addr flow) (make-ipv6 (read-n-bytes stream 16)))
                     (setf bcount (+ bcount 16)))
                   (when-flagged +store-field-gateway-addr4+
                     (setf (gateway-addr flow) (make-ipv4 (read-n-bytes stream 4)))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-gateway-addr6+
                     (setf (gateway-addr flow) (make-ipv6 (read-n-bytes stream 16)))
                     (setf bcount (+ bcount 16)))
                   (when-flagged +store-field-srcdst-port+
                     (setf (src-port flow) (read-n-bytes stream 2))
                     (setf (dst-port flow) (read-n-bytes stream 2))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-packets+
                     (setf (packets flow) (read-n-bytes stream 8))
                     (setf bcount (+ bcount 8)))
                   (when-flagged +store-field-octets+
                     (setf (octets flow) (read-n-bytes stream 8))
                     (setf bcount (+ bcount 8)))
                   (when-flagged +store-field-if-indices+
                     (setf (if-index-in flow) (read-n-bytes stream 2))
                     (setf (if-index-out flow) (read-n-bytes stream 2))
                     (setf bcount (+ bcount 4)))
                   (when-flagged +store-field-agent-info+
                     (setf (sys-uptime-ms flow) (read-n-bytes stream 4))
                     (setf (time-sec flow) (read-n-bytes stream 4))
                     (setf (time-nanosec flow) (read-n-bytes stream 4))
                     (setf (netflow-version flow) (read-n-bytes stream 2))
                     (setf pad (read-n-bytes stream 2))
                     (setf bcount (+ bcount 16)))
                   (when-flagged +store-field-flow-times+
                     (setf (flow-start flow) (read-n-bytes stream 4))
                     (setf (flow-finish flow) (read-n-bytes stream 4))
                     (setf bcount (+ bcount 8)))
                   (when-flagged +store-field-as-info+
                     (setf (src-as flow) (read-n-bytes stream 2))
                     (setf (dst-as flow) (read-n-bytes stream 2))
                     (setf (src-mask flow) (read-n-bytes stream 1))
                     (setf (dst-mask flow) (read-n-bytes stream 1))
                     (setf pad (read-n-bytes stream 2))
                     (setf bcount (+ bcount 8)))
                   (when-flagged +store-field-flow-engine-info+
                     (setf (engine-type flow) (read-n-bytes stream 1))
                     (setf (engine-id flow) (read-n-bytes stream 1))
                     (setf pad (read-n-bytes stream 2))
                     (setf (flow-sequence flow) (read-n-bytes stream 4))
                     (setf bcount (+ bcount 8)))
                   (when-flagged +store-field-crc32+
                     (setf pad (read-n-bytes stream 4))
                     (setf bcount (+ bcount 4)))
                   
                   (let ((rest (- (len-words flow-header) bcount)))
                     (read-n-bytes stream rest)
                     )
                   )
          (end-of-file () nil))
        flow)))

    )


@export
(defun read-flow-v2 (flow-header &optional flow-obj)
      "(read-flow <flow-header> &optional flow-object)

This function reads one flow entry from a flowd log < v2 file (return value from
OPEN-LOG) and returns it. If a flow object is passed in as an optional
parameter, this flow object is re-used for storage instead of allocating
a new instance."
      (let ((stream (store-header-v2.stream flow-header)))
        (let ((fields (read-n-bytes stream 4)))
          (let ((flow (if flow-obj
                          (progn
                            (setf (fields flow-obj) fields)
                            flow-obj)
                        (make-instance 'flow :fields fields)))
                pad)
            (when-flagged +store-field-tag+
                          (setf (tag flow) (read-n-bytes stream 4)))
            (when-flagged +store-field-recv-time+
                          (setf (recv-time flow) (read-n-bytes stream 4))
                          (setf (recv-time-usecs flow) (read-n-bytes stream 4)))
            (when-flagged +store-field-proto-flags-tos+
                          (setf (tcp-flags flow) (read-n-bytes stream 1))
                          (setf (protocol flow) (read-n-bytes stream 1))
                          (setf (tos flow) (read-n-bytes stream 1))
                          (setf pad (read-n-bytes stream 1)))
            (when-flagged +store-field-agent-addr4+
                          (setf (agent-addr flow) (make-ipv4 (read-n-bytes stream 4))))
            (when-flagged +store-field-agent-addr6+
                          (setf (agent-addr flow) (make-ipv6 (read-n-bytes stream 16))))
            (when-flagged +store-field-src-addr4+
                          (setf (src-addr flow) (make-ipv4 (read-n-bytes stream 4))))
            (when-flagged +store-field-src-addr6+
                          (setf (src-addr flow) (make-ipv6 (read-n-bytes stream 16))))
            (when-flagged +store-field-dst-addr4+
                          (setf (dst-addr flow) (make-ipv4 (read-n-bytes stream 4))))
            (when-flagged +store-field-dst-addr6+
                          (setf (dst-addr flow) (make-ipv6 (read-n-bytes stream 16))))
            (when-flagged +store-field-gateway-addr4+
                          (setf (gateway-addr flow) (make-ipv4 (read-n-bytes stream 4))))
            (when-flagged +store-field-gateway-addr6+
                          (setf (gateway-addr flow) (make-ipv6 (read-n-bytes stream 16))))
            (when-flagged +store-field-srcdst-port+
                          (setf (src-port flow) (read-n-bytes stream 2))
                          (setf (dst-port flow) (read-n-bytes stream 2)))
            (when-flagged +store-field-packets+
                          (setf (packets flow) (read-n-bytes stream 8)))
            (when-flagged +store-field-octets+
                          (setf (octets flow) (read-n-bytes stream 8)))
            (when-flagged +store-field-if-indices+
                          (setf (if-index-in flow) (read-n-bytes stream 2))
                          (setf (if-index-out flow) (read-n-bytes stream 2)))
            (when-flagged +store-field-agent-info+
                          (setf (sys-uptime-ms flow) (read-n-bytes stream 4))
                          (setf (time-sec flow) (read-n-bytes stream 4))
                          (setf (time-nanosec flow) (read-n-bytes stream 4))
                          (setf (netflow-version flow) (read-n-bytes stream 2))
                          (setf pad (read-n-bytes stream 2)))
            (when-flagged +store-field-flow-times+
                          (setf (flow-start flow) (read-n-bytes stream 4))
                          (setf (flow-finish flow) (read-n-bytes stream 4)))
            (when-flagged +store-field-as-info+
                          (setf (src-as flow) (read-n-bytes stream 2))
                          (setf (dst-as flow) (read-n-bytes stream 2))
                          (setf (src-mask flow) (read-n-bytes stream 1))
                          (setf (dst-mask flow) (read-n-bytes stream 1))
                          (setf pad (read-n-bytes stream 2)))
            (when-flagged +store-field-flow-engine-info+
                          (setf (engine-type flow) (read-n-bytes stream 1))
                          (setf (engine-id flow) (read-n-bytes stream 1))
                          (setf pad (read-n-bytes stream 2))
                          (setf (flow-sequence flow) (read-n-bytes stream 4)))
            (when-flagged +store-field-crc32+
                          (setf pad (read-n-bytes stream 4)))
            flow))))


(defun read-header (stream)
  (let ((version (read-n-bytes stream 1)))
    (let ((len-words (* 4 (read-n-bytes stream 1))))
	(read-n-bytes stream 2) ; RESERVED BYTE FEILD
	(let ((fields (read-n-bytes stream 4))) 
            (make-instance 'store-header
                           :version version
			   :len-words len-words
                           :fields fields
			   :stream stream)))))
@export
(defun open-log (file)
  "(open-log <file name>

This function opens a new flowd log file > v2 and returns a header structure containing
the relevant file header information."
  (let ((stream (open file :element-type '(unsigned-byte 8) :direction :input)))
    stream
    ))

@export
(defun open-log-v2 (file)
  "(open-log <file name>

This function opens a new flowd v2 log file and returns a header structure
containing the relevant file header information."
  (let ((stream (open file :element-type '(unsigned-byte 8) :direction :input)))

    (let ((magic (read-n-bytes stream 4)))
      (let ((version (read-n-bytes stream 4)))
        (let ((start-time (read-n-bytes stream 4)))
          (let ((flags (read-n-bytes stream 4)))
            (make-instance 'store-header
                           :magic magic
                           :version version
                           :start-time start-time
                           :flags flags
                           :stream stream)))))))


@export
(defun close-log (flow)
  "This function closes the log file associated with a storage header."
  (close (stream flow)))

@export
(defmacro with-open-log ((var filename) &body body
                         &aux (store (gensym)))
  "Use open-log to obtain a store-header to flowd log located at <filename>
  "
  `(let (,store)
     (unwind-protect
       (multiple-value-prog1
         (let ((,var (setq ,store (open-log ,filename))))
           ,@body)
         )
       (when ,store (close ,store)))))


;;; Formatting Functions

(defmacro formatted-addr (flow-obj slot)
  (let ((flags
	 (case slot
	   (dst-addr (list +store-field-dst-addr4+ +store-field-dst-addr6+))
	   (src-addr (list +store-field-src-addr4+ +store-field-src-addr6+))
	   (gateway-addr (list +store-field-gateway-addr4+ +store-field-gateway-addr6+))
	   (agent-addr (list +store-field-agent-addr4+ +store-field-agent-addr6+))))
	(flow flow-obj))
    `(format-addr ,flow ',flags (,slot ,flow))))

@export
@inline
(defun hex (v &key stream)
  "Sends string hex value of <v> to <stream>"
  (format stream "~x" v))

(defun format-addr (flow-obj flags chunk)
  (let ((flag4 (car flags))
	(flag6 (cadr flags))
	(fields (fields flow-obj)))
    (or (when (= flag4 (logand flag4 fields))
	  (format-ipv4 chunk))
	(when (= flag6 (logand flag6 fields))
	  (hex chunk)))))

@export
(defun format-ipv4 (chunk &optional stream mask)
  "(format-ipv4 binary-chunk &optiona stream mask)

This function outputs an IPv4 address as a dotted quad to STREAM. If a
netmask is passed in, it's outputted with the dotted quad in CIDR notation."
  (if mask (format stream "~D.~D.~D.~D/~D"
		  (ldb (byte 8 24) chunk) (ldb (byte 8 16) chunk)
		  (ldb (byte 8 8) chunk) (ldb (byte 8 0) chunk) mask)
      (format stream "~D.~D.~D.~D"
	      (ldb (byte 8 24) chunk) (ldb (byte 8 16) chunk)
	      (ldb (byte 8 8) chunk) (ldb (byte 8 0) chunk))))

@export
(defun src-net (flow-obj &optional (stream nil) (formatted nil))
  "(src-net flow-obj &optional stream formatted-p)

This function extracts the source network and masks it against the
relevant IPv4 netmask and returns the network part. If given a STREAM and
FORMATTED-P is not null, the resulting netblock is emitted using
FORMAT-IPV4 to the indicated stream."
  (let ((bitmask (logior +store-field-as-info+ +store-field-src-addr4+)))
    (when (= bitmask (logand (fields flow-obj) bitmask))
      (let ((masklen (src-mask flow-obj)))
	(let ((netmask (aref *ipv4-netmasks* masklen)))
	  (let ((netblock (logand (src-addr flow-obj) netmask)))
	    (if formatted
		(format-ipv4 netblock stream masklen)
		netblock)))))))

@export
(defun dst-net (flow-obj &optional (stream nil) (formatted nil)) 
  "(dst-net flow-obj &optional stream formatted-p)

This function extracts the destination network and masks it against the
relevant IPv4 netmask and returns the network part. If given a STREAM and
FORMATTED-P is not null, the resulting netblock is emitted using
FORMAT-IPV4 to the indicated stream."
  (let ((bitmask (logior +store-field-as-info+ +store-field-dst-addr4+)))
    (when (= bitmask (logand (fields flow-obj) bitmask))
      (let ((masklen (dst-mask flow-obj)))
	(let ((netmask (aref *ipv4-netmasks* masklen)))
	  (let ((netblock (logand (dst-addr flow-obj) netmask)))
	    (if formatted
		(format-ipv4 netblock stream masklen)
		netblock)))))))

@export
(defun format-flow (stream f)
  "formats a string representing the next entry in the flowd log
   <stream> can be stream to write to or nil to return string"
  (format stream "FLOW recv_time ~d.~d proto ~a tcpflags ~a tos ~a agent [~a] src [~a]:~a dst [~a]~%"
          (recv-time f)
          (recv-time-usecs f)
          (hex (protocol f))
          (hex (tcp-flags f))
          (hex (tos f))
          (format-ipv4 (agent-addr f))
          (format-ipv4 (src-addr f))
          (src-port f)
          (format-ipv4 (dst-addr f))
          )
  )
