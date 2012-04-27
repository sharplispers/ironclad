; -*- mode: lisp -*-
(defpackage #:ironclad-system
  (:use :cl :asdf))

(in-package #:ironclad-system)

;;; easy-to-type readmacro for creating s-boxes and the like

(defun array-reader (stream subchar arg)
  (declare (ignore subchar))
  (let ((array-data (read stream nil stream nil))
        (array-element-type `(unsigned-byte ,arg)))
    ;; FIXME: need to make this work for multi-dimensional arrays
    `(make-array ,(length array-data) :element-type ',array-element-type
                :initial-contents ',array-data)))
    
(defparameter *ironclad-readtable*
  (let ((readtable (copy-readtable nil)))
    (set-dispatch-macro-character #\# #\@ #'array-reader readtable)
    readtable))

(defclass ironclad-source-file (cl-source-file) ())
(defclass txt-file (doc-file) ())
(defclass css-file (doc-file) ())

(defmethod source-file-type ((c txt-file) (s module)) "txt")
(defmethod source-file-type ((c css-file) (s module)) "css")

(asdf:defsystem :ironclad
  :version "0.30"
  :author "Nathan Froyd <froydnj@gmail.com>"
  :maintainer "Nathan Froyd <froydnj@gmail.com>"
  :description "A cryptographic toolkit written in pure Common Lisp"
  :default-component-class ironclad-source-file
  :depends-on (#+sbcl sb-rotate-byte nibbles sb-posix)
  :components ((:static-file "README")
               (:static-file "LICENSE")
               (:static-file "TODO")
               (:static-file "NEWS")
               (:module "src"
                        :components
                        ((:file "package")
                         (:file "conditions" :depends-on ("package"))
                         (:file "util" :depends-on ("package"))
                         (:file "macro-utils" :depends-on ("package"))
                         (:file "common" :depends-on ("package"))
                         ;; FIXME: make this depend on :FEATURE :IRONCLAD-GRAY-STREAMS
                         #+(or lispworks sbcl openmcl cmu allegro)
                         (:file "octet-stream" :depends-on ("common"))
                         (:file "padding" :depends-on ("common"))
                         (:file "pkcs5" :depends-on ("common"))
                         (:file "password-hash" :depends-on ("pkcs5"))
                         (:file "math" :depends-on ("prng" "public-key"))
                         (:module "sbcl-opt"
                                  :depends-on ("package" "common")
                                  :components
                                  ;; ASDF doesn't DTRT, so we can't make
                                  ;; the whole module :IN-ORDER-TO.
                                  ;; We'll settle for this one file and
                                  ;; key off of that.
                                  ((:file "fndb"
                                          :in-order-to ((compile-op
                                                         (feature :sbcl))))
                                   ;; It would be nice if we could say
                                   ;; (OR (FEATURE :X86) (FEATURE :X86-64))
                                   ;; but ASDF is not that flexible.
                                   (:file "x86oid-vm" :depends-on ("fndb")))
                                  :if-component-dep-fails :ignore)
                         (:module "ciphers"
                                  :depends-on ("common" "macro-utils")
                                  :components
                                  (
                                   ;; block ciphers of various kinds
                                   (:file "cipher")
                                   (:file "modes" :depends-on ("cipher"))
                                   (:file "make-cipher" :depends-on ("cipher"))
                                   (:file "null-cipher" :depends-on ("cipher"))
                                   (:file "aes" :depends-on ("cipher"))
                                   (:file "des" :depends-on ("cipher"))
                                   (:file "blowfish" :depends-on ("cipher"))
                                   (:file "twofish" :depends-on ("cipher"))
                                   (:file "idea" :depends-on ("cipher"))
                                   (:file "misty1" :depends-on ("cipher"))
                                   (:file "square" :depends-on ("cipher"))
                                   (:file "rc2" :depends-on ("cipher"))
                                   (:file "rc5" :depends-on ("cipher"))
                                   (:file "rc6" :depends-on ("cipher"))
                                   (:file "tea" :depends-on ("cipher"))
                                   (:file "xtea" :depends-on ("cipher"))
                                   (:file "cast5" :depends-on ("cipher"))
                                   ;; stream ciphers
                                   (:file "arcfour" :depends-on ("cipher"))))
                         (:module "digests"
                                  :depends-on ("common" "macro-utils" "sbcl-opt")
                                  :components
                                  ((:file "digest")
                                   (:file "crc24" :depends-on ("digest"))
                                   (:file "crc32" :depends-on ("digest"))
                                   (:file "adler32" :depends-on ("digest"))
                                   (:file "md2" :depends-on ("digest"))
                                   (:file "md4" :depends-on ("digest"))
                                   (:file "md5" :depends-on ("digest"))
                                   (:file "md5-lispworks-int32" :depends-on ("digest"))
                                   (:file "sha1" :depends-on ("digest"))
                                   (:file "sha256" :depends-on ("digest"))
                                   (:file "sha512" :depends-on ("digest"))
                                   (:file "ripemd-128" :depends-on ("digest"))
                                   (:file "ripemd-160" :depends-on ("digest"))
                                   (:file "tiger" :depends-on ("digest"))
                                   (:file "whirlpool" :depends-on ("digest"))
                                   (:file "tree-hash" :depends-on ("digest"))))
                         (:module "macs"
                                  :depends-on ("common" "digests")
                                  :components
                                  ((:file "hmac")
                                   (:file "cmac")))
                         (:module "public-key"
                                  :depends-on ("package")
                                  :components
                                  ((:file "public-key")
                                   (:file "dsa" :depends-on ("public-key"))
                                   (:file "rsa" :depends-on ("public-key"))))
                         (:module "prng"
                                  :depends-on ("digests" "ciphers")
                                  :components
                                  ((:file "prng")
                                   (:file "fortuna" :depends-on ("prng"
                                                                 "generator"))
                                   (:file "generator")))))
               (:module "doc"
                        :components
                        ((:html-file "ironclad")
                         ;; XXX ASDF bogosity
                         (:txt-file "ironclad-doc")
                         (:css-file "style")))))

(defun ironclad-implementation-features ()
  #+sbcl
  (list* sb-c:*backend-byte-order*
         (if (= sb-vm:n-word-bits 32)
             :32-bit
             :64-bit)
         :ironclad-fast-mod32-arithmetic
         :ironclad-gray-streams
         (when (member :x86-64 *features*)
           '(:ironclad-fast-mod64-arithmetic)))
  #+cmu
  (list (c:backend-byte-order c:*target-backend*)
        (if (= vm:word-bits 32)
            :32-bit
            :64-bit)
        :ironclad-fast-mod32-arithmetic
        :ironclad-gray-streams)
  #+allegro
  (list :ironclad-gray-streams)
  #+lispworks
  (list :ironclad-gray-streams)
  #+openmcl
  (list :ironclad-gray-streams)
  #-(or sbcl cmu allegro lispworks openmcl)
  nil)

  
(macrolet ((do-silently (&body body)
             `(handler-bind ((style-warning #'muffle-warning)
                             ;; It's about as fast as we can make it,
                             ;; and a number of the notes relate to code
                             ;; that we're running at compile time,
                             ;; which we don't care about the speed of
                             ;; anyway...
                             #+sbcl (sb-ext:compiler-note #'muffle-warning))
                ,@body)))
(defmethod perform :around ((op compile-op) (c ironclad-source-file))
  (let ((*readtable* *ironclad-readtable*)
        (*print-base* 10)               ; INTERN'ing FORMAT'd symbols
        (*print-case* :upcase)
        #+sbcl (sb-ext:*inline-expansion-limit* (max sb-ext:*inline-expansion-limit* 1000))
        #+cmu (ext:*inline-expansion-limit* (max ext:*inline-expansion-limit* 1000))
        (*features* (append (ironclad-implementation-features) *features*)))
    (do-silently (call-next-method))))

(defmethod perform :around ((op load-op) (c ironclad-source-file))
  (do-silently (call-next-method))))

(defmethod perform :after ((op load-op) (c (eql (find-system :ironclad))))
  (provide :ironclad))


;;; testing

(defclass test-vector-file (static-file)
  ())

(defmethod source-file-type ((c test-vector-file) (s module)) "testvec")

(defpackage :ironclad-tests
  (:nicknames :crypto-tests)
  (:use :cl))

(defmethod perform ((op test-op) (c (eql (find-system :ironclad))))
  (oos 'test-op 'ironclad-tests))

;;; A tester's job is never done!
(defmethod operation-done-p ((op test-op) (c (eql (find-system :ironclad))))
  nil)

(asdf:defsystem ironclad-tests
  :depends-on (ironclad)
  :version "0.6"
  :in-order-to ((test-op (load-op :ironclad-tests)))
  :components ((:module "testing"
                        :components
                        ((:file "rt")
                         (:file "testfuns" :depends-on ("rt"))
                         (:module "test-vectors"
                                  :depends-on ("testfuns")
                                  :components
                                  ((:file "macs")
                                   (:file "modes")
                                   (:file "ciphers")
                                   (:file "digests")
                                   (:file "padding")
                                   (:file "pkcs5")
                                   (:file "ironclad")
                                   (:file "prng")
                                   ;; test vectors
                                   (:test-vector-file "crc24")
                                   (:test-vector-file "crc32")
                                   (:test-vector-file "adler32")
                                   (:test-vector-file "md2")
                                   (:test-vector-file "md4")
                                   (:test-vector-file "md5")
                                   (:test-vector-file "sha1")
                                   (:test-vector-file "sha224")
                                   (:test-vector-file "sha256")
                                   (:test-vector-file "sha384")
                                   (:test-vector-file "sha512")
                                   (:test-vector-file "ripemd-128")
                                   (:test-vector-file "ripemd-160")
                                   (:test-vector-file "tiger")
                                   (:test-vector-file "whirlpool")
                                   (:test-vector-file "hmac")
                                   (:test-vector-file "cmac")
                                   (:test-vector-file "tree-hash")
                                   ;; block ciphers of various kinds
                                   (:test-vector-file "null")
                                   (:test-vector-file "aes")
                                   (:test-vector-file "des")
                                   (:test-vector-file "3des")
                                   (:test-vector-file "blowfish")
                                   (:test-vector-file "twofish")
                                   (:test-vector-file "idea")
                                   (:test-vector-file "misty1")
                                   (:test-vector-file "square")
                                   (:test-vector-file "rc2")
                                   (:test-vector-file "rc5")
                                   (:test-vector-file "rc6")
                                   (:test-vector-file "tea")
                                   (:test-vector-file "xtea")
                                   (:test-vector-file "cast5")
                                   ;; modes
                                   (:test-vector-file "cbc")
                                   (:test-vector-file "ctr")
                                   (:test-vector-file "ofb")
                                   (:test-vector-file "cfb")
                                   (:test-vector-file "cfb8")
                                   ;; stream ciphers
                                   (:test-vector-file "arcfour")))))))

(defmethod operation-done-p ((op test-op)
                             (c (eql (find-system :ironclad-tests))))
  nil)

(defmethod perform ((op test-op) (c (eql (find-system :ironclad-tests))))
  (or (funcall (intern "DO-TESTS" (find-package "RTEST")))
      (error "TEST-OP failed for IRONCLAD-TESTS")))
