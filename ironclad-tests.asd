; -*- mode: lisp -*-
(defpackage #:ironclad-tests-system
  (:use :cl :asdf))

(in-package #:ironclad-tests-system)

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
  :version "0.5"
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
                                   (:file "ironclad")
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
