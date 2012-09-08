;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto-tests)

;;; Test vectors based on those defined in the Go implementation.
;;;
;;; http://github.com/dchest/scrypt

(defvar *scrypt-password*
  (coerce #(112 97 115 115 119 111 114 100)
          '(vector (unsigned-byte 8))))
(defvar *scrypt-salt*
  (coerce #(115 97 108 116)
          '(vector (unsigned-byte 8))))

(defvar *scrypt-key*
  (coerce #(116 87 49 175 68 132 243 35 150 137 105 237 162 137 174 238 0 91 89 3 172 86
              30 100 165 172 161 33 121 123 247 115)
          '(vector (unsigned-byte 8))))

(rtest:deftest scryptkdf
    (run-kdf-test (crypto:make-scrypt-kdf)
                  *scrypt-password* *scrypt-salt* 1000 (length *scrypt-key*) *scrypt-key*)
  t)
