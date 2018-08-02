;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto)

(defclass pbkdf1 ()
  ((digest :reader kdf-digest)))

(defclass pbkdf2 ()
  ((digest-name :initarg :digest :reader kdf-digest)))

(defclass scrypt-kdf ()
 ((N :initarg :N :reader scrypt-kdf-N)
  (r :initarg :r :reader scrypt-kdf-r)
  (p :initarg :p :reader scrypt-kdf-p)))

(defclass argon2i ()
  ((block :accessor argon2i-block :type (simple-array (unsigned-byte 64) (128)))
   (pass-number :accessor argon2i-pass-number)
   (slice-number :accessor argon2i-slice-number)
   (nb-blocks :accessor argon2i-nb-blocks)
   (block-count :accessor argon2i-block-count)
   (nb-iterations :accessor argon2i-nb-iterations)
   (counter :accessor argon2i-counter)
   (offset :accessor argon2i-offset)
   (additional-key :accessor argon2i-additional-key :type (simple-array (unsigned-byte 8) (*)))
   (additional-data :accessor argon2i-additional-data :type (simple-array (unsigned-byte 8) (*)))
   (work-area :accessor argon2i-work-area :type (simple-array (unsigned-byte 64) (*)))
   (digester :accessor argon2i-digester)))

(defun make-kdf (kind &key digest
                      (N 4096) (r 8) (p 2)
                      (block-count 10000) additional-key additional-data)
  ;; PBKDF1, at least, will do stricter checking; this is good enough for now.
  "digest is used for pbkdf1 and pbkdf2.
N, p, and r are cost factors for scrypt.
block-count, additional-key and additional-data are parameters for
argon2i"
  (case kind
    ((pbkdf1 :pbkdf1)
     (unless (digestp digest)
       (error 'unsupported-digest :name digest))
     (make-instance 'pbkdf1 :digest digest))
    ((pbkdf2 :pbkdf2)
     (unless (digestp digest)
       (error 'unsupported-digest :name digest))
     (make-instance 'pbkdf2 :digest digest))
    ((scrypt-kdf :scrypt-kdf)
     (when (or (<= N 1)
               (not (zerop (logand N (1- N))))
               (>= (* r p) (expt 2 30)))
       (error 'unsupported-scrypt-cost-factors :N N :r r :p p))
     (make-instance 'scrypt-kdf :N N :r r :p p))
    ((argon2i :argon2i)
     (when (< block-count 8)
       (error 'unsupported-argon2i-parameters))
     (make-instance 'argon2i
                    :block-count block-count
                    :additional-key additional-key
                    :additional-data additional-data))
    (t
     (error 'unsupported-kdf :kdf kind))))
