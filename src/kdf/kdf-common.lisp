;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto)

(defclass pbkdf1 ()
  ((digest :reader kdf-digest)))

(defclass pbkdf2 ()
  ((digest-name :initarg :digest :reader kdf-digest)))

(defclass hmac-kdf ()
  ((digest-name :initarg :digest :reader kdf-digest)
   (info :initarg :info :accessor hmac-kdf-info :type (simple-array (unsigned-byte 8) (*))
         :documentation "Optional context and application specific information")))

(defclass scrypt-kdf ()
 ((N :initarg :N :reader scrypt-kdf-N)
  (r :initarg :r :reader scrypt-kdf-r)
  (p :initarg :p :reader scrypt-kdf-p)))

(defclass argon2 ()
  ((block :accessor argon2-block :type (simple-array (unsigned-byte 64) (128)))
   (pass-number :accessor argon2-pass-number)
   (slice-number :accessor argon2-slice-number)
   (nb-blocks :accessor argon2-nb-blocks)
   (block-count :accessor argon2-block-count)
   (nb-iterations :accessor argon2-nb-iterations)
   (counter :accessor argon2-counter)
   (offset :accessor argon2-offset)
   (additional-key :accessor argon2-additional-key :type (simple-array (unsigned-byte 8) (*)))
   (additional-data :accessor argon2-additional-data :type (simple-array (unsigned-byte 8) (*)))
   (work-area :accessor argon2-work-area :type (simple-array (unsigned-byte 64) (*)))
   (digester :accessor argon2-digester)))

(defclass argon2i (argon2)
  ())

(defclass argon2d (argon2)
  ())

(defun make-kdf (kind &key digest
                      (N 4096) (r 8) (p 2)
                      (block-count 10000) additional-key additional-data)
  ;; PBKDF1, at least, will do stricter checking; this is good enough for now.
  "digest is used for pbkdf1 and pbkdf2.
N, p, and r are cost factors for scrypt.
block-count, additional-key and additional-data are parameters for
argon2"
  (case (massage-symbol kind)
    (pbkdf1
     (let ((digest-name (massage-symbol digest)))
       (unless (digestp digest-name)
         (error 'unsupported-digest :name digest))
       (make-instance 'pbkdf1 :digest digest-name)))
    (pbkdf2
     (let ((digest-name (massage-symbol digest)))
       (unless (digestp digest-name)
         (error 'unsupported-digest :name digest))
       (make-instance 'pbkdf2 :digest digest-name)))
    (hmac-kdf
     (let ((digest-name (massage-symbol digest)))
       (unless (digestp digest-name)
         (error 'unsupported-digest :name digest))
       (make-instance 'hmac-kdf :digest digest-name :info additional-data)))
    (scrypt-kdf
     (when (or (<= N 1)
               (not (zerop (logand N (1- N))))
               (>= (* r p) (expt 2 30)))
       (error 'unsupported-scrypt-cost-factors :N N :r r :p p))
     (make-instance 'scrypt-kdf :N N :r r :p p))
    (argon2i
     (when (< block-count 8)
       (error 'unsupported-argon2-parameters))
     (make-instance 'argon2i
                    :block-count block-count
                    :additional-key additional-key
                    :additional-data additional-data))
    (argon2d
     (when (< block-count 8)
       (error 'unsupported-argon2-parameters))
     (make-instance 'argon2d
                    :block-count block-count
                    :additional-key additional-key
                    :additional-data additional-data))
    (t
     (error 'unsupported-kdf :kdf kind))))
