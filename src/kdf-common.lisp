;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
(in-package :crypto)

(defgeneric derive-key (kdf passphrase salt iteration-count key-length))

(defclass pbkdf1 ()
  ((digest :reader kdf-digest)))

(defclass pbkdf2 ()
  ((digest-name :initarg :digest :reader kdf-digest)))

(defclass scrypt-kdf ()
 ((N :initarg :N :reader scrypt-kdf-N)
  (r :initarg :r :reader scrypt-kdf-r)
  (p :initarg :p :reader scrypt-kdf-p)))

(defun make-kdf (kind &key digest (N 4096) (r 8) (p 2))
  ;; PBKDF1, at least, will do stricter checking; this is good enough for now.
  "digest is used for pbkdf1 and pbkdf2.
   N, p, and r are cost factors for scrypt."
  (case kind
    (pbkdf1
     (unless (digestp digest)
       (error 'unsupported-digest :name digest))
     (make-instance 'pbkdf1 :digest digest))
    (pbkdf2
     (unless (digestp digest)
       (error 'unsupported-digest :name digest))
     (make-instance 'pbkdf2 :digest digest))
    (scrypt-kdf
     (when (or (<= N 1)
               (not (zerop (logand N (1- N))))
               (>= (* r p) (expt 2 30)))
       (error 'unsupported-scrypt-cost-factors :N N :r r :p p))
     (make-instance 'scrypt-kdf :N N :r r :p p))
    (t
     (error 'unsupported-kdf :kdf kind))))
