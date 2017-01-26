;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; os-prng.lisp -- OS-provided pseudo-random number generator

(in-package :crypto)

(defclass os-prng ()
  (#+unix source))

(defmethod prng-random-data (num-bytes (prng os-prng))
  #+unix
  (let ((seq (make-array num-bytes :element-type 'unsigned-byte)))
    (unless (slot-boundp prng 'source)
      (setf (slot-value prng 'source)
            (open #P"/dev/urandom" :element-type 'unsigned-byte)))
    (assert (>= (read-sequence seq (slot-value prng 'source)) num-bytes))
    seq)
  ;; FIXME: this is _untested_!
  #+(and win32 sb-dynamic-core)(sb-win32:crypt-gen-random num-bytes)
  #-(or unix (and win32 sb-dynamic-core))(error "Your platform does not have a supported random source."))

(defmethod make-prng ((name (eql :os)) &key seed)
  (declare (ignorable seed))
  (make-instance 'os-prng))

(setf *prng* (make-prng :os))
