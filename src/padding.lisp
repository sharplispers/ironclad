;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; padding.lisp -- implementation of various padding algorithms

(in-package :crypto)

(defclass padding () ())

;;; PKCS7 padding

(defclass pkcs7-padding (padding) ())

(defmethod add-padding-bytes ((padding pkcs7-padding) text start
                              block-offset block-size)
  (declare (type simple-octet-vector text))
  (declare (type index start block-offset))
  (let* ((n-padding-bytes (- block-size block-offset))
         (pad-byte (if (zerop n-padding-bytes) block-size n-padding-bytes)))
    (declare (type (unsigned-byte 8) pad-byte))
    (loop for i from (+ start block-offset)
          for j from 0 below n-padding-bytes
          do (setf (aref text i) pad-byte))
    (values)))
