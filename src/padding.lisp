;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; padding.lisp -- implementation of various padding algorithms

(in-package :crypto)

(defclass padding () ())

;;; PKCS7 padding

(defclass pkcs7-padding (padding) ())

(defmethod add-padding-bytes ((padding pkcs7-padding) text start block-offset block-size)
  (declare (type simple-octet-vector text))
  (declare (type index start block-offset))
  (let ((n-padding-bytes (- block-size block-offset)))
    (declare (type (unsigned-byte 8) n-padding-bytes))
    (fill text n-padding-bytes :start (+ start block-offset) :end (+ start block-size))
    (values)))

(defmethod count-padding-bytes ((padding pkcs7-padding) text start block-size)
  (declare (type simple-octet-vector text))
  (declare (type index start))
  (let ((n-padding-bytes (aref text (1- (+ start block-size)))))
    (when (> n-padding-bytes block-size)
      (error 'invalid-padding :padding-name 'pkcs7 :block text))
    n-padding-bytes))
