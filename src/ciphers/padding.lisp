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
    (declare (type (unsigned-byte 8) n-padding-bytes))
    (when (or (> n-padding-bytes block-size)
              (not (loop for i from (- block-size n-padding-bytes) below block-size
                         always (= (aref text (+ start i)) n-padding-bytes))))
      (error 'invalid-padding :name 'pkcs7 :block text))
    n-padding-bytes))


;;; ANSI X.923 padding

(defclass ansi-x923-padding (padding) ())

(defmethod add-padding-bytes ((padding ansi-x923-padding) text start block-offset block-size)
  (declare (type simple-octet-vector text))
  (declare (type index start block-offset))
  (let ((n-padding-bytes (- block-size block-offset)))
    (declare (type (unsigned-byte 8) n-padding-bytes))
    (fill text 0 :start (+ start block-offset) :end (+ start block-size))
    (setf (aref text (1- (+ start block-size))) n-padding-bytes)
    (values)))

(defmethod count-padding-bytes ((padding ansi-x923-padding) text start block-size)
  (declare (type simple-octet-vector text))
  (declare (type index start))
  (let ((n-padding-bytes (aref text (1- (+ start block-size)))))
    (declare (type (unsigned-byte 8) n-padding-bytes))
    (when (or (> n-padding-bytes block-size)
              (not (loop for i from (- block-size n-padding-bytes) below (1- block-size)
                         always (zerop (aref text (+ start i))))))
      (error 'invalid-padding :name 'ansi-x923 :block text))
    n-padding-bytes))
