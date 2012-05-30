;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; padding.lisp -- implementation of various padding algorithms

(in-package :crypto)

(defclass padding () ())

(defgeneric add-padding-bytes (padding text start block-offset block-size)
  (:documentation "Add padding to the block in TEXT beginning at position
START.  Padding is done according to PADDING and assumes that text
prior to BLOCK-OFFSET is user-supplied.

This function assumes that the portion of TEXT from START to
 (+ START BLOCK-SIZE) is writable."))

(defgeneric count-padding-bytes (padding text start block-size)
  (:documentation "Return the number of bytes of padding in the block in
TEXT beginning at START.  The padding algorithm used for the block is
PADDING."))


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
