;;;; -*- mode: lisp; indent-tabs-mode: nil -*-

(in-package :crypto)

;;; Check what features are supported by the CPU

#+(and sbcl x86-64 ironclad-assembly)
(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun aes-ni-support-p ()
    (aes-ni-support-p))
  (compile 'aes-ni-support-p)
  (when (aes-ni-support-p)
    (pushnew :aes-ni *features*))

  (defun pclmulqdq-support-p ()
    (pclmulqdq-support-p))
  (compile 'pclmulqdq-support-p)
  (when (pclmulqdq-support-p)
    (pushnew :pclmulqdq *features*)))
