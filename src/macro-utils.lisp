;;;; macro-utils.lisp -- things to make compiler macros easier

(in-package :crypto)

(defun quotationp (thing)
  (and (consp thing) (consp (rest thing))
       (cl:null (cddr thing)) (eq (first thing) 'quote)))

(defun unquote (thing)
  (if (quotationp thing) (second thing) thing))
