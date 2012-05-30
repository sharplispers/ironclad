;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; macro-utils.lisp -- things to make compiler macros easier

(in-package :crypto)

(defun quotationp (thing)
  (and (consp thing) (consp (rest thing))
       (cl:null (cddr thing)) (eq (first thing) 'quote)))

(defun unquote (thing)
  (if (quotationp thing) (second thing) thing))

(defun massage-symbol (symbol)
  (let ((package (symbol-package symbol))
        (ironclad (load-time-value (find-package :ironclad))))
    (cond
      ((eq package ironclad) symbol)
      ((eq package (load-time-value (find-package :keyword)))
       (find-symbol (symbol-name symbol) ironclad))
      (t nil))))
