;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; dsa.lisp -- implementation of the Digital Signature Algorithm

(in-package :crypto)


;;; class definitions

(defclass dsa-key ()
  ((group :initarg :group :reader group)))

(defclass dsa-public-key (dsa-key)
  ((y :initarg :y :reader dsa-key-y :type integer)))

(defclass dsa-private-key (dsa-key)
  ((y :initarg :y :reader dsa-key-y :type integer)
   (x :initarg :x :reader dsa-key-x :type integer)))

(defclass dsa-signature ()
  ((r :initarg :r :reader dsa-signature-r)
   (s :initarg :s :reader dsa-signature-s)))

(defun dsa-key-p (dsa-key)
  (group-pval (group dsa-key)))
(defun dsa-key-q (dsa-key)
  (group-qval (group dsa-key)))
(defun dsa-key-g (dsa-key)
  (group-gval (group dsa-key)))


;;; function definitions

(defun make-dsa-signature (r s)
  (make-instance 'dsa-signature
                 :r (maybe-integerize r) :s (maybe-integerize s)))

(defmethod make-public-key ((kind (eql :dsa))
                            &key p q g y &allow-other-keys)
  (let ((group (make-instance 'discrete-logarithm-group :p p :q q :g g)))
    (make-instance 'dsa-public-key :group group :y y)))

(defmethod make-private-key ((kind (eql :dsa))
                             &key p q g y x &allow-other-keys)
  (unless (and p q g)
    ;; FIXME: "real" ironclad error needed here
    (error "Must specify all members of the DL group for DSA"))
  (let ((group (make-instance 'discrete-logarithm-group :p p :q q :g g)))
    (make-instance 'dsa-private-key :group group :y y :x x)))

(defconstant +dsa-message-length+ 20)

;;; Note that hashing is not performed here.
(defmethod sign-message ((key dsa-private-key) message &key (start 0) end)
  (let ((end (or end (length message))))
    (unless (= (- end start) +dsa-message-length+)
      ;; FIXME: "real" ironclad error needed here
      (error "Can only sign exactly 20 bytes of message with DSA"))
    (let* ((group (group key))
           (k (random (group-qval group)))
           (r (mod (expt-mod (group-gval group) k (group-pval group))
                   (group-qval group)))
           (message-integer (octets-to-integer message :start start :end end))
           (k-inverse (modular-inverse k (group-qval group)))
           (s (mod (* k-inverse
                      (+ (* (dsa-key-x key) r) message-integer))
                   (group-qval group))))
      (assert (= (mod (* k k-inverse) (group-qval group)) 1))
      (make-dsa-signature (integer-to-octets r) (integer-to-octets s)))))

(defmethod verify-signature ((key dsa-public-key) message (signature dsa-signature)
                             &key (start 0) end)
  (let ((end (or end (length message))))
    (unless (= (- end start) +dsa-message-length+)
      ;; FIXME: "real" ironclad error needed here
      (error "Can only verify exactly 20 bytes of message with DSA"))
    (let* ((group (group key))
           (message-integer (octets-to-integer message :start start :end end))
           (r-integer (maybe-integerize (dsa-signature-r signature)))
           (s-integer (maybe-integerize (dsa-signature-s signature)))
           (w (modular-inverse s-integer (group-qval group)))
           (u1 (mod (* message-integer w) (group-qval group)))
           (u2 (mod (* r-integer w) (group-qval group)))
           (v (mod (mod (* (expt-mod (group-gval group) u1 (group-pval group))
                           (expt-mod (dsa-key-y key) u2 (group-pval group)))
                        (group-pval group))
                   (group-qval group))))
      (= v r-integer))))
