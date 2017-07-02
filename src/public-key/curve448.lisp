;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; curve448.lisp -- implementation of the curve448 Diffie-Hellman function

(in-package :crypto)


;;; class definitions

(defclass curve448-public-key ()
  ((y :initarg :y :reader curve448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass curve448-private-key ()
  ((x :initarg :x :reader curve448-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader curve448-key-y :type (simple-array (unsigned-byte 8) (*)))))

;; Internally, we represent a point (x, y) using only the projective
;; coordinate (X, Z) for x, with x = X / Z.
(deftype curve448-point () '(vector integer 2))


;;; constants and function definitions

(defconstant +curve448-bits+ 448)
(defconstant +curve448-p+ 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439)
(defconstant +curve448-a24+ 39081)

(declaim (type curve448-point +curve448-g+))
(defconst +curve448-g+ (vector 5 1))


(declaim (inline curve448-inv))
(defun curve448-inv (x)
  (expt-mod x (- +curve448-p+ 2) +curve448-p+))

(defun curve448-double-and-add (x1 z1 x2 z2 x3)
  "Point doubling and addition on curve448 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer x1 z1 x2 z2 x3))
  (let* ((t1 (mod (+ x1 z1) +curve448-p+))
         (t2 (mod (- x1 z1) +curve448-p+))
         (t3 (mod (- x2 z2) +curve448-p+))
         (t4 (mod (* t1 t3) +curve448-p+))
         (t5 (mod (+ x2 z2) +curve448-p+))
         (t6 (mod (* t2 t5) +curve448-p+))
         (t7 (mod (- t4 t6) +curve448-p+))
         (t8 (mod (* t7 t7) +curve448-p+))
         (z5 (mod (* x3 t8) +curve448-p+))
         (t9 (mod (+ t4 t6) +curve448-p+))
         (x5 (mod (* t9 t9) +curve448-p+))
         (t10 (mod (* t1 t1) +curve448-p+))
         (t11 (mod (* t2 t2) +curve448-p+))
         (x4 (mod (* t10 t11) +curve448-p+))
         (t12 (mod (- t10 t11) +curve448-p+))
         (t13 (mod (* t12 +curve448-a24+) +curve448-p+))
         (t14 (mod (+ t13 t10) +curve448-p+))
         (z4 (mod (* t14 t12) +curve448-p+)))
    (declare (type integer t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 x4 z4 x5 z5))
    (values x4 z4 x5 z5)))

(defun curve448-scalar-mult (p n)
  "Point multiplication on curve448 curve using the Montgomery ladder."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type curve448-point p)
           (type integer n))
  (assert (= 1 (aref p 1)))
  (do ((x (aref p 0))
       (x1 1)
       (z1 0)
       (x2 (aref p 0))
       (z2 1)
       (i 447 (1- i)))
      ((minusp i) (vector x1 z1))
    (declare (type integer x x1 z1 x2 z2)
             (type fixnum i))
    (if (logbitp i n)
        (multiple-value-setq (x2 z2 x1 z1)
          (curve448-double-and-add x2 z2 x1 z1 x))
        (multiple-value-setq (x1 z1 x2 z2)
          (curve448-double-and-add x1 z1 x2 z2 x)))))

(defun curve448-encode-int (x)
  "Encode an integer as a byte array (little-endian)."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (integer-to-octets x :n-bits +curve448-bits+ :big-endian nil))

(defun curve448-decode-int (octets)
  "Decode a byte array to an integer (little-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (ldb (byte +curve448-bits+ 0) (octets-to-integer octets :big-endian nil))))
    (setf (ldb (byte 2 0) x) 0)
    (setf (ldb (byte 1 (1- +curve448-bits+)) x) 1)
    x))

(defun curve448-encode-point (p)
  "Encode a point on curve448 curve as a byte array."
  (declare (type curve448-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x (aref p 0))
         (z (aref p 1))
         (x1 (mod (* x (curve448-inv z)) +curve448-p+)))
    (declare (type integer x z x1))
    (curve448-encode-int x1)))

(defun curve448-decode-point (octets)
  "Decode a byte array to a point on curve448 curve."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x (ldb (byte +curve448-bits+ 0) (octets-to-integer octets :big-endian nil))))
    (declare (integer x))
    (vector x 1)))

(defun curve448-public-key (sk)
  "Compute the public key associated to the private key SK."
  (declare (type (simple-array (unsigned-byte 8) (*)) sk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((s (curve448-decode-int sk))
         (p (curve448-scalar-mult +curve448-g+ s)))
    (curve448-encode-point p)))

(defmethod make-public-key ((kind (eql :curve448)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'curve448
           :parameter 'y
           :description "public key"))
  (make-instance 'curve448-public-key :y y))

(defmethod destructure-public-key ((public-key curve448-public-key))
  (list :y (curve448-key-y public-key)))

(defmethod make-private-key ((kind (eql :curve448)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'curve448
           :parameter 'x
           :description "private key"))
  (make-instance 'curve448-private-key :x x :y (or y (curve448-public-key x))))

(defmethod destructure-private-key ((private-key curve448-private-key))
  (list :x (curve448-key-x private-key)
        :y (curve448-key-y private-key)))

(defmethod generate-key-pair ((kind (eql :curve448)) &key &allow-other-keys)
  (let ((sk (random-data (ceiling +curve448-bits+ 8))))
    (setf (ldb (byte 2 0) (elt sk 0)) 0)
    (setf (ldb (byte 1 7) (elt sk (- (ceiling +curve448-bits+ 8) 1))) 1)
    (let ((pk (curve448-public-key sk)))
      (values (make-private-key :curve448 :x sk :y pk)
              (make-public-key :curve448 :y pk)))))

(defmethod diffie-hellman ((private-key curve448-private-key) (public-key curve448-public-key))
  (let ((s (curve448-decode-int (curve448-key-x private-key)))
        (p (curve448-decode-point (curve448-key-y public-key))))
    (curve448-encode-point (curve448-scalar-mult p s))))
