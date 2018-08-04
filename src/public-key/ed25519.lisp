;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ed25519.lisp -- implementation of the ed25519 signature algorithm

(in-package :crypto)


;;; class definitions

(defclass ed25519-public-key ()
  ((y :initarg :y :reader ed25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass ed25519-private-key ()
  ((x :initarg :x :reader ed25519-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader ed25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

;; Internally, a point (x, y) is represented in extended homogeneous
;; coordinates (X, Y, Z, W), with x = X / Z, y = Y / Z and x * y = W / Z.
(deftype ed25519-point () '(vector integer 4))


;;; constant, variable and function definitions

(defconstant +ed25519-bits+ 256)
(defconstant +ed25519-q+ 57896044618658097711785492504343953926634992332820282019728792003956564819949)
(defconstant +ed25519-l+ 7237005577332262213973186563042994240857116359379907606001950938285454250989)
(defconstant +ed25519-d+ 37095705934669439343138083508754565189542113879843219016388785533085940283555)
(defconstant +ed25519-i+ 19681161376707505956807079304988542015446066515923890162744021073123829784752)

(declaim (type ed25519-point +ed25519-b+))
(defconst +ed25519-b+
  (vector 15112221349535400772501151409588531511454012693041857206046113283949847762202
          46316835694926478169428394003475163141307993866256225615783033603165251855960
          1
          46827403850823179245072216630277197565144205554125654976674165829533817101731))


(declaim (inline ed25519-inv))
(defun ed25519-inv (x)
  (expt-mod x (- +ed25519-q+ 2) +ed25519-q+))

(defun ed25519-recover-x (y)
  "Recover the X coordinate of a point on ed25519 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer y))
  (let* ((u (mod (1- (* y y)) +ed25519-q+))
         (v (mod (1+ (* +ed25519-d+ (1+ u))) +ed25519-q+))
         (v3 (mod (* v v v) +ed25519-q+))
         (uv3 (mod (* u v3) +ed25519-q+))
         (uv7 (mod (* uv3 v3 v) +ed25519-q+))
         (x (mod (* uv3 (expt-mod uv7 (/ (- +ed25519-q+ 5) 8) +ed25519-q+)) +ed25519-q+)))
    (declare (type integer u v v3 uv3 uv7 x))
    (unless (= u (mod (* v x x) +ed25519-q+))
      (setf x (mod (* x +ed25519-i+) +ed25519-q+)))
    (unless (evenp x)
      (setf x (- +ed25519-q+ x)))
    x))

(defun ed25519-edwards-add (p q)
  "Point addition on ed25519 curve."
  (declare (type ed25519-point p q)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x1 (aref p 0))
         (y1 (aref p 1))
         (z1 (aref p 2))
         (w1 (aref p 3))
         (x2 (aref q 0))
         (y2 (aref q 1))
         (z2 (aref q 2))
         (w2 (aref q 3))
         (a (mod (* (- y1 x1) (- y2 x2)) +ed25519-q+))
         (b (mod (* (+ y1 x1) (+ y2 x2)) +ed25519-q+))
         (i (mod (* w1 w2) +ed25519-q+))
         (c (mod (* 2 i +ed25519-d+) +ed25519-q+))
         (d (mod (* 2 z1 z2) +ed25519-q+))
         (e (mod (- b a) +ed25519-q+))
         (f (mod (- d c) +ed25519-q+))
         (g (mod (+ d c) +ed25519-q+))
         (h (mod (+ b a) +ed25519-q+))
         (x3 (mod (* e f) +ed25519-q+))
         (y3 (mod (* g h) +ed25519-q+))
         (z3 (mod (* f g) +ed25519-q+))
         (w3 (mod (* e h) +ed25519-q+)))
    (declare (type integer x1 y1 z1 w1 x2 y2 z2 w2 a b c d e f g h i x3 y3 z3 w3))
    (vector x3 y3 z3 w3)))

(defun ed25519-edwards-double (p)
  "Point doubling on ed25519 curve."
  (declare (type ed25519-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x1 (aref p 0))
         (y1 (aref p 1))
         (z1 (aref p 2))
         (a (mod (* x1 x1) +ed25519-q+))
         (b (mod (* y1 y1) +ed25519-q+))
         (c (mod (* 2 z1 z1) +ed25519-q+))
         (d (mod (+ x1 y1) +ed25519-q+))
         (i (mod (* d d) +ed25519-q+))
         (h (mod (+ a b) +ed25519-q+))
         (e (mod (- h i) +ed25519-q+))
         (g (mod (- a b) +ed25519-q+))
         (f (mod (+ c g) +ed25519-q+))
         (x2 (mod (* e f) +ed25519-q+))
         (y2 (mod (* g h) +ed25519-q+))
         (z2 (mod (* f g) +ed25519-q+))
         (w2 (mod (* e h) +ed25519-q+)))
    (declare (type integer x1 y1 z1 a b c d e f g h i x2 y2 z2 w2))
    (vector x2 y2 z2 w2)))

(defun ed25519-scalar-mult (p e)
  "Point multiplication on ed25519 curve using the Montgomery ladder."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type ed25519-point p)
           (type integer e))
  (do ((r0 (vector 0 1 1 0))
       (r1 p)
       (i 254 (1- i)))
      ((minusp i) r0)
    (declare (type ed25519-point r0 r1)
             (type fixnum i))
    (if (logbitp i e)
        (setf r0 (ed25519-edwards-add r0 r1)
              r1 (ed25519-edwards-double r1))
        (setf r1 (ed25519-edwards-add r0 r1)
              r0 (ed25519-edwards-double r0)))))

(defun ed25519-on-curve-p (p)
  "Check if the point P is on ed25519 curve."
  (declare (type ed25519-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x (aref p 0))
         (y (aref p 1))
         (z (aref p 2))
         (w (aref p 3))
         (xx (mod (* x x) +ed25519-q+))
         (yy (mod (* y y) +ed25519-q+))
         (zz (mod (* z z) +ed25519-q+))
         (ww (mod (* w w) +ed25519-q+))
         (a (mod (- yy xx) +ed25519-q+))
         (b (mod (+ zz (* +ed25519-d+ ww)) +ed25519-q+)))
    (declare (type integer x y z xx yy zz ww a b))
    (zerop (mod (- a b) +ed25519-q+))))

(defun ed25519-point-equal (p q)
  "Check whether P and Q represent the same point."
  (declare (type ed25519-point p q)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (aref p 0))
        (y1 (aref p 1))
        (z1 (aref p 2))
        (x2 (aref q 0))
        (y2 (aref q 1))
        (z2 (aref q 2)))
    (declare (type integer x1 y1 z1 x2 y2 z2))
    (and (zerop (mod (- (* x1 z2) (* x2 z1)) +ed25519-q+))
         (zerop (mod (- (* y1 z2) (* y2 z1)) +ed25519-q+)))))

(defun ed25519-encode-int (y)
  "Encode an integer as a byte array (little-endian)."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (integer-to-octets y :n-bits +ed25519-bits+ :big-endian nil))

(defun ed25519-decode-int (octets)
  "Decode a byte array to an integer (little-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (octets-to-integer octets :big-endian nil))

(defun ed25519-encode-point (p)
  "Encode a point on ed25519 curve as a byte array."
  (declare (type ed25519-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((z (aref p 2))
         (invz (ed25519-inv z))
         (x (mod (* (aref p 0) invz) +ed25519-q+))
         (y (mod (* (aref p 1) invz) +ed25519-q+)))
    (declare (type integer x y z invz))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) (ldb (byte 1 0) x))
    (ed25519-encode-int y)))

(defun ed25519-decode-point (octets)
  "Decode a byte array to a point on ed25519 curve."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((y (ed25519-decode-int octets))
         (b (ldb (byte 1 (- +ed25519-bits+ 1)) y)))
    (declare (type integer y)
             (type fixnum b))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) 0)
    (let ((x (ed25519-recover-x y)))
      (declare (type integer x))
      (unless (= (ldb (byte 1 0) x) b)
        (setf x (- +ed25519-q+ x)))
      (let* ((w (mod (* x y) +ed25519-q+))
             (p (vector x y 1 w)))
        (declare (type integer w)
                 (type ed25519-point p))
        (unless (ed25519-on-curve-p p)
          (error 'invalid-curve-point :kind 'ed25519))
        p))))

(defun ed25519-hash (&rest messages)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((digest (make-digest :sha512)))
    (dolist (m messages)
      (update-digest digest m))
    (produce-digest digest)))

(defun ed25519-public-key (sk)
  "Compute the public key associated to the private key SK."
  (declare (type (simple-array (unsigned-byte 8) (*)) sk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed25519-hash sk)))
    (setf h (subseq h 0 (/ +ed25519-bits+ 8)))
    (setf (ldb (byte 3 0) (elt h 0)) 0)
    (setf (ldb (byte 2 6) (elt h (- (/ +ed25519-bits+ 8) 1))) 1)
    (let ((a (ed25519-decode-int h)))
      (ed25519-encode-point (ed25519-scalar-mult +ed25519-b+ a)))))

(defmethod make-signature ((kind (eql :ed25519)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'ed25519
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'ed25519
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :ed25519)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +ed25519-bits+ 4))
        (error 'invalid-signature-length :kind 'ed25519)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defun ed25519-sign (m sk pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) m sk pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed25519-hash sk)))
    (setf (ldb (byte 3 0) (elt h 0)) 0)
    (setf (ldb (byte 2 6) (elt h (- (/ +ed25519-bits+ 8) 1))) 1)
    (let* ((a (ed25519-decode-int (subseq h 0 (/ +ed25519-bits+ 8))))
           (rh (ed25519-hash (subseq h (/ +ed25519-bits+ 8) (/ +ed25519-bits+ 4)) m))
           (ri (mod (ed25519-decode-int rh) +ed25519-l+))
           (r (ed25519-scalar-mult +ed25519-b+ ri))
           (rp (ed25519-encode-point r))
           (k (mod (ed25519-decode-int (ed25519-hash rp pk m)) +ed25519-l+))
           (s (mod (+ (* k a) ri) +ed25519-l+)))
      (declare (type integer a ri k s)
               (type (simple-array (unsigned-byte 8) (*)) rh)
               (type ed25519-point r))
      (make-signature :ed25519 :r rp :s (ed25519-encode-int s)))))

(defun ed25519-verify (s m pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) s m pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length s) (/ +ed25519-bits+ 4))
    (error 'invalid-signature-length :kind 'ed25519))
  (unless (= (length pk) (/ +ed25519-bits+ 8))
    (error 'invalid-public-key-length :kind 'ed25519))
  (let* ((signature-elements (destructure-signature :ed25519 s))
         (r (getf signature-elements :r))
         (rp (ed25519-decode-point r))
         (s (ed25519-decode-int (getf signature-elements :s)))
         (a (ed25519-decode-point pk))
         (h (mod (ed25519-decode-int (ed25519-hash r pk m)) +ed25519-l+))
         (res1 (ed25519-scalar-mult +ed25519-b+ s))
         (res2 (ed25519-edwards-add rp (ed25519-scalar-mult a h))))
    (declare (type (simple-array (unsigned-byte 8) (*)) r)
             (type integer s h)
             (type ed25519-point rp a res1 res2))
    (and (< s +ed25519-l+)
         (ed25519-point-equal res1 res2))))

(defmethod make-public-key ((kind (eql :ed25519)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'ed25519
           :parameter 'y
           :description "public key"))
  (make-instance 'ed25519-public-key :y y))

(defmethod destructure-public-key ((public-key ed25519-public-key))
  (list :y (ed25519-key-y public-key)))

(defmethod make-private-key ((kind (eql :ed25519)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'ed25519
           :parameter 'x
           :description "private key"))
  (make-instance 'ed25519-private-key :x x :y (or y (ed25519-public-key x))))

(defmethod destructure-private-key ((private-key ed25519-private-key))
  (list :x (ed25519-key-x private-key)
        :y (ed25519-key-y private-key)))

(defmethod sign-message ((key ed25519-private-key) message &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (sk (ed25519-key-x key))
        (pk (ed25519-key-y key)))
    (ed25519-sign (subseq message start end) sk pk)))

(defmethod verify-signature ((key ed25519-public-key) message signature &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (pk (ed25519-key-y key)))
    (ed25519-verify signature (subseq message start end) pk)))

(defmethod generate-key-pair ((kind (eql :ed25519)) &key &allow-other-keys)
  (let* ((sk (random-data (/ +ed25519-bits+ 8)))
         (pk (ed25519-public-key sk)))
    (values (make-private-key :ed25519 :x sk :y pk)
            (make-public-key :ed25519 :y pk))))
