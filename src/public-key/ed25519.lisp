;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ed25519.lisp -- implementation of the ed25519 signature algorithm

(in-package :crypto)


;;; class definitions

(defclass ed25519-public-key ()
  ((y :initarg :y :reader ed25519-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass ed25519-private-key ()
  ((x :initarg :x :reader ed25519-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader ed25519-key-y :type (simple-array (unsigned-byte 8) (*)))))


;;; constant and function definitions

(defconstant +ed25519-bits+ 256)
(defconstant +ed25519-q+ 57896044618658097711785492504343953926634992332820282019728792003956564819949)
(defconstant +ed25519-l+ 7237005577332262213973186563042994240857116359379907606001950938285454250989)
(defconstant +ed25519-d+ 37095705934669439343138083508754565189542113879843219016388785533085940283555)
(defconstant +ed25519-i+ 19681161376707505956807079304988542015446066515923890162744021073123829784752)
(defconst +ed25519-b+
  (vector 15112221349535400772501151409588531511454012693041857206046113283949847762202
          46316835694926478169428394003475163141307993866256225615783033603165251855960
          1))

(defun ed25519-inv (x)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (modular-inverse (mod x +ed25519-q+) +ed25519-q+))

(defun ed25519-recover-x (y)
  "Recover the X coordinate of a point on ed25519 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((yy (mod (* y y) +ed25519-q+))
         (xx (mod (* (- yy 1) (ed25519-inv (+ (* +ed25519-d+ yy) 1))) +ed25519-q+))
         (x (expt-mod xx (/ (+ +ed25519-q+ 3) 8) +ed25519-q+)))
    (unless (zerop (mod (- (* x x) xx) +ed25519-q+))
      (setf x (mod (* x +ed25519-i+) +ed25519-q+)))
    (unless (evenp x)
      (setf x (- +ed25519-q+ x)))
    x))

(defun ed25519-edwards-double (p)
  "Point doubling on ed25519 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x (aref p 0))
         (y (aref p 1))
         (z (aref p 2))
         (a (mod (* z z) +ed25519-q+))
         (b (mod (* a a) +ed25519-q+))
         (c (mod (* x x) +ed25519-q+))
         (d (mod (* y y) +ed25519-q+))
         (e (mod (* a (- d c)) +ed25519-q+))
         (f (mod (- (+ b b) e) +ed25519-q+))
         (g (mod (+ c d) +ed25519-q+))
         (h (mod (+ x y) +ed25519-q+))
         (j (mod (- (* h h) g) +ed25519-q+))
         (u (mod (* a f j) +ed25519-q+))
         (v (mod (* a e g) +ed25519-q+))
         (w (mod (* e f) +ed25519-q+)))
    (vector u v w)))

(defun ed25519-edwards-add (p q)
  "Point addition on ed25519 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x1 (aref p 0))
         (y1 (aref p 1))
         (z1 (aref p 2))
         (x2 (aref q 0))
         (y2 (aref q 1))
         (z2 (aref q 2))
         (a (mod (* z1 z2) +ed25519-q+))
         (b (mod (* a a) +ed25519-q+))
         (c (mod (* x1 x2) +ed25519-q+))
         (d (mod (* y1 y2) +ed25519-q+))
         (e (mod (* +ed25519-d+ c d) +ed25519-q+))
         (f (mod (- b e) +ed25519-q+))
         (g (mod (+ b e) +ed25519-q+))
         (h (mod (* (+ x1 y1) (+ x2 y2)) +ed25519-q+))
         (j (mod (+ c d) +ed25519-q+))
         (u (mod (* a f (- h j)) +ed25519-q+))
         (v (mod (* a g j) +ed25519-q+))
         (w (mod (* f g) +ed25519-q+)))
    (vector u v w)))

(defun ed25519-scalar-mult (p e)
  "Point multiplication on ed25519 curve using the Montgomery ladder."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (do ((r0 (vector 0 1 1))
       (r1 p)
       (i (1- (integer-length e)) (1- i)))
      ((minusp i) r0)
    (if (logbitp i e)
        (setf r0 (ed25519-edwards-add r0 r1)
              r1 (ed25519-edwards-double r1))
        (setf r1 (ed25519-edwards-add r0 r1)
              r0 (ed25519-edwards-double r0)))))

(defun ed25519-on-curve-p (p)
  "Check if the point P is on ed25519 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x (aref p 0))
         (y (aref p 1))
         (z (aref p 2))
         (xx (mod (* x x) +ed25519-q+))
         (yy (mod (* y y) +ed25519-q+))
         (zz (mod (* z z) +ed25519-q+))
         (zzzz (mod (* zz zz) +ed25519-q+))
         (a (mod (* zz (- yy xx)) +ed25519-q+))
         (b (mod (+ zzzz (* +ed25519-d+ xx yy)) +ed25519-q+)))
    (zerop (mod (- a b) +ed25519-q+))))

(defun ed25519-point-equal (p q)
  "Check whether P and Q represent the same point."
  (let ((x1 (aref p 0))
        (y1 (aref p 1))
        (z1 (aref p 2))
        (x2 (aref q 0))
        (y2 (aref q 1))
        (z2 (aref q 2)))
    (and (zerop (mod (- (* x1 z2) (* x2 z1)) +ed25519-q+))
         (zerop (mod (- (* y1 z2) (* y2 z1)) +ed25519-q+)))))

(defun ed25519-encode-int (y)
  "Encode an integer as a byte array (little-endian)."
  (integer-to-octets y :n-bits +ed25519-bits+ :big-endian nil))

(defun ed25519-decode-int (octets)
  "Decode a byte array to an integer (little-endian)."
  (octets-to-integer octets :big-endian nil))

(defun ed25519-encode-point (p)
  "Encode a point on ed25519 curve as a byte array."
  (let* ((z (aref p 2))
         (invz (ed25519-inv z))
         (x (mod (* (aref p 0) invz) +ed25519-q+))
         (y (mod (* (aref p 1) invz) +ed25519-q+)))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) (ldb (byte 1 0) x))
    (ed25519-encode-int y)))

(defun ed25519-decode-point (octets)
  "Decode a byte array to a point on ed25519 curve."
  (let* ((y (ed25519-decode-int octets))
         (b (ldb (byte 1 (- +ed25519-bits+ 1)) y)))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) 0)
    (let ((x (ed25519-recover-x y)))
      (unless (= (ldb (byte 1 0) x) b)
        (setf x (- +ed25519-q+ x)))
      (let ((p (vector x y 1)))
        (unless (ed25519-on-curve-p p)
          (error "Decoding point that is not on curve"))
        p))))

(defun ed25519-hash (&rest messages)
  (let ((digest (make-digest :sha512)))
    (dolist (m messages)
      (update-digest digest m))
    (produce-digest digest)))

(defun ed25519-public-key (sk)
  "Compute the public key associated to the private key SK."
  (let ((h (ed25519-hash sk)))
    (setf h (subseq h 0 (/ +ed25519-bits+ 8)))
    (setf (ldb (byte 3 0) (elt h 0)) 0)
    (setf (ldb (byte 2 6) (elt h (- (/ +ed25519-bits+ 8) 1))) 1)
    (let ((a (ed25519-decode-int h)))
      (ed25519-encode-point (ed25519-scalar-mult +ed25519-b+ a)))))

(defun ed25519-sign (m sk pk)
  (let ((h (ed25519-hash sk)))
    (setf (ldb (byte 3 0) (elt h 0)) 0)
    (setf (ldb (byte 2 6) (elt h (- (/ +ed25519-bits+ 8) 1))) 1)
    (let* ((a (ed25519-decode-int (subseq h 0 (/ +ed25519-bits+ 8))))
           (ri (ed25519-decode-int (ed25519-hash (subseq h (/ +ed25519-bits+ 8) (/ +ed25519-bits+ 4)) m)))
           (r (ed25519-scalar-mult +ed25519-b+ ri))
           (s (mod (+ (* (ed25519-decode-int (ed25519-hash (ed25519-encode-point r) pk m)) a) ri) +ed25519-l+)))
      (concatenate '(simple-array (unsigned-byte 8) (*))
                   (ed25519-encode-point r)
                   (ed25519-encode-int s)))))

(defun ed25519-verify (s m pk)
  (unless (= (length s) (/ +ed25519-bits+ 4))
    (error "Bad signature length"))
  (unless (= (length pk) (/ +ed25519-bits+ 8))
    (error "Bad public key length"))
  (let* ((r (ed25519-decode-point (subseq s 0 (/ +ed25519-bits+ 8))))
         (s (ed25519-decode-int (subseq s (/ +ed25519-bits+ 8) (/ +ed25519-bits+ 4))))
         (a (ed25519-decode-point pk))
         (h (ed25519-decode-int (ed25519-hash (ed25519-encode-point r) pk m)))
         (res1 (ed25519-scalar-mult +ed25519-b+ s))
         (res2 (ed25519-edwards-add r (ed25519-scalar-mult a h))))
    (ed25519-point-equal res1 res2)))

(defmethod make-public-key ((kind (eql :ed25519)) &key y &allow-other-keys)
  (make-instance 'ed25519-public-key :y y))

(defmethod make-private-key ((kind (eql :ed25519)) &key x y &allow-other-keys)
  (make-instance 'ed25519-private-key :x x :y y))

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
  (let* ((prng (or *prng* (make-prng :fortuna :seed :random)))
         (sk (random-data (/ +ed25519-bits+ 8) prng)))
    (setf (ldb (byte 3 0) (elt sk 0)) 0)
    (setf (ldb (byte 2 6) (elt sk (- (/ +ed25519-bits+ 8) 1))) 1)
    (let ((pk (ed25519-public-key sk)))
      (values (make-private-key :ed25519 :x sk :y pk)
              (make-public-key :ed25519 :y pk)))))
