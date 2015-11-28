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
  (cons 15112221349535400772501151409588531511454012693041857206046113283949847762202
        46316835694926478169428394003475163141307993866256225615783033603165251855960))

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
  (let* ((x (car p))
         (y (cdr p))
         (xx (mod (* x x) +ed25519-q+))
         (xy (mod (* x y) +ed25519-q+))
         (yy (mod (* y y) +ed25519-q+))
         (dxxyy (mod (* +ed25519-d+ xx yy) +ed25519-q+))
         (x2 (* 2 xy (ed25519-inv (+ 1 dxxyy))))
         (y2 (* (+ yy xx) (ed25519-inv (- 1 dxxyy)))))
    (cons (mod x2 +ed25519-q+) (mod y2 +ed25519-q+))))

(defun ed25519-edwards-add (p q)
  "Point addition on ed25519 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x1 (car p))
         (y1 (cdr p))
         (x2 (car q))
         (y2 (cdr q))
         (x1x2 (mod (* x1 x2) +ed25519-q+))
         (x1y2 (mod (* x1 y2) +ed25519-q+))
         (x2y1 (mod (* x2 y1) +ed25519-q+))
         (y1y2 (mod (* y1 y2) +ed25519-q+))
         (dx1x2y1y2 (mod (* +ed25519-d+ x1x2 y1y2) +ed25519-q+))
         (x3 (* (+ x1y2 x2y1) (ed25519-inv (+ 1 dx1x2y1y2))))
         (y3 (* (+ y1y2 x1x2) (ed25519-inv (- 1 dx1x2y1y2)))))
    (cons (mod x3 +ed25519-q+) (mod y3 +ed25519-q+))))

(defun ed25519-scalar-mult (point e)
  "Point multiplication on ed25519 curve using the windowed method."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((result (cons 0 1))
         (k 5)
         (base (expt 2 k))

         ;; Compute the digits of the exponent in base 2^k
         (digits (do ((q e)
                      r
                      digits)
                     ((zerop q) digits)
                   (multiple-value-setq (q r) (floor q base))
                   (push r digits)))
         (multiples (make-array base :initial-element (cons 0 1))))

    ;; Precompute the multiples of point
    (dotimes (i (1- base))
      (setf (aref multiples (1+ i)) (ed25519-edwards-add (aref multiples i) point)))

    ;; Compute the result
    (dolist (digit digits result)
      (dotimes (i k)
        (setf result (ed25519-edwards-double result)))
      (unless (zerop digit)
        (setf result (ed25519-edwards-add result (aref multiples digit)))))))

(defun ed25519-on-curve-p (p)
  "Check if the point P is on ed25519 curve."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x (car p))
         (y (cdr p))
         (xx (mod (* x x) +ed25519-q+))
         (yy (mod (* y y) +ed25519-q+)))
    (zerop (mod (- yy xx 1 (* +ed25519-d+ xx yy)) +ed25519-q+))))

(defun ed25519-encode-int (y)
  "Encode an integer as a byte array (little-endian)."
  (integer-to-octets y :n-bits +ed25519-bits+ :big-endian nil))

(defun ed25519-decode-int (octets)
  "Decode a byte array to an integer (little-endian)."
  (octets-to-integer octets :big-endian nil))

(defun ed25519-encode-point (p)
  "Encode a point on ed25519 curve as a byte array."
  (let ((x (car p))
        (y (cdr p)))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) (ldb (byte 1 0) x))
    (ed25519-encode-int y)))

(defun ed25519-decode-point (octets)
  "Decode a byte array to a point on ed25519 curve."
  (let* ((y (ed25519-decode-int octets))
         (b (ldb (byte 1 (- +ed25519-bits+ 1)) y)))
    (setf (ldb (byte 1 (- +ed25519-bits+ 1)) y) 0)
    (let ((x (ed25519-recover-x y)))
      (when (/= (ldb (byte 1 0) x) b)
        (setf x (- +ed25519-q+ x)))
      (let ((p (cons x y)))
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
    (equal res1 res2)))

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
