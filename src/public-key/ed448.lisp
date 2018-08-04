;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; ed448.lisp -- implementation of the ed448 signature algorithm

(in-package :crypto)


;;; class definitions

(defclass ed448-public-key ()
  ((y :initarg :y :reader ed448-key-y :type (simple-array (unsigned-byte 8) (*)))))

(defclass ed448-private-key ()
  ((x :initarg :x :reader ed448-key-x :type (simple-array (unsigned-byte 8) (*)))
   (y :initarg :y :reader ed448-key-y :type (simple-array (unsigned-byte 8) (*)))))

;; Internally, a point (x, y) is represented using the projective coordinates
;; (X, Y, Z), with x = X / Z and y = Y / Z.
(deftype ed448-point () '(vector integer 3))


;;; constant and function definitions

(defconstant +ed448-bits+ 456)
(defconstant +ed448-q+ 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439)
(defconstant +ed448-l+ 181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779)
(defconstant +ed448-d+ -39081)

(declaim (type ed448-point +ed448-b+))
(defconst +ed448-b+
  (vector 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710
          298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
          1))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun ed448-dom (x y)
    (declare (type (unsigned-byte 8) x)
             (type (simple-array (unsigned-byte 8) (*)) y)
             (optimize (speed 3) (safety 0) (space 0) (debug 0)))
    (when (> (length y) 255)
      (error 'ironclad-error
             :format-control "The Y array is to big."))
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (map 'vector #'char-code "SigEd448")
                 (vector x)
                 (vector (length y))
                 y)))
;; Ed448 (x = 0), no context (y = #())
(defconst +ed448-dom+ (ed448-dom 0 (make-array 0 :element-type '(unsigned-byte 8))))

(declaim (inline ed448-inv))
(defun ed448-inv (x)
  (expt-mod x (- +ed448-q+ 2) +ed448-q+))

(defun ed448-recover-x (y)
  "Recover the X coordinate of a point on ed448 curve from the Y coordinate."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer y))
  (let* ((u (mod (1- (* y y)) +ed448-q+))
         (v (mod (1- (* +ed448-d+ (1+ u))) +ed448-q+))
         (uv (mod (* u v) +ed448-q+))
         (u3v (mod (* u u uv) +ed448-q+))
         (u5v3 (mod (* u3v uv uv) +ed448-q+))
         (x (mod (* u3v (expt-mod u5v3 (/ (- +ed448-q+ 3) 4) +ed448-q+)) +ed448-q+)))
    (declare (type integer u v uv u3v u5v3 x))
    (unless (evenp x)
      (setf x (- +ed448-q+ x)))
    x))

(defun ed448-edwards-add (p q)
  "Point addition on ed448 curve."
  (declare (type ed448-point p q)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x1 (aref p 0))
         (y1 (aref p 1))
         (z1 (aref p 2))
         (x2 (aref q 0))
         (y2 (aref q 1))
         (z2 (aref q 2))
         (a (mod (* z1 z2) +ed448-q+))
         (b (mod (* a a) +ed448-q+))
         (c (mod (* x1 x2) +ed448-q+))
         (d (mod (* y1 y2) +ed448-q+))
         (k (mod (* c d) +ed448-q+))
         (e (mod (* +ed448-d+ k) +ed448-q+))
         (f (mod (- b e) +ed448-q+))
         (g (mod (+ b e) +ed448-q+))
         (h (mod (* (+ x1 y1) (+ x2 y2)) +ed448-q+))
         (i (mod (* a f) +ed448-q+))
         (j (mod (* a g) +ed448-q+))
         (x3 (mod (* i (- h c d)) +ed448-q+))
         (y3 (mod (* j (- d c)) +ed448-q+))
         (z3 (mod (* f g) +ed448-q+)))
    (declare (type integer x1 y1 z1 x2 y2 z2 a b c d e f g h i j k x3 y3 z3))
    (vector x3 y3 z3)))

(defun ed448-edwards-double (p)
  "Point doubling on ed448 curve."
  (declare (type ed448-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x1 (aref p 0))
         (y1 (aref p 1))
         (z1 (aref p 2))
         (a (mod (+ x1 y1) +ed448-q+))
         (b (mod (* a a) +ed448-q+))
         (c (mod (* x1 x1) +ed448-q+))
         (d (mod (* y1 y1) +ed448-q+))
         (e (mod (+ c d) +ed448-q+))
         (f (mod (* z1 z1) +ed448-q+))
         (g (mod (- e (* 2 f)) +ed448-q+))
         (x2 (mod (* (- b e) g) +ed448-q+))
         (y2 (mod (* (- c d) e) +ed448-q+))
         (z2 (mod (* e g) +ed448-q+)))
    (declare (type integer x1 y1 z1 x2 y2 z2 a b c d e f g x2 y2 z2))
    (vector x2 y2 z2)))

(defun ed448-scalar-mult (p e)
  "Point multiplication on ed448 curve using the Montgomery ladder."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type ed448-point p)
           (type integer e))
  (do ((r0 (vector 0 1 1))
       (r1 p)
       (i 447 (1- i)))
      ((minusp i) r0)
    (declare (type ed448-point r0 r1)
             (type fixnum i))
    (if (logbitp i e)
        (setf r0 (ed448-edwards-add r0 r1)
              r1 (ed448-edwards-double r1))
        (setf r1 (ed448-edwards-add r0 r1)
              r0 (ed448-edwards-double r0)))))

(defun ed448-on-curve-p (p)
  "Check if the point P is on ed448 curve."
  (declare (type ed448-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((x (aref p 0))
         (y (aref p 1))
         (z (aref p 2))
         (xx (mod (* x x) +ed448-q+))
         (yy (mod (* y y) +ed448-q+))
         (zz (mod (* z z) +ed448-q+))
         (zzzz (mod (* zz zz) +ed448-q+))
         (a (mod (* zz (+ yy xx)) +ed448-q+))
         (b (mod (+ zzzz (* +ed448-d+ xx yy)) +ed448-q+)))
    (declare (type integer x y z xx yy zz zzzz a b))
    (zerop (mod (- a b) +ed448-q+))))

(defun ed448-point-equal (p q)
  "Check whether P and Q represent the same point."
  (declare (type ed448-point p q)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((x1 (aref p 0))
        (y1 (aref p 1))
        (z1 (aref p 2))
        (x2 (aref q 0))
        (y2 (aref q 1))
        (z2 (aref q 2)))
    (declare (type integer x1 y1 z1 x2 y2 z2))
    (and (zerop (mod (- (* x1 z2) (* x2 z1)) +ed448-q+))
         (zerop (mod (- (* y1 z2) (* y2 z1)) +ed448-q+)))))

(defun ed448-encode-int (y)
  "Encode an integer as a byte array (little-endian)."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (integer-to-octets y :n-bits +ed448-bits+ :big-endian nil))

(defun ed448-decode-int (octets)
  "Decode a byte array to an integer (little-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (octets-to-integer octets :big-endian nil))

(defun ed448-encode-point (p)
  "Encode a point on ed448 curve as a byte array."
  (declare (type ed448-point p)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((z (aref p 2))
         (invz (ed448-inv z))
         (x (mod (* (aref p 0) invz) +ed448-q+))
         (y (mod (* (aref p 1) invz) +ed448-q+)))
    (setf (ldb (byte 1 (- +ed448-bits+ 1)) y) (ldb (byte 1 0) x))
    (ed448-encode-int y)))

(defun ed448-decode-point (octets)
  "Decode a byte array to a point on ed448 curve."
  (declare (type (simple-array (unsigned-byte 8) (*)) octets)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let* ((y (ed448-decode-int octets))
         (b (ldb (byte 1 (- +ed448-bits+ 1)) y)))
    (setf (ldb (byte 1 (- +ed448-bits+ 1)) y) 0)
    (let ((x (ed448-recover-x y)))
      (unless (= (ldb (byte 1 0) x) b)
        (setf x (- +ed448-q+ x)))
      (let ((p (vector x y 1)))
        (unless (ed448-on-curve-p p)
          (error 'invalid-curve-point :kind 'ed448))
        p))))

(defun ed448-hash (&rest messages)
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((digest (make-digest :shake256 :output-length 114)))
    (dolist (m messages)
      (update-digest digest m))
    (produce-digest digest)))

(defun ed448-public-key (sk)
  "Compute the public key associated to the private key SK."
  (let ((h (ed448-hash sk)))
    (setf h (subseq h 0 (ceiling +ed448-bits+ 8)))
    (setf (ldb (byte 2 0) (elt h 0)) 0)
    (setf (ldb (byte 1 7) (elt h (- (ceiling +ed448-bits+ 8) 2))) 1)
    (setf (elt h (- (ceiling +ed448-bits+ 8) 1)) 0)
    (let ((a (ed448-decode-int h)))
      (ed448-encode-point (ed448-scalar-mult +ed448-b+ a)))))

(defmethod make-signature ((kind (eql :ed448)) &key r s &allow-other-keys)
  (unless r
    (error 'missing-signature-parameter
           :kind 'ed448
           :parameter 'r
           :description "first signature element"))
  (unless s
    (error 'missing-signature-parameter
           :kind 'ed448
           :parameter 's
           :description "second signature element"))
  (concatenate '(simple-array (unsigned-byte 8) (*)) r s))

(defmethod destructure-signature ((kind (eql :ed448)) signature)
  (let ((length (length signature)))
    (if (/= length (/ +ed448-bits+ 4))
        (error 'invalid-signature-length :kind 'ed448)
        (let* ((middle (/ length 2))
               (r (subseq signature 0 middle))
               (s (subseq signature middle)))
          (list :r r :s s)))))

(defun ed448-sign (m sk pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) m sk pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (let ((h (ed448-hash sk)))
    (setf (ldb (byte 2 0) (elt h 0)) 0)
    (setf (ldb (byte 1 7) (elt h (- (ceiling +ed448-bits+ 8) 2))) 1)
    (setf (elt h (- (ceiling +ed448-bits+ 8) 1)) 0)
    (let* ((a (ed448-decode-int (subseq h 0 (ceiling +ed448-bits+ 8))))
           (rh (ed448-hash +ed448-dom+ (subseq h (ceiling +ed448-bits+ 8) (ceiling +ed448-bits+ 4)) m))
           (ri (mod (ed448-decode-int rh) +ed448-l+))
           (r (ed448-scalar-mult +ed448-b+ ri))
           (rp (ed448-encode-point r))
           (k (mod (ed448-decode-int (ed448-hash +ed448-dom+ rp pk m)) +ed448-l+))
           (s (mod (+ (* k a) ri) +ed448-l+)))
      (make-signature :ed448 :r rp :s (ed448-encode-int s)))))

(defun ed448-verify (s m pk)
  (declare (type (simple-array (unsigned-byte 8) (*)) s m pk)
           (optimize (speed 3) (safety 0) (space 0) (debug 0)))
  (unless (= (length s) (ceiling +ed448-bits+ 4))
    (error 'invalid-signature-length :kind 'ed448))
  (unless (= (length pk) (ceiling +ed448-bits+ 8))
    (error 'invalid-public-key-length :kind 'ed448))
  (let* ((signature-elements (destructure-signature :ed448 s))
         (r (getf signature-elements :r))
         (rp (ed448-decode-point r))
         (s (ed448-decode-int (getf signature-elements :s)))
         (a (ed448-decode-point pk))
         (h (mod (ed448-decode-int (ed448-hash +ed448-dom+ r pk m)) +ed448-l+))
         (res1 (ed448-scalar-mult +ed448-b+ s))
         (res2 (ed448-edwards-add rp (ed448-scalar-mult a h))))
    (declare (type (simple-array (unsigned-byte 8) (*)) r)
             (type integer s h)
             (type ed448-point rp a res1 res2))
    (and (< s +ed448-l+)
         (ed448-point-equal res1 res2))))

(defmethod make-public-key ((kind (eql :ed448)) &key y &allow-other-keys)
  (unless y
    (error 'missing-key-parameter
           :kind 'ed448
           :parameter 'y
           :description "public key"))
  (make-instance 'ed448-public-key :y y))

(defmethod destructure-public-key ((public-key ed448-public-key))
  (list :y (ed448-key-y public-key)))

(defmethod make-private-key ((kind (eql :ed448)) &key x y &allow-other-keys)
  (unless x
    (error 'missing-key-parameter
           :kind 'ed448
           :parameter 'x
           :description "private key"))
  (make-instance 'ed448-private-key :x x :y (or y (ed448-public-key x))))

(defmethod destructure-private-key ((private-key ed448-private-key))
  (list :x (ed448-key-x private-key)
        :y (ed448-key-y private-key)))

(defmethod sign-message ((key ed448-private-key) message &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (sk (ed448-key-x key))
        (pk (ed448-key-y key)))
    (ed448-sign (subseq message start end) sk pk)))

(defmethod verify-signature ((key ed448-public-key) message signature &key (start 0) end &allow-other-keys)
  (let ((end (or end (length message)))
        (pk (ed448-key-y key)))
    (ed448-verify signature (subseq message start end) pk)))

(defmethod generate-key-pair ((kind (eql :ed448)) &key &allow-other-keys)
  (let* ((sk (random-data (ceiling +ed448-bits+ 8)))
         (pk (ed448-public-key sk)))
    (values (make-private-key :ed448 :x sk :y pk)
            (make-public-key :ed448 :y pk))))
