;;;; public-key.lisp -- implementation of common public key components

(in-package :crypto)


;;; generic definitions

(defgeneric make-public-key (kind &key &allow-other-keys)
  (:documentation "Return a public key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric make-private-key (kind &key &allow-other-keys)
  (:documentation "Return a private key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric sign-message (key message &key start end)
  (:documentation "Produce a key-specific signature of MESSAGE; MESSAGE is a
(VECTOR (UNSIGNED-BYTE 8)).  START and END bound the extent of the
message."))

(defgeneric verify-signature (key message signature &key start end)
  (:documentation "Verify that SIGNATURE is the signature of MESSAGE using
KEY.  START and END bound the extent of the message."))

(defgeneric encrypt-message (key message &key start end)
  (:documentation "Encrypt MESSAGE with KEY.  START and END bound the extent
of the message.  Returns a fresh octet vector."))

(defgeneric decrypt-message (key message &key start end)
  (:documentation "Decrypt MESSAGE with KEY.  START and END bound the extent
of the message.  Returns a fresh octet vector."))


;;; converting from integers to octet vectors

(defun octets-to-integer (octet-vec &key (start 0) end (big-endian t) n-bits)
  (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
  (let ((end (or end (length octet-vec))))
    (multiple-value-bind (complete-bytes extra-bits)
        (if n-bits
            (truncate n-bits 8)
            (values (- end start) 0))
      (declare (ignorable complete-bytes extra-bits))
      (if big-endian
          (do ((j start (1+ j))
               (sum 0))
              ((>= j end) sum)
            (setf sum (+ (aref octet-vec j) (ash sum 8))))
          (loop for i from (- end start 1) downto 0
                for j from (1- end) downto start
                sum (ash (aref octet-vec j) (* i 8)))))))

(defun integer-to-octets (bignum &key (n-bits (integer-length bignum))
                                (big-endian t))
  (let ((octet-vec (make-array (ceiling n-bits 8)
                               :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
    (if big-endian
        (loop for i from (1- (ceiling n-bits 8)) downto 0
              for index from 0
              do (setf (aref octet-vec index) (ldb (byte 8 (* i 8)) bignum))
              finally (return octet-vec))
        (loop for i from 0 upto (floor n-bits 8)
              for byte from 0 by 8
              do (setf (aref octet-vec i) (ldb (byte 8 byte) bignum))
              finally (return octet-vec)))))

(defun maybe-integerize (thing)
  (etypecase thing
    (integer thing)
    ((simple-array (unsigned-byte 8) (*)) (octets-to-integer thing))))


;;; modular arithmetic utilities

(defun shift-off-zeros (n)
  (do ((zeros 0 (1+ zeros)))
      ((logbitp zeros n) (values (ash n (- zeros)) zeros))))

(defun frobnicate (z a b x y)
  (multiple-value-bind (g bits) (shift-off-zeros z)
    (dotimes (i bits (values g a b))
      (when (or (oddp a) (oddp b))
        (incf a y)
        (decf b x))
      (setf a (ash a -1) b (ash b -1)))))

(defun modular-inverse (n modulus)
  (declare (type (integer 1 *) modulus))
  (declare (type (integer 0 *) n))
  (when (or (zerop n) (and (evenp n) (evenp modulus)))
    (return-from modular-inverse 0))
  (let ((x modulus)
        (y n)
        (u modulus)
        (v n)
        (a 1) (b 0) (c 0) (d 1))
    (loop until (zerop u)
      do (progn
           (multiple-value-setq (u a b) (frobnicate u a b x y))
           (multiple-value-setq (v c d) (frobnicate v c d x y))
           (cond
             ((>= u v)
              (decf u v) (decf a c) (decf b d))
             (t
              (decf v u) (decf c a) (decf d b))))
      finally (progn
                (unless (= v 1)
                  (return 0))
                (loop while (minusp d)
                  do (incf d modulus))
                (loop while (>= d modulus)
                  do (decf d modulus))
                (return d)))))

;;; direct from CLiki
(defun expt-mod (n exponent modulus)
  "As (mod (expt n exponent) modulus), but more efficient."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0)))  
  (loop with result = 1
        for i of-type fixnum from 0 below (integer-length exponent)
        for sqr = n then (mod (* sqr sqr) modulus)
        when (logbitp i exponent) do
        (setf result (mod (* result sqr) modulus))
        finally (return result)))
