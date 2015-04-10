;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; public-key.lisp -- implementation of common public key components

(in-package :crypto)


;;; class definitions

(defclass discrete-logarithm-group ()
  ((p :initarg :p :reader group-pval)
   (q :initarg :q :reader group-qval)
   (g :initarg :g :reader group-gval)))


;;; generic definitions

(defgeneric make-public-key (kind &key &allow-other-keys)
  (:documentation "Return a public key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric make-private-key (kind &key &allow-other-keys)
  (:documentation "Return a private key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric generate-new-key-pair (kind num-bits &key &allow-other-keys)
  (:documentation "Generate a new NUM-BITS-bit key pair. The first returned
value is the secret key, the second value is the public key."))

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
  (let* ((n-bytes (ceiling n-bits 8))
         (octet-vec (make-array n-bytes :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec))
    (if big-endian
        (loop for i from (1- n-bytes) downto 0
              for index from 0
              do (setf (aref octet-vec index) (ldb (byte 8 (* i 8)) bignum))
              finally (return octet-vec))
        (loop for i from 0 below n-bytes
              for byte from 0 by 8
              do (setf (aref octet-vec i) (ldb (byte 8 byte) bignum))
              finally (return octet-vec)))))

(defun maybe-integerize (thing)
  (etypecase thing
    (integer thing)
    ((simple-array (unsigned-byte 8) (*)) (octets-to-integer thing))))
