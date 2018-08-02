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

(defgeneric destructure-public-key (public-key)
  (:documentation "Return a plist containing the elements of a PUBLIC-KEY."))

(defgeneric make-private-key (kind &key &allow-other-keys)
  (:documentation "Return a private key of KIND, initialized according to
the specified keyword arguments."))

(defgeneric destructure-private-key (private-key)
  (:documentation "Return a plist containing the elements of a PRIVATE-KEY."))

(defgeneric generate-key-pair (kind &key num-bits &allow-other-keys)
  (:documentation "Generate a new key pair. The first returned
value is the secret key, the second value is the public key. If KIND
is :RSA or :DSA, NUM-BITS must be specified. If /kind/ is :ELGAMAL,
NUM-BITS must be specified unless COMPATIBLE-WITH-KEY is specified."))

(defgeneric make-signature (kind &key &allow-other-keys)
  (:documentation "Build the octet vector representing a signature
from its elements."))

(defgeneric destructure-signature (kind signature)
  (:documentation "Return a plist containing the elements of a SIGNATURE."))

(defgeneric sign-message (key message &key start end &allow-other-keys)
  (:documentation "Produce a key-specific signature of MESSAGE; MESSAGE is a
(VECTOR (UNSIGNED-BYTE 8)).  START and END bound the extent of the
message."))

(defgeneric verify-signature (key message signature &key start end &allow-other-keys)
  (:documentation "Verify that SIGNATURE is the signature of MESSAGE using
KEY.  START and END bound the extent of the message."))

(defgeneric make-message (kind &key &allow-other-keys)
  (:documentation "Build the octet vector representing a message
from its elements."))

(defgeneric destructure-message (kind message)
  (:documentation "Return a plist containing the elements of
an encrypted MESSAGE."))

(defgeneric encrypt-message (cipher-or-key message &key start end &allow-other-keys)
  (:documentation "Encrypt a MESSAGE with a CIPHER or a public KEY. START and
END bound the extent of the message. Returns a fresh octet vector."))

(defgeneric decrypt-message (cipher-or-key message &key start end n-bits &allow-other-keys)
  (:documentation "Decrypt a MESSAGE with a CIPHER or a private KEY. START and
END bound the extent of the message. Returns a fresh octet vector. N-BITS can be
used to indicate the expected size of the decrypted message."))

(defgeneric diffie-hellman (private-key public-key)
  (:documentation "Compute a shared secret using Alice's PRIVATE-KEY and Bob's PUBLIC-KEY"))


;;; converting from integers to octet vectors

(defun octets-to-integer (octet-vec &key (start 0) end (big-endian t) n-bits)
  (declare (type (simple-array (unsigned-byte 8) (*)) octet-vec)
           (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let ((end (or end (length octet-vec))))
    (multiple-value-bind (n-bits n-bytes)
        (let ((size (- end start)))
          (if n-bits
              (values n-bits (min (ceiling n-bits 8) size))
              (values (* 8 size) size)))
      (let ((sum (if big-endian
                     (loop with sum = 0
                           for i from (- end n-bytes) below end
                           do (setf sum (+ (ash sum 8) (aref octet-vec i)))
                           finally (return sum))
                     (loop for i from start below (+ start n-bytes)
                           for j from 0 by 8
                           sum (ash (aref octet-vec i) j)))))
        (ldb (byte n-bits 0) sum)))))

(defun integer-to-octets (bignum &key n-bits (big-endian t))
  (declare (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let* ((n-bits (or n-bits (integer-length bignum)))
         (bignum (ldb (byte n-bits 0) bignum))
         (n-bytes (ceiling n-bits 8))
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
