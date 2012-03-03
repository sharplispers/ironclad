;;;; generator.lisp -- Fortuna PRNG generator

(in-package :crypto)



;; FIXME: should this be moved into digests?
(defun shad-256 (octets)
  (digest-sequence :sha256 (digest-sequence :sha256 octets)))

(defclass generator ()
  ((key
    :initform (make-array 16
                          :element-type '(unsigned-byte 8)
                          :initial-element 0))
   (counter :initform 0)
   (cipher-name :initform :aes :initarg :cipher-name)
   (cipher :initform nil))
  (:documentation "Fortuna generator.  KEY is the key used to initialise
  CIPHER as an instance of CIPHER-NAME (which must be a valid NAME
  recognised by MAKE-CIPHER)."))

(defun reseed (generator seed)
  (with-slots (key counter cipher cipher-name) generator
    (setf key
          (shad-256
           (concatenate '(vector (unsigned-byte 8)) key seed)))
    (incf counter)
    (setf cipher
          (make-cipher cipher-name :key key :mode :ecb))))

(defun generate-blocks (generator num-blocks)
  "Internal use only"
  (with-slots (cipher key counter) generator
    (assert (and cipher
                 (plusp counter)))
    (loop for i from 1 to num-blocks
       collect (let ((block (integer-to-octets counter
                                               :n-bits 128
                                               :big-endian nil)))
                      (encrypt-in-place cipher block)
                      block)
       into blocks
       do (incf counter)
       finally (return (apply #'concatenate 'simple-octet-vector blocks)))))

(defun pseudo-random-data (generator num-bytes)
  (assert (< 0 num-bytes (expt 2 20)))
  (let* ((output (subseq (generate-blocks generator (ceiling num-bytes 16))
                         0
                         num-bytes))
         (key (generate-blocks generator 2)))
    (setf (slot-value generator 'key) key)
    output))
