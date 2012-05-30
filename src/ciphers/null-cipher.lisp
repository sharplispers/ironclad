;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; null-cipher.lisp -- the do-nothing cipher

;;; It's not very secure, but it does come in handy to serve as a dummy
;;; cipher in security protocols before ciphers and keys have been
;;; established.

(cl:in-package :crypto)

(eval-when (:compile-toplevel :load-toplevel :execute)
(defconstant +null-block-length+ 8)
)

(defclass null (cipher 8-byte-block-mixin)
  ((key :accessor null-key :type simple-octet-vector)
   (key-index :accessor null-key-index :initform 0 :type fixnum)))

(defun null-crypt-block (context in in-start out out-start)
  (declare (type simple-octet-vector in out))
  (let* ((key (null-key context))
         (key-index (null-key-index context))
         (key-length (length key)))
    (declare (type simple-octet-vector key))
    (cond
      ((= key-length 1)
       (let ((byte (aref key 0)))
         ;; Ignore the case where we just crypt in place.
         (unless (and (zerop byte)
                      (eq in out)
                      (= in-start out-start))
           (dotimes (i +null-block-length+)
             (setf (aref out (+ out-start i))
                   (logxor byte (aref in (+ in-start i))))))))
      (t
       (dotimes (i +null-block-length+)
         (setf (aref out (+ out-start i))
               (logxor (aref key key-index) (aref in (+ in-start i))))
         (incf key-index)
         (when (>= key-index key-length)
           (setf key-index 0)))
       (setf (null-key-index context) key-index)))))

(define-block-encryptor null #.+null-block-length+
  (null-crypt-block context plaintext plaintext-start ciphertext ciphertext-start))

(define-block-decryptor null #.+null-block-length+
  (null-crypt-block context ciphertext ciphertext-start plaintext plaintext-start))

(defmethod schedule-key ((cipher null) key)
  ;; Optimize the probable common case of a key with bytes all the same.
  (let ((short-key (remove-duplicates key)))
    (if (= (length short-key) 1)
        (setf (null-key cipher) short-key)
        (setf (null-key cipher) key))
    cipher))

(defcipher null
  (:encrypt-function null-encrypt-block)
  (:decrypt-function null-decrypt-block)
  (:block-length #.+null-block-length+)
  (:key-length (:variable 1 256 1)))
