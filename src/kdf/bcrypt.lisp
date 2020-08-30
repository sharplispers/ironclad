;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; bcrypt.lisp -- implementation of the bcrypt password hashing function

(in-package :crypto)


(defconst +bcrypt-initial-hash+
  (ascii-string-to-byte-array "OrpheanBeholderScryDoubt"))

(defun bcrypt-expand-key (passphrase salt p-array s-boxes)
  (declare (type (simple-array (unsigned-byte 8) (*)) passphrase salt)
           (type blowfish-p-array p-array)
           (type blowfish-s-boxes s-boxes))
  (let ((data (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 8) (8)) data))
    (mix-p-array passphrase p-array)
    (dotimes (i 9)
      (xor-block 8 data 0 salt (if (evenp i) 0 8) data 0)
      (blowfish-encrypt-block* p-array s-boxes data 0 data 0)
      (let ((index (* 2 i)))
        (setf (aref p-array index) (ub32ref/be data 0)
              (aref p-array (1+ index)) (ub32ref/be data 4))))
    (dotimes (i 4)
      (dotimes (j 128)
        (xor-block 8 data 0 salt (if (oddp j) 0 8) data 0)
        (blowfish-encrypt-block* p-array s-boxes data 0 data 0)
        (let ((index (+ (* 256 i) (* 2 j))))
          (setf (aref s-boxes index) (ub32ref/be data 0)
                (aref s-boxes (1+ index)) (ub32ref/be data 4)))))))

(defun bcrypt-eksblowfish (passphrase salt rounds)
  (declare (type (simple-array (unsigned-byte 8) (*)) passphrase salt))
  (let ((passphrase (concatenate '(simple-array (unsigned-byte 8) (*))
                                 passphrase (vector 0)))
        (p-array (copy-seq +p-array+))
        (s-boxes (concatenate '(simple-array (unsigned-byte 32) (1024))
                              +s-box-0+ +s-box-1+ +s-box-2+ +s-box-3+)))
    (declare (type (simple-array (unsigned-byte 8) (*)) passphrase)
             (type blowfish-p-array p-array)
             (type blowfish-s-boxes s-boxes))
    (bcrypt-expand-key passphrase salt p-array s-boxes)
    (dotimes (i rounds)
      (initialize-blowfish-vectors passphrase p-array s-boxes)
      (initialize-blowfish-vectors salt p-array s-boxes))
    (values p-array s-boxes)))

(defmethod derive-key ((kdf bcrypt) passphrase salt iteration-count key-length)
  (declare (type (simple-array (unsigned-byte 8) (*)) passphrase salt))
  (unless (<= (length passphrase) 72)
    (error 'ironclad-error
           :format-control "PASSPHRASE must be at most 72 bytes long."))
  (unless (= (length salt) 16)
    (error 'ironclad-error
           :format-control "SALT must be 16 bytes long."))
  (unless (and (zerop (logand iteration-count (1- iteration-count)))
               (<= (expt 2 4) iteration-count (expt 2 31)))
    (error 'ironclad-error
           :format-control "ITERATION-COUNT must be a power of 2 between 2^4 and 2^31."))
  (unless (= key-length 24)
    (error 'ironclad-error
           :format-control "KEY-LENGTH must be 24."))
  (multiple-value-bind (p-array s-boxes)
      (bcrypt-eksblowfish passphrase salt iteration-count)
    (declare (type blowfish-p-array p-array)
             (type blowfish-s-boxes s-boxes))
    (let ((hash (copy-seq +bcrypt-initial-hash+)))
      (declare (type (simple-array (unsigned-byte 8) (24)) hash))
      (dotimes (i 64 hash)
        (blowfish-encrypt-block* p-array s-boxes hash 0 hash 0)
        (blowfish-encrypt-block* p-array s-boxes hash 8 hash 8)
        (blowfish-encrypt-block* p-array s-boxes hash 16 hash 16)))))

#|
;; http://kwarc.github.io/llamapun/src/crypto/bcrypt.rs.html
;; https://github.com/patrickfav/bcrypt/wiki/Published-Test-Vectors
(let* ((kdf (crypto:make-kdf :bcrypt))
       (pass (crypto:hex-string-to-byte-array "552a55"))
       (salt (crypto:hex-string-to-byte-array "10410410410410410410410410410410"))
       (hash (crypto:derive-key kdf pass salt 32 24)))
  (write-line "\"1bb69143f9a8d304c8d23d99ab049a77a68e2ccc744206\"")
  (crypto:byte-array-to-hex-string hash))
|#
