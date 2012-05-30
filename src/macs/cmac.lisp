;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;; cmac.lisp -- The CMAC algorithm from NIST 800-38B.

(in-package :crypto)

(defclass cmac ()
  ((cipher :reader cmac-cipher :initarg :cipher)
   (subkey1 :reader cmac-subkey1 :initarg :subkey1
            :type (simple-array (unsigned-byte 8) (*)))
   (subkey2 :reader cmac-subkey2 :initarg :subkey2
            :type (simple-array (unsigned-byte 8) (*)))
   (buffer :reader cmac-buffer :initarg :buffer
           :type (simple-array (unsigned-byte 8) (*)))
   (buffer-index :accessor cmac-buffer-index :initform 0 :type index)))

(defun make-cmac (key cipher-name)
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (let* ((cipher (make-cipher cipher-name :key key :mode :ecb))
         (block-length (block-length cipher-name))
         (L (make-array block-length :element-type '(unsigned-byte 8)
                        :initial-element 0)))
    (encrypt-in-place cipher L)
    (flet ((gen-subkey (b)
             (let* ((n-bits (* block-length 8))
                    (k (integer-to-octets
                        (ldb (byte n-bits 0) (ash (octets-to-integer b) 1))
                        :n-bits n-bits)))
               (when (logbitp 7 (aref b 0))
                 (setf (aref k (1- block-length))
                       (logxor (ecase block-length
                                 (16 #x87)
                                 (8 #x1b))
                               (aref k (1- block-length)))))
               k)))
      (let ((L.u (gen-subkey L)))
        (make-instance 'cmac
                       :cipher cipher
                       :subkey1 L.u
                       :subkey2 (gen-subkey L.u)
                       :buffer (make-array block-length
                                           :element-type '(unsigned-byte 8)
                                           :initial-element 0))))))

(defun update-cmac (cmac sequence
                    &key (start 0) end)
  (declare (type (simple-array (unsigned-byte 8) (*)) sequence))
  (declare (type index start))
  (declare (type (or index cl:null) end))
  (do ((end (or end (length sequence)))
       (buffer (cmac-buffer cmac))
       (length (length (cmac-buffer cmac)))
       (i start (1+ i)))
      ((>= i end) cmac)
    (declare (type (simple-array (unsigned-byte 8) (*)) buffer))
    (when (= length (cmac-buffer-index cmac))
      (setf (cmac-buffer-index cmac) 0)
      (encrypt-in-place (cmac-cipher cmac) buffer))
    (setf (aref buffer (cmac-buffer-index cmac))
          (logxor (aref buffer (cmac-buffer-index cmac)) (aref sequence i)))
    (incf (cmac-buffer-index cmac))))

(defun cmac-digest (cmac)
  (let* ((block-length (length (cmac-buffer cmac)))
         (x (copy-seq (cmac-buffer cmac)))
         (L (cond
              ((= block-length (cmac-buffer-index cmac))
               (cmac-subkey1 cmac))
              (t
               (setf (aref x (cmac-buffer-index cmac))
                     (logxor (aref x (cmac-buffer-index cmac)) #x80))
               (cmac-subkey2 cmac)))))
    (xor-block block-length L x 0 x 0)
    (encrypt-in-place (cmac-cipher cmac) x)
    x))
