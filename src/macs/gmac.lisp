;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; gmac.lisp -- GMAC message authentication code


(in-package :crypto)


(defclass gmac ()
  ((accumulator :accessor gmac-accumulator
                :initform (make-array 16 :element-type '(unsigned-byte 8))
                :type (simple-array (unsigned-byte 8) (16)))
   (table :accessor gmac-table
          :initform (make-array '(128 2 2) :element-type '(unsigned-byte 64) :initial-element 0)
          :type (simple-array (unsigned-byte 64) (128 2 2)))
   (total-length :accessor gmac-total-length
                 :initform 0
                 :type (unsigned-byte 64))
   (cipher :accessor gmac-cipher
           :initform nil)
   (iv :accessor gmac-iv
       :initform (make-array 16 :element-type '(unsigned-byte 8))
       :type (simple-array (unsigned-byte 8) (16)))
   (buffer :accessor gmac-buffer
           :initform (make-array 16 :element-type '(unsigned-byte 8))
           :type (simple-array (unsigned-byte 8) (16)))
   (buffer-length :accessor gmac-buffer-length
                  :initform 0
                  :type (integer 0 16))))

(defun make-gmac (key cipher-name initialization-vector)
  (unless (member (length key) (key-lengths cipher-name))
    (error 'invalid-mac-parameter
           :mac-name 'gmac
           :message "The key length is not compatible with the cipher"))
  (unless (= (block-length cipher-name) 16)
    (error 'invalid-mac-parameter
           :mac-name 'gmac
           :message "GMAC only supports 128-bit block ciphers"))
  (unless (= (length initialization-vector) 12)
    (error 'invalid-mac-parameter
           :mac-name 'gmac
           :message "The initialization vector length must be 12 bytes"))
  (make-instance 'gmac
                 :key key
                 :cipher-name cipher-name
                 :initialization-vector initialization-vector))

(defmethod shared-initialize :after ((mac gmac) slot-names &rest initargs &key key cipher-name initialization-vector &allow-other-keys)
  (declare (ignore slot-names initargs)
           (type (simple-array (unsigned-byte 8) (*)) key))
  (let* ((table (gmac-table mac))
         (cipher (if cipher-name
                     (make-cipher cipher-name :key key :mode :ecb)
                     (gmac-cipher mac)))
         (key (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 64) (128 2 2)) table)
             (type (simple-array (unsigned-byte 8) (16)) key)
             (dynamic-extent key))
    (setf (gmac-total-length mac) 0
          (gmac-buffer-length mac) 0)
    (fill (gmac-accumulator mac) 0)
    (when initialization-vector
      (replace (gmac-iv mac) initialization-vector))
    (setf (gmac-cipher mac) cipher)
    (encrypt-in-place cipher key)

    (setf (aref table 0 1 0) (ub64ref/be key 0)
          (aref table 0 1 1) (ub64ref/be key 8))
    (dotimes (i 127)
      (let ((c (if (logbitp 0 (aref table i 1 1)) #xe100000000000000 0)))
        (declare (type (unsigned-byte 64) c))
        (setf (aref table (1+ i) 1 1) (logior (mod64ash (aref table i 1 1) -1)
                                              (mod64ash (aref table i 1 0) 63))
              (aref table (1+ i) 1 0) (logxor (mod64ash (aref table i 1 0) -1) c))))
    mac))

(defun gmac-mul (accumulator table)
  (declare (type (simple-array (unsigned-byte 8) (16)) accumulator)
           (type (simple-array (unsigned-byte 64) (128 2 2)) table)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((x 0)
        (z0 0)
        (z1 0)
        (b 0))
    (declare (type (unsigned-byte 8) x)
             (type (unsigned-byte 64) z0 z1)
             (type bit b))
    (dotimes-unrolled (i 16)
      (setf x (aref accumulator i))
      (dotimes-unrolled (j 8)
        (setf b (logand (ash x (- j 7)) 1)
              z0 (logxor z0 (aref table (+ (* i 8) j) b 0))
              z1 (logxor z1 (aref table (+ (* i 8) j) b 1)))))
    (setf (ub64ref/be accumulator 0) z0
          (ub64ref/be accumulator 8) z1)
    (values)))

(defun update-gmac (mac data &key (start 0) (end (length data)))
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type index start end)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (let ((accumulator (gmac-accumulator mac))
        (table (gmac-table mac))
        (total-length (gmac-total-length mac))
        (buffer (gmac-buffer mac))
        (buffer-length (gmac-buffer-length mac))
        (remaining (- end start)))
    (declare (type (simple-array (unsigned-byte 8) (16)) accumulator buffer)
             (type (simple-array (unsigned-byte 64) (128 2 2)) table)
             (type (unsigned-byte 64) total-length)
             (type (integer 0 16) buffer-length)
             (type index remaining))

    ;; Fill the buffer with new data if necessary
    (when (plusp buffer-length)
      (let ((n (min remaining (- 16 buffer-length))))
        (declare (type (integer 0 16) n))
        (replace buffer data
                 :start1 buffer-length
                 :start2 start
                 :end2 (+ start n))
        (incf buffer-length n)
        (incf start n)
        (decf remaining n)))

    ;; Process the buffer
    (when (= buffer-length 16)
      (xor-block 16 accumulator buffer 0 accumulator 0)
      (gmac-mul accumulator table)
      (incf total-length 16)
      (setf buffer-length 0))

    ;; Process the data
    (loop while (> remaining 16) do
      (xor-block 16 accumulator data start accumulator 0)
      (gmac-mul accumulator table)
      (incf total-length 16)
      (incf start 16)
      (decf remaining 16))

    ;; Put the remaining data in the buffer
    (when (plusp remaining)
      (replace buffer data :start1 0 :start2 start :end2 end)
      (setf buffer-length remaining))

    ;; Save the state
    (setf (gmac-total-length mac) total-length
          (gmac-buffer-length mac) buffer-length)
    (values)))

(defun gmac-digest (mac)
  (let ((accumulator (copy-seq (gmac-accumulator mac)))
        (table (gmac-table mac))
        (total-length (gmac-total-length mac))
        (cipher (gmac-cipher mac))
        (iv (copy-seq (gmac-iv mac)))
        (buffer (copy-seq (gmac-buffer mac)))
        (buffer-length (gmac-buffer-length mac)))
    (declare (type (simple-array (unsigned-byte 8) (16)) accumulator buffer iv)
             (type (simple-array (unsigned-byte 64) (128 2 2)) table)
             (type (unsigned-byte 64) total-length)
             (type (integer 0 16) buffer-length))

    ;; Process the buffer
    (when (plusp buffer-length)
      (xor-block buffer-length accumulator buffer 0 accumulator 0)
      (gmac-mul accumulator table)
      (incf total-length buffer-length))

    ;; Padding
    (setf (ub64ref/be buffer 0) (mod64* 8 total-length)
          (ub64ref/be buffer 8) 0)
    (xor-block 16 accumulator buffer 0 accumulator 0)
    (gmac-mul accumulator table)

    ;; Produce the tag
    (fill iv 0 :start 12 :end 15)
    (setf (aref iv 15) 1)
    (encrypt-in-place cipher iv)
    (xor-block 16 accumulator iv 0 accumulator 0)
    accumulator))

(defmac gmac
        make-gmac
        update-gmac
        gmac-digest)
