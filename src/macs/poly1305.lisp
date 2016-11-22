;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; poly1305.lisp -- RFC 7539 poly1305 message authentication code


(in-package :crypto)


(defconstant +poly1305-p+ 1361129467683753853853498429727072845819) ; 2^130 - 5
(defconstant +poly1305-hibit+ 340282366920938463463374607431768211456) ; 2^128


(defclass poly1305 ()
  ((accumulator :accessor poly1305-accumulator
                :type integer)
   (r :accessor poly1305-r
      :type (unsigned-byte 128))
   (s :accessor poly1305-s
      :type (unsigned-byte 128))
   (buffer :accessor poly1305-buffer
           :type (simple-array (unsigned-byte 8) (16)))
   (buffer-length :accessor poly1305-buffer-length
                  :type (integer 0 16))))

(defun poly1305-octets->uint128le (data start)
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type integer start)
           (optimize (speed 3) (space 0) (safety 0) (debug 0)))
  (logior (ub64ref/le data start)
          (ash (ub64ref/le data (+ start 8)) 64)))

(defun poly1305-uint128le->octets (n)
  (declare (type integer n))
  (do ((data (make-array 16 :element-type '(unsigned-byte 8)))
       (i 0 (1+ i)))
      ((= i 16) data)
    (declare (type (simple-array (unsigned-byte 8) (*)) data)
             (type (integer 0 16) i))
    (setf (aref data i) (ldb (byte 8 0) n)
          n (ash n -8))))

(defun poly1305-clamp (r)
  (declare (type (unsigned-byte 128) r))
  (logand r #x0ffffffc0ffffffc0ffffffc0fffffff))

(defun make-poly1305 (key)
  (declare (type (simple-array (unsigned-byte 8) (32)) key))
  (unless (= (length key) 32)
    (error "Key size must be 32 bytes."))
  (make-instance 'poly1305 :key key))

(defmethod shared-initialize ((mac poly1305) slot-names
                              &rest initargs
                              &key key &allow-other-keys)
  (declare (ignore slot-names initargs)
           (type (simple-array (unsigned-byte 8) (32)) key))
  (let ((r (poly1305-clamp (poly1305-octets->uint128le key 0)))
        (s (poly1305-octets->uint128le key 16)))
    (setf (poly1305-r mac) r
          (poly1305-s mac) s
          (poly1305-accumulator mac) 0
          (poly1305-buffer mac) (make-array 16 :element-type '(unsigned-byte 8))
          (poly1305-buffer-length mac) 0)
    mac))

(defun update-poly1305 (mac data &key (start 0) (end (length data)))
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type integer start end)
           (optimize (speed 3) (space 0) (safety 1) (debug 0)))
  (let ((buffer (poly1305-buffer mac))
        (buffer-length (poly1305-buffer-length mac))
        (accumulator (poly1305-accumulator mac))
        (r (poly1305-r mac))
        (remaining (- end start)))
    (declare (type (simple-array (unsigned-byte 8) (16)) buffer)
             (type (integer 0 16) buffer-length)
             (type (unsigned-byte 128) r)
             (type integer accumulator remaining))

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
      (let ((n (logior (poly1305-octets->uint128le buffer 0)
                       +poly1305-hibit+)))
        (declare (type integer n))
        (setf accumulator (mod (* r (+ accumulator n)) +poly1305-p+)
              buffer-length 0)))

    ;; Process the data
    (do ((n 0))
        ((< remaining 16))
      (declare (type integer n))
      (setf n (logior (poly1305-octets->uint128le data start)
                      +poly1305-hibit+)
            accumulator (mod (* r (+ accumulator n)) +poly1305-p+))
      (incf start 16)
      (decf remaining 16))

    ;; Put the remaining data in the buffer
    (when (plusp remaining)
      (replace buffer data :start1 0 :start2 start :end2 end)
      (setf buffer-length remaining))

    ;; Save the state
    (setf (poly1305-accumulator mac) accumulator
          (poly1305-buffer-length mac) buffer-length)
    (values)))

(defun poly1305-digest (mac)
  (let ((buffer (copy-seq (poly1305-buffer mac)))
        (buffer-length (poly1305-buffer-length mac))
        (accumulator (poly1305-accumulator mac))
        (r (poly1305-r mac))
        (s (poly1305-s mac)))
    (declare (type (simple-array (unsigned-byte 8) (16)) buffer)
             (type (integer 0 16) buffer-length)
             (type integer accumulator)
             (type (unsigned-byte 128) r s))

    ;; Process the buffer
    (when (plusp buffer-length)
      (fill buffer 0 :start buffer-length :end 16)
      (let ((n (poly1305-octets->uint128le buffer 0))
            (i (* buffer-length 8)))
        (declare (type integer n))
        (setf (ldb (byte 1 i) n) 1
              accumulator (mod (* r (+ accumulator n)) +poly1305-p+))))

    ;; Produce the tag
    (incf accumulator s)
    (poly1305-uint128le->octets accumulator)))
