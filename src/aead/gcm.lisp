;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; gcm.lisp -- Galois counter mode

(in-package :crypto)


(defclass gcm (aead-mode)
  ((cipher :accessor gcm-cipher
           :initform nil)
   (mac :accessor gcm-mac
        :initform nil)
   (buffer :accessor gcm-buffer
           :initform (make-array 16 :element-type '(unsigned-byte 8))
           :type (simple-array (unsigned-byte 8) (16)))
   (buffer-length :accessor gcm-buffer-length
                  :initform 0
                  :type (integer 0 16))))

(defmethod shared-initialize :after ((mode gcm) slot-names &rest initargs &key key cipher-name initialization-vector &allow-other-keys)
  (declare (ignore slot-names initargs)
           (type simple-octet-vector key initialization-vector))
  (let* ((mac (if (or (null (gcm-mac mode)) cipher-name)
                  (make-mac :gmac key cipher-name initialization-vector)
                  (reinitialize-instance (gcm-mac mode)
                                         :key key
                                         :initialization-vector initialization-vector)))
         (iv (concatenate 'simple-octet-vector initialization-vector #(0 0 0 2)))
         (cipher (if (or (null (gcm-cipher mode)) cipher-name)
                     (make-cipher cipher-name
                                  :key key
                                  :mode :ctr
                                  :initialization-vector iv)
                     (reinitialize-instance (gcm-cipher mode)
                                            :key key
                                            :mode :ctr
                                            :initialization-vector iv))))
    (setf (gcm-mac mode) mac
          (gcm-cipher mode) cipher
          (gcm-buffer-length mode) 0))
  mode)

(defmethod process-associated-data ((mode gcm) data &key (start 0) end)
  (if (encryption-started-p mode)
      (error 'ironclad-error :format-control "All associated data must be processed before the encryption begins.")
      (update-mac (gcm-mac mode) data :start start :end (or end (length data)))))

(defmethod produce-tag ((mode gcm) &key tag (tag-start 0))
  (let* ((encrypted-data-length (encrypted-data-length mode))
         (mac (gcm-mac mode))
         (mac-digest (gmac-digest mac encrypted-data-length))
         (digest-size (length mac-digest)))
    (etypecase tag
      (simple-octet-vector
       (if (<= digest-size (- (length tag) tag-start))
           (replace tag mac-digest :start1 tag-start)
           (error 'insufficient-buffer-space
                  :buffer tag
                  :start tag-start
                  :length digest-size)))
      (null
       mac-digest))))

(defmethod encrypt ((mode gcm) plaintext ciphertext &key (plaintext-start 0) plaintext-end (ciphertext-start 0) handle-final-block)
  (declare (ignore handle-final-block))
  (setf (encryption-started-p mode) t)
  (multiple-value-bind (consumed-bytes produced-bytes)
      (encrypt (gcm-cipher mode) plaintext ciphertext
               :plaintext-start plaintext-start :plaintext-end plaintext-end
               :ciphertext-start ciphertext-start)
    (update-mac (gcm-mac mode) ciphertext
                :start ciphertext-start :end (+ ciphertext-start produced-bytes))
    (values consumed-bytes produced-bytes)))

(defmethod decrypt ((mode gcm) ciphertext plaintext &key (ciphertext-start 0) ciphertext-end (plaintext-start 0) handle-final-block)
  (setf (encryption-started-p mode) t)
  (let ((ciphertext-end (or ciphertext-end (+ ciphertext-start (length ciphertext))))
        (cipher (gcm-cipher mode))
        (mac (gcm-mac mode)))
    (update-mac mac ciphertext
                :start ciphertext-start :end ciphertext-end)
    (multiple-value-bind (consumed-bytes produced-bytes)
        (decrypt cipher ciphertext plaintext
                 :ciphertext-start ciphertext-start :ciphertext-end ciphertext-end
                 :plaintext-start plaintext-start)
      (when (and handle-final-block (tag mode))
        (let ((correct-tag (tag mode))
              (tag (produce-tag mac)))
          (unless (constant-time-equal tag correct-tag)
            (error 'bad-authentication-tag))))
      (values consumed-bytes produced-bytes))))

(defmethod encrypt-message ((mode gcm) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- end start))
         (encrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (encrypt mode message encrypted-message
             :plaintext-start start :plaintext-end end)
    encrypted-message))

(defmethod decrypt-message ((mode gcm) message &key (start 0) end associated-data (associated-data-start 0) associated-data-end &allow-other-keys)
  (let* ((length (- end start))
         (decrypted-message (make-array length :element-type '(unsigned-byte 8))))
    (when associated-data
      (process-associated-data mode associated-data
                               :start associated-data-start :end associated-data-end))
    (decrypt mode message decrypted-message
             :plaintext-start start :plaintext-end end)
    decrypted-message))

(defaead gcm)
