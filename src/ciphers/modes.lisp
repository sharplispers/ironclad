;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; modes.lisp -- using encryption modes with block ciphers

(in-package :crypto)

(defgeneric encrypted-message-length (cipher mode length
                                      &optional handle-final-block)
  (:documentation "Return the length a message of LENGTH would be if it
were to be encrypted (decrypted) with CIPHER in MODE.  HANDLE-FINAL-BLOCK
indicates whether we are encrypting up to and including the final block
 (so that short blocks may be taken into account, if applicable).

Note that this computation may involve MODE's state."))

(defgeneric mode-crypt-functions (cipher mode)
  (:documentation "Returns two functions that perform encryption and
decryption, respectively, with CIPHER in MODE.  The lambda list of each
function is (IN OUT IN-START IN-END OUT-START HANDLE-FINAL-BLOCK).
HANDLE-FINAL-BLOCK is as in ENCRYPT and DECRYPT; the remaining parameters
should be self-explanatory.  Each function, when called, returns two values:
the number of octets processed from IN and the number of octets processed
from OUT.  Note that for some cipher modes, IN and OUT may be different."))

(defclass encryption-mode ()
  ((encrypt-function :reader encrypt-function)
   (decrypt-function :reader decrypt-function)))
(defclass ecb-mode (encryption-mode) ())
(defclass stream-mode (encryption-mode) ())
(defclass inititialization-vector-mixin ()
  ((iv :reader iv :initarg :initialization-vector)
   (position :accessor iv-position :initform 0)))
(defclass cbc-mode (encryption-mode inititialization-vector-mixin) ())
(defclass ofb-mode (encryption-mode inititialization-vector-mixin) ())
(defclass cfb-mode (encryption-mode inititialization-vector-mixin) ())
(defclass cfb8-mode (encryption-mode inititialization-vector-mixin) ())
(defclass ctr-mode (encryption-mode inititialization-vector-mixin) ())

(defclass padded-cipher-mode (encryption-mode)
  ((buffer :reader buffer)
   (buffer-index :accessor buffer-index :initform 0)
   (sub-mode :reader sub-mode :initarg :sub-mode)))

(defmethod print-object ((object encryption-mode) stream)
  (print-unreadable-object (object stream :identity t)
    (format stream "~A" (class-name (class-of object)))))

(defmethod initialize-instance :after ((mode encryption-mode) &key cipher)
  (multiple-value-bind (efun dfun) (mode-crypt-functions cipher mode)
    (setf (slot-value mode 'encrypt-function) efun
          (slot-value mode 'decrypt-function) dfun)))

(defmethod initialize-instance :after ((mode padded-cipher-mode)
                                       &key buffer-length)
  (setf (slot-value mode 'buffer)
        (make-array buffer-length :element-type '(unsigned-byte 8))))

(defvar *supported-modes* (list :ecb :cbc :ofb :cfb :cfb8 :ctr))

(defun mode-supported-p (name)
  (member name *supported-modes*))

(defun list-all-modes ()
  (copy-seq *supported-modes*))

(defmethod encrypt-message (cipher msg &key (start 0) (end (length msg)))
  (let* ((length (- end start))
         (encrypted-length (encrypted-message-length cipher (mode cipher)
                                                     length t))
         (encrypted-message (make-array encrypted-length
                                        :element-type '(unsigned-byte 8))))
    (encrypt cipher msg encrypted-message
             :plaintext-start start :plaintext-end end
             :handle-final-block t)
    encrypted-message))

(defun increment-counter-block (block)
  (declare (type simple-octet-vector block))
  (let ((length (length block))
        (carry 1))
    (declare (type fixnum length)
             (type (unsigned-byte 16) carry))
    (loop for i of-type fixnum from (1- length) downto 0
          for sum of-type (unsigned-byte 16) = (+ (aref block i) carry)
          until (zerop carry) do
          (setf (aref block i) (ldb (byte 8 0) sum)
                carry (ldb (byte 1 8) sum)))
    (values)))

;;; Only really works on big-endian processors...
#+nil
(defun increment-counter-block (block)
  (let ((words (truncate (length block) sb-vm:n-word-bytes))
        (carry 1))
    (loop for i from (1- words) downto 0
          until (zerop carry) do
          (let ((word (sb-kernel:%vector-raw-bits block i)))
            (multiple-value-setq (word carry)
              (sb-bignum:%add-with-carry word 0 carry))
            (setf (sb-kernel:%vector-raw-bits block i) word)))
    (values)))

;;; This way is kind of ugly, but I don't know a better way.
(macrolet ((define-mode-function (&rest mode-definition-funs &environment env)
             (loop for fun in mode-definition-funs
                   collect (macroexpand `(,fun 128-byte-block-mixin 128) env) into forms
                   collect (macroexpand `(,fun 64-byte-block-mixin 64) env) into forms
                   collect (macroexpand `(,fun 32-byte-block-mixin 32) env) into forms
                   collect (macroexpand `(,fun 16-byte-block-mixin 16) env) into forms
                   collect (macroexpand `(,fun 8-byte-block-mixin 8) env) into forms
                   finally (return `(progn ,@forms))))
           (mode-lambda (&body body)
             `(lambda (in out in-start in-end out-start handle-final-block)
                (declare (type simple-octet-vector in out))
                (declare (type index in-start in-end out-start))
                (declare (ignorable handle-final-block))
                ,@body)))


;;; ECB mode

(macrolet ((mode-crypt (cipher-specializer block-length-expr)
             `(defmethod mode-crypt-functions ((cipher ,cipher-specializer)
                                               (mode ecb-mode))
                (flet ((ecb-crypt-function (function)
                         (declare (type function function))
                         (mode-lambda
                          (loop with offset of-type index = in-start
                                while (<= offset (- in-end ,block-length-expr))
                                do (funcall function cipher in offset out out-start)
                                   (incf offset ,block-length-expr)
                                   (incf out-start ,block-length-expr)
                                finally (return
                                          (let ((n-bytes-processed (- offset in-start)))
                                            (values n-bytes-processed n-bytes-processed)))))))
                  (values (ecb-crypt-function (encrypt-function cipher))
                          (ecb-crypt-function (decrypt-function cipher))))))
           (message-length (cipher-specializer block-length-expr)
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode ecb-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                (* (truncate length ,block-length-expr) ,block-length-expr))))
  (define-mode-function mode-crypt message-length))


;;; CBC mode

(macrolet ((mode-crypt (cipher-specializer block-length-expr)
             `(defmethod mode-crypt-functions ((cipher ,cipher-specializer)
                                               (mode cbc-mode))
                (let ((efun (encrypt-function cipher))
                      (dfun (decrypt-function cipher))
                      (iv (iv mode)))
                  (declare (type function efun dfun))
                  (declare (type (simple-octet-vector ,block-length-expr) iv))
                  (declare (inline xor-block))
                  (values
                    (mode-lambda
                     (loop with offset of-type index = in-start
                           while (<= offset (- in-end ,block-length-expr))
                           do (xor-block ,block-length-expr iv in offset
                                  out out-start)
                              (funcall efun cipher out out-start out out-start)
                              (replace iv out :start1 0 :end1 ,block-length-expr
                                       :start2 out-start)
                              (incf offset ,block-length-expr)
                              (incf out-start ,block-length-expr)
                           finally (return
                                     (let ((n-bytes-processed (- offset in-start)))
                                       (values n-bytes-processed n-bytes-processed)))))
                    (mode-lambda
                     (let ((temp-block (make-array ,block-length-expr
                                                   :element-type '(unsigned-byte 8))))
                       (declare (type (simple-octet-vector ,block-length-expr) temp-block))
                       (declare (dynamic-extent temp-block))
                       (declare (inline xor-block))
                       (loop with offset of-type index = in-start
                             while (<= offset (- in-end ,block-length-expr))
                             do (replace temp-block in :start1 0 :end1 ,block-length-expr
                                         :start2 offset)
                                (funcall dfun cipher in offset out out-start)
                                (xor-block ,block-length-expr iv out out-start
                                    out out-start)
                                (replace iv temp-block :end1 ,block-length-expr
                                         :end2 ,block-length-expr)
                                (incf offset ,block-length-expr)
                                (incf out-start ,block-length-expr)
                             finally (return
                                       (let ((n-bytes-processed (- offset in-start)))
                                         (values n-bytes-processed n-bytes-processed))))))))))
           (message-length (cipher-specializer block-length-expr)
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode cbc-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                (* (truncate length ,block-length-expr) ,block-length-expr))))
  (define-mode-function mode-crypt message-length))


;;; CFB mode

(macrolet ((mode-crypt (cipher-specializer block-length-expr)
             `(defmethod mode-crypt-functions ((cipher ,cipher-specializer)
                                               (mode cfb-mode))
                (let ((function (encrypt-function cipher))
                      (iv (iv mode))
                      (iv-position (iv-position mode)))
                  (declare (type function function))
                  (declare (type (simple-octet-vector ,block-length-expr) iv))
                  (declare (type (integer 0 (,block-length-expr)) iv-position))
                  (values
                    (mode-lambda
                     (loop for i of-type index from in-start below in-end
                           for j of-type index from out-start
                           do (when (zerop iv-position)
                                (funcall function cipher iv 0 iv 0))
                              (let ((b (logxor (aref in i) (aref iv iv-position))))
                                (setf (aref out j) b)
                                (setf (aref iv iv-position) b)
                                (setf iv-position (mod (1+ iv-position) ,block-length-expr)))
                           finally (return
                                     (let ((n-bytes-processed (- in-end in-start)))
                                       (values n-bytes-processed n-bytes-processed)))))
                    (mode-lambda
                     (loop for i of-type index from in-start below in-end
                           for j of-type index from out-start
                           do (when (zerop iv-position)
                                (funcall function cipher iv 0 iv 0))
                              (let ((b (logxor (aref in i) (aref iv iv-position))))
                                (setf (aref out j) b)
                                (setf (aref iv iv-position) (aref in i))
                                (setf iv-position (mod (1+ iv-position) ,block-length-expr)))
                           finally (return
                                     (let ((n-bytes-processed (- in-end in-start)))
                                       (values n-bytes-processed n-bytes-processed)))))))))
           (message-length (cipher-specializer block-length-expr)
             (declare (ignore block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode cfb-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function mode-crypt message-length))


;;; CFB8 mode

(macrolet ((mode-crypt (cipher-specializer block-length-expr)
           `(defmethod mode-crypt-functions ((cipher ,cipher-specializer)
                                             (mode cfb8-mode))
              (let ((function (encrypt-function cipher))
                    (iv (iv mode))
                    (encrypted-iv (nibbles:make-octet-vector ,block-length-expr)))
                (declare (type function function))
                (declare (type (simple-octet-vector ,block-length-expr) iv encrypted-iv))
                (values
                  (mode-lambda
                   (loop for i of-type index from in-start below in-end
                         for j of-type index from out-start
                         do (replace encrypted-iv iv :end1 ,block-length-expr :end2 ,block-length-expr)
                            (funcall function cipher encrypted-iv 0 encrypted-iv 0)
                            (let ((b (logxor (aref in i) (aref encrypted-iv 0))))
                              (setf (aref out j) b)
                              (replace iv iv :start1 0 :start2 1
                                       :end1 (1- ,block-length-expr) :end2 ,block-length-expr)
                              (setf (aref iv (1- ,block-length-expr)) b))
                         finally (return
                                   (let ((n-bytes-processed (- in-end in-start)))
                                     (values n-bytes-processed n-bytes-processed)))))
                  (mode-lambda
                   (loop for i of-type index from in-start below in-end
                         for j of-type index from out-start
                         do (replace encrypted-iv iv :end1 ,block-length-expr :end2 ,block-length-expr)
                            (funcall function cipher encrypted-iv 0 encrypted-iv 0)
                            (replace iv iv :start1 0 :start2 1
                                     :end1 (1- ,block-length-expr) :end2 ,block-length-expr)
                            (let ((b (aref in i)))
                              (setf (aref iv (1- ,block-length-expr)) b)
                              (setf (aref out j) (logxor b (aref encrypted-iv 0))))
                         finally (return
                                   (let ((n-bytes-processed (- in-end in-start)))
                                     (values n-bytes-processed n-bytes-processed)))))))))
           (message-length (cipher-specializer block-length-expr)
             (declare (ignore block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode cfb8-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function mode-crypt message-length))


;;; OFB mode

(macrolet ((mode-crypt (cipher-specializer block-length-expr)
             `(defmethod mode-crypt-functions ((cipher ,cipher-specializer)
                                               (mode ofb-mode))
                (let ((iv (iv mode))
                      (iv-position (iv-position mode)))
                  (declare (type (simple-octet-vector ,block-length-expr) iv))
                  (declare (type (integer 0 (,block-length-expr)) iv-position))
                  (flet ((ofb-crypt-function (function)
                           (declare (type function function))
                           (mode-lambda
                            (loop for i of-type index from in-start below in-end
                                  for j of-type index from out-start
                                  do (when (zerop iv-position)
                                       (funcall function cipher iv 0 iv 0))
                                     (setf (aref out j) (logxor (aref in i)
                                                                (aref iv iv-position)))
                                     (setf iv-position (mod (1+ iv-position) ,block-length-expr))
                                  finally (return
                                            (let ((n-bytes-processed (- in-end in-start)))
                                              (values n-bytes-processed n-bytes-processed)))))))
                    (let ((f (ofb-crypt-function (encrypt-function cipher))))
                      (values f f))))))
           (message-length (cipher-specializer block-length-expr)
             (declare (ignore block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode ofb-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function mode-crypt message-length))


;;; CTR mode

(macrolet ((mode-crypt (cipher-specializer block-length-expr)
             `(defmethod mode-crypt-functions ((cipher ,cipher-specializer)
                                               (mode ctr-mode))
                (let ((iv (iv mode))
                      (encrypted-iv (nibbles:make-octet-vector ,block-length-expr))
                      (iv-position (iv-position mode)))
                  (declare (type (simple-octet-vector ,block-length-expr) iv encrypted-iv))
                  (declare (type (integer 0 (,block-length-expr)) iv-position))
                  (flet ((ctr-crypt-function (function)
                           (declare (type function function))
                           (mode-lambda
                            (let ((remaining (- in-end in-start))
                                  (processed 0))
                              (declare (type index remaining processed))

                              ;; Use remaining bytes in encrypted-iv
                              (loop until (or (zerop remaining) (zerop iv-position))
                                    do (setf (aref out (+ out-start processed))
                                             (logxor (aref in (+ in-start processed))
                                                     (aref encrypted-iv iv-position)))
                                       (if (= iv-position (1- ,block-length-expr))
                                           (setf iv-position 0)
                                           (incf iv-position))
                                       (incf processed)
                                       (decf remaining))

                              ;; Process data by block
                              (loop until (< remaining ,block-length-expr)
                                    do (funcall function cipher iv 0 encrypted-iv 0)
                                       (increment-counter-block iv)
                                       (xor-block ,block-length-expr
                                                  encrypted-iv
                                                  in
                                                  (+ in-start processed)
                                                  out
                                                  (+ out-start processed))
                                       (incf processed ,block-length-expr)
                                       (decf remaining ,block-length-expr))

                              ;; Process remaing bytes of data
                              (loop until (zerop remaining)
                                    do (when (zerop iv-position)
                                         (funcall function cipher iv 0 encrypted-iv 0)
                                         (increment-counter-block iv))
                                       (setf (aref out (+ out-start processed))
                                             (logxor (aref in (+ in-start processed))
                                                     (aref encrypted-iv iv-position)))
                                       (if (= iv-position (1- ,block-length-expr))
                                           (setf iv-position 0)
                                           (incf iv-position))
                                       (incf processed)
                                       (decf remaining))

                              (values processed processed)))))
                    (let ((f (ctr-crypt-function (encrypt-function cipher))))
                      (values f f))))))
           (message-length (cipher-specializer block-length-expr)
             (declare (ignore block-length-expr))
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode ctr-mode) length
                                                   &optional handle-final-block)
                (declare (ignore handle-final-block))
                ;; We can encrypt the whole thing.
                length)))
  (define-mode-function mode-crypt message-length))


;;; Padded modes

(macrolet ((encrypt (cipher-specializer block-length-expr)
             `(defmethod encrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode padded-cipher-mode)
                                            plaintext ciphertext
                                            plaintext-start plaintext-end
                                            ciphertext-start handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (type index plaintext-start plaintext-end ciphertext-start))
                (declare (ignorable handle-final-block))
                (let* ((buffer (buffer mode))
                       (sub-mode (sub-mode mode))
                       (buffer-index (buffer-index mode))
                       (amount (- ,block-length-expr buffer-index))
                       (plaintext-length (- plaintext-end plaintext-start))
                       (n-bytes-encrypted 0))
                  (declare (type (simple-octet-vector ,block-length-expr) buffer))
                  (when (> plaintext-length amount)
                    (replace buffer plaintext :start1 buffer-index
                             :end1 ,block-length-expr
                             :start2 plaintext-start)
                    (encrypt-with-mode cipher sub-mode plaintext ciphertext
                                       plaintext-start plaintext-end
                                       ciphertext-start nil)
                    (setf buffer-index 0)
                    (decf plaintext-length amount)
                    (incf plaintext-start amount)
                    (incf n-bytes-encrypted amount)
                    (loop while (> plaintext-length ,block-length-expr)
                          do (encrypt-with-mode cipher sub-mode
                                     plaintext ciphertext
                                     plaintext-start
                                     (+ plaintext-start
                                                 ,block-length-expr)
                                     (+ ciphertext-start
                                                  n-bytes-encrypted)
                                     nil)
                             (decf plaintext-length ,block-length-expr)
                             (incf plaintext-start ,block-length-expr)
                             (incf n-bytes-encrypted ,block-length-expr)))
                  (replace buffer plaintext :start2 plaintext-start
                           :end2 plaintext-end)
                  (setf (buffer-index mode) plaintext-length)
                  (values (+ n-bytes-encrypted plaintext-length)
                          n-bytes-encrypted))))
           (decrypt (cipher-specializer block-length-expr)
             `(defmethod decrypt-with-mode ((cipher ,cipher-specializer)
                                            (mode padded-cipher-mode)
                                            ciphertext plaintext
                                            ciphertext-start ciphertext-end
                                            plaintext-start handle-final-block)
                (declare (type simple-octet-vector plaintext ciphertext))
                (declare (type index ciphertext-start ciphertext-end plaintext-start))
                (declare (ignorable handle-final-block))
                (let* ((buffer (buffer mode))
                       (sub-mode (sub-mode mode))
                       (buffer-index (buffer-index mode))
                       (amount (- ,block-length-expr buffer-index))
                       (ciphertext-length (- ciphertext-end ciphertext-start))
                       (n-bytes-decrypted 0))
                  (when (> ciphertext-length amount)
                    (replace buffer ciphertext :start1 buffer-index
                             :end1 ,block-length-expr
                             :start2 ciphertext-start)
                    (decrypt-with-mode cipher sub-mode ciphertext plaintext
                                       ciphertext-start ciphertext-end
                                       plaintext-start nil)
                    (setf buffer-index 0)
                    (decf ciphertext-length amount)
                    (incf ciphertext-start amount)
                    (incf n-bytes-decrypted amount)
                    (loop while (> ciphertext-length ,block-length-expr)
                          do (decrypt-with-mode cipher sub-mode
                                     ciphertext plaintext
                                     ciphertext-start
                                     (+ ciphertext-start
                                                  ,block-length-expr)
                                     (+ ciphertext-start
                                                  n-bytes-decrypted) nil)
                             (decf ciphertext-length ,block-length-expr)
                             (incf ciphertext-start ,block-length-expr)
                             (incf n-bytes-decrypted ,block-length-expr)))
                  (replace buffer ciphertext :start2 ciphertext-start
                           :end2 ciphertext-end)
                  (setf (buffer-index mode) ciphertext-length)
                  (values (+ n-bytes-decrypted ciphertext-length)
                          n-bytes-decrypted))))
           (message-length (cipher-specializer block-length-expr)
             `(defmethod encrypted-message-length ((cipher ,cipher-specializer)
                                                   (mode padded-cipher-mode)
                                                   length
                                                   &optional handle-final-block)
                (let* ((buffer-index (buffer-index mode))
                       (total-amount (+ buffer-index length)))
                  (cond
                    (handle-final-block
                     ;; Calculate how much padding we will need.
                     (multiple-value-bind (full-blocks leftover)
                         (ceiling total-amount ,block-length-expr)
                       (declare (ignore leftover))
                       (* full-blocks ,block-length-expr)))
                    (t
                     ;; Return the number of full blocks we will encrypt.
                     (multiple-value-bind (full-blocks leftover)
                         (floor total-amount ,block-length-expr)
                       (declare (ignore leftover))
                       (* full-blocks ,block-length-expr))))))))
  (define-mode-function encrypt decrypt message-length))

(defmethod mode-crypt-functions (cipher (mode stream-mode))
  (flet ((stream-crypt-function (function)
           (declare (type function function))
           (mode-lambda
            (let ((length (- in-end in-start)))
              (when (plusp length)
                (funcall function cipher in in-start out out-start length))
              (let ((n-bytes-processed (max 0 length)))
                (values n-bytes-processed n-bytes-processed))))))
    (values (stream-crypt-function (encrypt-function cipher))
            (stream-crypt-function (decrypt-function cipher)))))

) ; DEFINE-MODE-FUNCTION MACROLET

(defmethod encrypted-message-length (context
                                     (mode stream-mode) length
                                     &optional handle-final-block)
  (declare (ignore context mode handle-final-block))
  (declare (type index length))
  length)
