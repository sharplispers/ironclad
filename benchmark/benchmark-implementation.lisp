(asdf:load-system "ironclad")

(defparameter *file-size*
  #+sbcl (expt 10 8)
  #+(or allegro ccl ecl) (expt 10 7)
  #-(or allegro ccl ecl sbcl) (expt 10 6))
(defparameter *data-file* "/tmp/data-clr")
(defparameter *encrypted-file* "/tmp/data-enc")
(defparameter *implementation-result-file* "benchmark-tmp")
(defparameter *result* (acons "version"
                              (format nil "~a ~a"
                                      (lisp-implementation-type)
                                      (lisp-implementation-version))
                              '()))

(defmacro get-speed (&body body)
  (let ((start-time (gensym))
        (end-time (gensym))
        (result (gensym))
        (duration (gensym))
        (speed (gensym)))
    `(let* ((,start-time (get-internal-real-time))
            (,result ,@body)
            (,end-time (get-internal-real-time))
            (,duration (/ (- ,end-time ,start-time) internal-time-units-per-second))
            (,speed (round *file-size* ,duration)))
       (values ,speed ,result))))

(defun benchmark-ciphers ()
  (let ((speeds '()))
    (dolist (cipher-name (ironclad:list-all-ciphers))
      (with-open-file (plaintext *data-file*
                                 :element-type '(unsigned-byte 8))
        (with-open-file (ciphertext *encrypted-file*
                                    :direction :output
                                    :element-type '(unsigned-byte 8)
                                    :if-exists :supersede)
          (flet ((stream-cipher-p (cipher-name)
                   (= 1 (ironclad:block-length cipher-name))))
            (let* ((key (ironclad:random-data (car (last (ironclad:key-lengths cipher-name)))))
                   (cipher (ironclad:make-cipher cipher-name
                                                 :key key
                                                 :mode (if (stream-cipher-p cipher-name)
                                                           :stream
                                                           :ecb)))
                   (buffer (make-array 32768 :element-type '(unsigned-byte 8)))
                   (speed (get-speed (loop for buffer-length = (read-sequence buffer plaintext)
                                           until (zerop buffer-length)
                                           do (progn
                                                (ironclad:encrypt-in-place cipher buffer :end buffer-length)
                                                (write-sequence buffer ciphertext :end buffer-length))))))
              (setf speeds (acons cipher-name speed speeds)))))))
    (setf *result* (acons "ciphers" speeds *result*))))

(defun benchmark-digests ()
  (let ((speeds '()))
    (dolist (digest-name (ironclad:list-all-digests))
      (with-open-file (plaintext *data-file*
                                 :element-type '(unsigned-byte 8))
        (let* ((digest (ironclad:make-digest digest-name))
               (buffer (make-array 32768 :element-type '(unsigned-byte 8)))
               (speed (get-speed (loop for buffer-length = (read-sequence buffer plaintext)
                                       until (zerop buffer-length)
                                       do (ironclad:update-digest digest buffer :end buffer-length)
                                       finally (ironclad:produce-digest digest)))))
          (setf speeds (acons digest-name speed speeds)))))
    (setf *result* (acons "digests" speeds *result*))))

(defun benchmark-macs ()
  (let ((speeds '()))
    (dolist (mac-name (ironclad:list-all-macs))
      (with-open-file (plaintext *data-file*
                                 :element-type '(unsigned-byte 8))
        (let* ((key-length (ecase mac-name
                             (ironclad:blake2-mac 64)
                             (ironclad:blake2s-mac 32)
                             (ironclad:cmac 32)
                             (ironclad:hmac 32)
                             (ironclad:poly1305 32)
                             (ironclad:skein-mac 64)))
               (key (ironclad:random-data key-length))
               (extra-args (case mac-name
                             (ironclad:cmac '(:aes))
                             (ironclad:hmac '(:sha256))))
               (mac (apply #'ironclad:make-mac mac-name key extra-args))
               (buffer (make-array 32768 :element-type '(unsigned-byte 8)))
               (speed (get-speed (loop for buffer-length = (read-sequence buffer plaintext)
                                       until (zerop buffer-length)
                                       do (ironclad:update-mac mac buffer :end buffer-length)
                                       finally (ironclad:produce-mac mac)))))
          (setf speeds (acons mac-name speed speeds)))))
    (setf *result* (acons "macs" speeds *result*))))

(benchmark-ciphers)
(benchmark-digests)
(benchmark-macs)
(with-open-file (file *implementation-result-file* :direction :output :if-exists :supersede)
  (write *result* :stream file))

#+allegro (exit)
#-allegro (quit)
