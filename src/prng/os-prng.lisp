;;;; -*- mode: lisp; indent-tabs-mode: nil -*-
;;;; os-prng.lisp -- OS-provided pseudo-random number generator

(in-package :crypto)

(defclass os-prng ()
  (#+unix source))

(defmethod prng-random-data (num-bytes (prng os-prng))
  #+unix
  (let ((seq (make-array num-bytes :element-type '(unsigned-byte 8))))
    (unless (slot-boundp prng 'source)
      (setf (slot-value prng 'source)
            (open #P"/dev/urandom" :element-type '(unsigned-byte 8))))
    (assert (>= (read-sequence seq (slot-value prng 'source)) num-bytes))
    seq)
  #+(and win32 sb-dynamic-core)(sb-win32:crypt-gen-random num-bytes)
  #+(and os-windows ccl) (multiple-value-bind (buff buffp)
                             (ccl:make-heap-ivector num-bytes '(unsigned-byte 8))
                           (when (= (ccl:external-call "SystemFunction036" :address buffp :unsigned-long num-bytes :boolean) 0)
                             (error 'ironclad-error :format-control "RtlGenRandom failed"))
                           (let ((copy (copy-seq buff)))
                             (ccl:dispose-heap-ivector buff)
                             (ccl:dispose-heap-ivector buffp)
                             copy))
  #+(and os-windows allegro) (let ((buff (make-array num-bytes :element-type '(unsigned-byte 8))))
                               (when (= (rtl-gen-random buff num-bytes) 0)
                                 (error 'ironclad-error :format-control "RtlGenRandom failed"))
                               buff)
  #+(and mswindows lispworks)(let ((buff (sys:in-static-area (make-array num-bytes :element-type '(unsigned-byte 8)))))
                                (unless (fli:with-dynamic-lisp-array-pointer (buff buff) (rtl-gen-random buff num-bytes)) (error 'ironclad-error :format-control "RtlGenRandom failed"))
                                (copy-seq buff))
  #-(or unix (and win32 sb-dynamic-core) (and os-windows ccl) (and os-windows allegro) (and mswindows lispworks))(error 'ironclad-error :format-control "OS-RANDOM-SEED is not supported on your platform."))

(defmethod make-prng ((name (eql :os)) &key seed)
  (declare (ignorable seed))
  (make-instance 'os-prng))

(setf *prng* (make-prng :os))
#+thread-support(pushnew '(*prng* . (make-prng :os)) bt:*default-special-bindings* :test #'equal)
