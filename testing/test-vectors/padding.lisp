;;;; padding.lisp

(in-package :crypto-tests)

(rtest:deftest pkcs7-padding
  (loop with block-size = 16
        and array = (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-element 0)
        and padding = (make-instance 'crypto::pkcs7-padding)
       for i from 0 below block-size
       do (crypto::add-padding-bytes padding array 0 i block-size)
       finally (return
                 (dotimes (i block-size :ok)
                   (unless (= (aref array i) (- block-size i))
                     (return :error)))))
  :ok)

