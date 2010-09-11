(in-package :sb-vm)

#+(or x86 x86-64)
(progn
(define-vop (fill-block-ub8)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg))
         (buffer :scs (descriptor-reg))
         (offset :scs (unsigned-reg immediate) :target buffer-index))
  (:variant-vars big-endian-p bytes-to-copy 64-bit-p)
  (:temporary (:sc unsigned-reg) temp buffer-index block-index)
  (:generator 50
    (let* ((data-offset (- (* n-word-bytes vector-data-offset)
                             other-pointer-lowtag))
           (block-disp (+ data-offset bytes-to-copy))
           (ea-size #+x86 :dword #+x86-64 :qword)
           (immediate-offset (sc-is offset immediate))
           (unroll (if immediate-offset 2 1))
           (loop (gen-label)))
      (flet ((ea-for-buffer (&optional (offset 0))
               (if immediate-offset
                   (make-ea ea-size :base buffer
                            :index block-index
                            :scale n-word-bytes
                            :disp (+ block-disp offset))
                   (make-ea ea-size :base buffer
                            :index buffer-index :disp data-offset)))
             (ea-for-block (&optional (offset 0))
               (make-ea ea-size :base block
                        :index block-index
                        :scale n-word-bytes
                        :disp (+ block-disp offset)))
             (handle-endianness (x)
               (when big-endian-p
                 (inst bswap x)
                 #+x86-64
                 (unless 64-bit-p
                   (inst rol x 32)))))
        (unless immediate-offset
          (move buffer-index offset))
        (inst mov block-index (- (truncate bytes-to-copy n-word-bytes)))
        (emit-label loop)
        (inst mov temp (ea-for-buffer 0))
        (when immediate-offset
          (inst mov buffer-index (ea-for-buffer n-word-bytes)))
        (handle-endianness temp)
        (when immediate-offset
          (handle-endianness buffer-index))
        (inst mov (ea-for-block) temp)
        (when immediate-offset
          (inst mov (ea-for-block n-word-bytes) buffer-index))
        (unless immediate-offset
          (inst add buffer-index n-word-bytes))
        (inst add block-index unroll)
        (inst jmp :nz loop)))))

(define-vop (fill-block-ub8-le fill-block-ub8)
  (:translate ironclad::fill-block-ub8-le)
  (:arg-types simple-array-unsigned-byte-32
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant nil 64 nil))

(define-vop (fill-block-ub8-be fill-block-ub8)
  (:translate ironclad::fill-block-ub8-be)
  (:arg-types simple-array-unsigned-byte-32
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant t 64 nil))

#+x86-64
(define-vop (fill-block-ub8-le/64 fill-block-ub8)
  (:translate ironclad::fill-block-ub8-le/64)
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-8
              positive-fixnum)
  ;; Yes.  Really.  Inconsistent naming FTW.
  (:variant nil 64 t))

#+x86-64
(define-vop (fill-block-ub8-be/64 fill-block-ub8)
  (:translate ironclad::fill-block-ub8-be/64)
  (:arg-types simple-array-unsigned-byte-64
              simple-array-unsigned-byte-8
              positive-fixnum)
  (:variant t 128 t))

(define-vop (expand-block)
  (:translate ironclad::expand-block)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-32)
  (:temporary (:sc unsigned-reg) temp count)
  (:generator 100
    (flet ((block-word (elem-offset)
             (make-ea :dword :base block
                      :index count
                      :scale 4
                      :disp (+ (- (* n-word-bytes vector-data-offset)
                                  other-pointer-lowtag)
                               (* 4 (+ 80 elem-offset))))))
      (let ((loop (gen-label))
            #+x86-64 (temp (reg-in-size temp :dword)))
        (inst mov count -64)
        (emit-label loop)
        (inst mov temp (block-word -3))
        (inst xor temp (block-word -8))
        (inst xor temp (block-word -14))
        (inst xor temp (block-word -16))
        (inst rol temp 1)
        (inst mov (block-word 0) temp)
        (inst add count 1)
        (inst jmp :nz loop)))))

(define-vop (sha256-expand-block)
  (:translate ironclad::sha256-expand-block)
  (:policy :fast-safe)
  (:args (block :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-32)
  (:temporary (:sc unsigned-reg) t1 t2 t3 t4 count)
  (:generator 100
    (flet ((block-word (elem-offset)
             (make-ea :dword :base block
                      :index count
                      :scale 4
                      :disp (+ (- (* n-word-bytes vector-data-offset)
                                  other-pointer-lowtag)
                               (* 4 (+ 64 elem-offset))))))
      (let ((loop (gen-label))
            #+x86-64 (t1 (reg-in-size t1 :dword))
            #+x86-64 (t2 (reg-in-size t2 :dword))
            #+x86-64 (t3 (reg-in-size t3 :dword))
            #+x86-64 (t4 (reg-in-size t4 :dword)))
        ;; The code could definitely be improved for x86-64 by using
        ;; more temporaries, but this version works on both 32- and
        ;; 64-bit and eliminates many of the stupidities in the modular
        ;; arithmetic version (mostly on 64-bit, but some lameness in
        ;; the 32-bit version as well).
        (inst mov count -48)
        (emit-label loop)
        (inst mov t1 (block-word -2))
        ;; sigma1
        (inst mov t2 t1)
        (inst rol t2 15)
        (inst mov t3 t1)
        (inst rol t3 13)
        (inst xor t2 t3)
        (inst shr t1 10)
        (inst xor t1 t2)
        (inst mov t2 (block-word -15))
        ;; sigma0
        (inst mov t3 t2)
        (inst rol t3 25)
        (inst mov t4 t2)
        (inst rol t4 14)
        (inst xor t3 t4)
        (inst shr t2 3)
        (inst xor t2 t3)
        (inst add t1 (block-word -7))
        (inst add t2 (block-word -16))
        (inst add t1 t2)
        (inst mov (block-word 0) t1)
        (inst add count 1)
        (inst jmp :nz loop)))))

;;; Implementing this for x86 would require nasty hacks with
;;; pseudo-atomic.  Might just be worth it for the speed increase,
;;; though.  The code is also probably not scheduled optimally.
#+x86-64
(define-vop (update-sha1-block)
  (:translate ironclad::%update-sha1-block)
  (:policy :fast-safe)
  (:args (regs :scs (descriptor-reg) :target result)
         (block :scs (descriptor-reg)))
  (:arg-types simple-array-unsigned-byte-32 simple-array-unsigned-byte-32)
  (:results (result :scs (descriptor-reg)))
  (:result-types simple-array-unsigned-byte-32)
  (:temporary (:sc unsigned-reg) a b c d e t1 t2)
  (:generator 1000
    (let ((a (reg-in-size a :dword))
          (b (reg-in-size b :dword))
          (c (reg-in-size c :dword))
          (d (reg-in-size d :dword))
          (e (reg-in-size e :dword))
          (t1 (reg-in-size t1 :dword))
          (t2 (reg-in-size t2 :dword))
          (k1 #x5a827999)
          (k2 #x6ed9eba1)
          (k3 #x-70e44324)
          (k4 #x-359d3e2a))
      (labels ((block/reg-ea (base index)
                 (make-ea :dword
                          :base base
                          :disp (+ (- (* n-word-bytes vector-data-offset)
                                      other-pointer-lowtag)
                                   (* 4 index))))
               (f1 (a b c d e n)
                 (inst mov t2 a)
                 (inst mov t1 c)
                 (inst rol t2 5)
                 (inst xor t1 d)
                 (inst add t2 (block/reg-ea block n))
                 (inst and t1 b)
                 (inst xor t1 d)
                 (inst lea e (make-ea :dword :base t1 :index e :disp k1))
                 (inst rol b 30)
                 (inst add e t2))
               (f2/4 (a b c d e n k)
                 (inst mov t2 a)
                 (inst mov t1 d)
                 (inst rol t2 5)
                 (inst xor t1 c)
                 (inst add t2 (block/reg-ea block n))
                 (inst xor t1 b)
                 (inst lea e (make-ea :dword :base t1 :index e :disp k))
                 (inst rol b 30)
                 (inst add e t2))
               (f2 (a b c d e n)
                 (f2/4 a b c d e n k2))
               (f4 (a b c d e n)
                 (f2/4 a b c d e n k4))
               (f3 (a b c d e n)
                 (inst mov t2 c)
                 (inst mov t1 c)
                 (inst and t2 b)
                 (inst or t1 b)
                 (inst and t1 d)
                 (inst or t1 t2)
                 (inst mov t2 a)
                 (inst rol t2 5)
                 (inst add t2 (block/reg-ea block n))
                 (inst rol b 30)
                 (inst lea e (make-ea :dword :base t1 :index e :disp k3))
                 (inst add e t2))
               (sha1-rounds (start end f)
                 (let ((xvars (ironclad::make-circular-list a b c d e)))
                   (loop for i from start upto end
                         for vars on xvars by #'cddddr
                         do (multiple-value-bind (a b c d e)
                                (apply #'values (ironclad::circular-list-subseq vars 0 5))
                              (funcall f a b c d e i))))))
        (inst mov a (block/reg-ea regs 0))
        (inst mov b (block/reg-ea regs 1))
        (inst mov c (block/reg-ea regs 2))
        (inst mov d (block/reg-ea regs 3))
        (inst mov e (block/reg-ea regs 4))
        (sha1-rounds 0 19 #'f1)
        (sha1-rounds 20 39 #'f2)
        (sha1-rounds 40 59 #'f3)
        (sha1-rounds 60 79 #'f4)
        (inst add (block/reg-ea regs 0) a)
        (inst add (block/reg-ea regs 1) b)
        (inst add (block/reg-ea regs 2) c)
        (inst add (block/reg-ea regs 3) d)
        (inst add (block/reg-ea regs 4) e)
        (move result regs)))))
)                        ; PROGN
