(in-package :crypto-tests)


(rtest:deftest bcrypt-1
    (run-kdf-test (crypto:make-kdf 'crypto:bcrypt)
                  (crypto:ascii-string-to-byte-array "Kk4DQuMMfZL9o")
                  (crypto:hex-string-to-byte-array "79762be9970f5be73ac77c0e4f0a3851")
                  16
                  24
                  (crypto:hex-string-to-byte-array "db8f0360d2aa48e1415598bbc1b5c0d9103043ea39686ad2"))
  t)

(rtest:deftest bcrypt-2
    (run-kdf-test (crypto:make-kdf 'crypto:bcrypt)
                  (crypto:ascii-string-to-byte-array "U*U")
                  (crypto:hex-string-to-byte-array "10410410410410410410410410410410")
                  32
                  24
                  (crypto:hex-string-to-byte-array "1bb69143f9a8d304c8d23d99ab049a77a68e2ccc744206bb"))
  t)

(rtest:deftest bcrypt-3
    (run-kdf-test (crypto:make-kdf 'crypto:bcrypt)
                  (crypto:ascii-string-to-byte-array "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                  (crypto:hex-string-to-byte-array "71d79f8218a39259a7a29aabb2dbafc3")
                  32
                  24
                  (crypto:hex-string-to-byte-array "eeee31f80919920425881002d140d555b28a5c72e00f097d"))
  t)
