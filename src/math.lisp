(in-package :crypto)

(defun egcd (a b)
  "Extended Euclidean algorithm, aka extended greatest common
denominator."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer a b))
  (assert (and (>= a 0)
               (>= b 0)))
  (loop
     for c = a then (- d (* q c))
     and d = b then c
     for u_c = 1 then (- u_d (* q u_c))
     and v_c = 0 then (- v_d (* q v_c))
     and u_d = 0 then u_c
     and v_d = 1 then v_c
     until (= c 0)
     for q = (floor d c)
     finally (return (values d u_d v_d))))

(defconst +small-primes+
  (make-array 269
              :element-type 'fixnum
              :initial-contents '(2 3 5 7 11 13 17 19 23 29 31 37 41 43
          47 53 59 61 67 71 73 79 83 89 97 101 103 107 109 113 127 131
          137 139 149 151 157 163 167 173 179 181 191 193 197 199 211
          223 227 229 233 239 241 251 257 263 269 271 277 281 283 293
          307 311 313 317 331 337 347 349 353 359 367 373 379 383 389
          397 401 409 419 421 431 433 439 443 449 457 461 463 467 479
          487 491 499 503 509 521 523 541 547 557 563 569 571 577 587
          593 599 601 607 613 617 619 631 641 643 647 653 659 661 673
          677 683 691 701 709 719 727 733 739 743 751 757 761 769 773
          787 797 809 811 821 823 827 829 839 853 857 859 863 877 881
          883 887 907 911 919 929 937 941 947 953 967 971 977 983 991
          997 1009 1013 1019 1021 1031 1033 1039 1049 1051 1061 1063
          1069 1087 1091 1093 1097 1103 1109 1117 1123 1129 1151 1153
          1163 1171 1181 1187 1193 1201 1213 1217 1223 1229 1231 1237
          1249 1259 1277 1279 1283 1289 1291 1297 1301 1303 1307 1319
          1321 1327 1361 1367 1373 1381 1399 1409 1423 1427 1429 1433
          1439 1447 1451 1453 1459 1471 1481 1483 1487 1489 1493 1499
          1511 1523 1531 1543 1549 1553 1559 1567 1571 1579 1583 1597
          1601 1607 1609 1613 1619 1621 1627 1637 1657 1663 1667 1669
          1693 1697 1699 1709 1721 1723)))

(defun generate-small-primes (n)
  "Generates a list of all primes up to N using the Sieve of
Eratosthenes.  Was used to generate the list above; included for
mathematical interest."
  (assert (<= 2 n (expt 2 20)))
  (loop for i from 2 to n
     with array = (make-array (1+ n) :initial-element 1)
     unless (zerop (aref array i))
     do (loop for j from 2 to (floor (/ n i))
           do (setf (aref array (* i j)) 0))
     finally (return (loop for j from 2 to n
                        unless (zerop (aref array j))
                        collect j))))

(defun prime-p (n &optional (prng *prng*))
  "True if N is a prime number (with very high probability; 1:2^128
chance of returning true for a composite number."
  (assert (>= n 3))
  (if (find n +small-primes+)
      t
      (loop for p across +small-primes+
         while (< p n)
         when (zerop (mod n p))
         do (return nil)
         end
         finally (return (rabin-miller n prng)))))

(defun rabin-miller (n prng)
  "Rabin-Miller probabalistic primality test.  There is a 1:2^128
chance that a composite number will be determined to be a prime number
using this test."
  (declare (optimize (speed 3) (safety 0) (space 0) (debug 0))
           (type integer n))
  (assert (and (>= n 3) (oddp n)))
  (loop for s of-type integer = (1- n) then (the integer (/ s 2))
     and tt of-type integer = 0 then (1+ tt)
     while (zerop (mod s 2))
     finally (return
               (loop for k from 0 to 128 by 2
                  for a = (+ 2 (strong-random (- n 2) prng))
                  for v = (expt-mod a s n)
                  if (not (= v 1))
                  do (loop for i = 0 then (1+ i)
                        while (not (= v (1- n)))
                        if (= i (1- tt))
                        do (return-from rabin-miller)
                        else
                        do (setf v (expt-mod v 2 n)))
                  finally (return t)))))

(defun generate-prime-in-range (lower-limit upper-limit &optional (prng *prng*))
  (assert (< 0 lower-limit upper-limit))
  (loop for r = (strong-random (- upper-limit lower-limit -1) prng)
     for x = (+ r lower-limit)
     until (prime-p x prng)
     finally (return x)))

(defun generate-prime (num-bits &optional (prng *prng*))
  "Return a NUM-BITS-bit prime number with very high
probability (1:2^128 chance of returning a composite number)."
  (loop with big = (ash 2 (1- num-bits))
     for x = (logior (strong-random big prng) big 1)
     until (prime-p x prng)
     finally (return x)))
