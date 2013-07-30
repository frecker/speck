-- implements Spec128/128 - as defined in http://eprint.iacr.org/2013/404.pdf
-- Frank Recker, 2013

module Speck(self_test,key_expansion,encryption,decryption) where
import Data.Bits
import Data.Word

-- Tests the test vector
self_test
  | cipher /= cipher' = error "encryption failed"
  | plain /= plain' = error "decryption failed"
  | otherwise = True
  where
    keys = [0x0f0e0d0c0b0a0908,0x0706050403020100]
    plain = (0x6c61766975716520,0x7469206564616d20)
    cipher = (0xa65d985179783265,0x7860fedf5c570d18)
    rks = key_expansion keys
    cipher' = uncurry (encryption rks) plain
    plain' = uncurry (decryption (reverse rks)) cipher'

-- keys are in the order 1 0
-- round keys are in order 0..T-1
key_expansion :: [Word64] -> [Word64]
key_expansion [l0,k0] =
  take 32 $ k0:help 0 l0 k0
  where
    help i li ki = let i' = i+1
                       li' = (ki + (rotate li (-8))) `xor` i
                       ki' = (rotate ki 3) `xor` li'
                   in  ki':help i' li' ki'

-- round_keys are in order 0..T-1
encryption :: [Word64] -> Word64 -> Word64 -> (Word64,Word64)
encryption (k:ks) x y =
  encryption ks x_new y_new
  where
    x_new = (rotate x (-8) + y) `xor` k
    y_new = (rotate y 3) `xor` x_new
encryption [] x y = (x,y)

-- round_keys are in order T-1..0
-- in fact, this function is not used in counter-mode but provided anyway
decryption :: [Word64] -> Word64 -> Word64 -> (Word64,Word64)
decryption (k:ks) x y =
  decryption ks x_new y_new
  where
    y_new = rotate (x `xor` y) (-3)
    x_new = rotate ((x `xor` k) - y_new) 8
decryption [] x y = (x,y)
