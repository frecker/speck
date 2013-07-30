-- Counter-Mode-Encryption and Decryption
-- Frank Recker, 2013

module CounterMode(ctr_encrypt) where
import Data.Bits
import Data.Word

-- encryption and decryption is the same operation in counter mode
ctr_encrypt key_expansion_function encryption_function keys xs = zipWith xor xs (ctr_stream key_expansion_function encryption_function keys)

ctr_stream key_expansion_function encryption_function keys =
  w8_stream
  where
    w8_stream =
      concat [word64_to_word8 u ++ word64_to_word8 v | (u,v) <- w64_stream]
    w64_stream = [encryption_function rks ch cl | ch<-[0..maxBound], cl<-[0..maxBound]]
    rks = key_expansion_function keys

word64_to_word8 :: Word64 -> [Word8]
word64_to_word8 x =
  reverse $ help 8 x
  where
    help 0 0 = []
    help n x = let y = fromIntegral (mod x 256)
                   z = (div x 256)
               in  y:help (n-1) z
