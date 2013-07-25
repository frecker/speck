-- implements Spec128/128 - as defined in http://eprint.iacr.org/2013/404.pdf
-- encrption and decryption is done in Counter-Mode

-- Frank Recker, 2013

import Data.Word
import Data.Bits
import System.Random
import System.Environment
import System.IO
import qualified Data.ByteString.Lazy as B

main
  | self_test  = do
      hSetBuffering stdout NoBuffering
      getArgs >>= \args -> case args of
        ["e",inp,out] -> ctr_file_encrypt inp out
        ["d",inp,out] -> ctr_file_decrypt inp out

---- IO
ctr_file_encrypt f g = do
  (key_1,key_0) <- gen_key
  print_keys key_1 key_0
  xs <- B.readFile f
  B.writeFile g $ B.pack $ ctr_encrypt [key_1,key_0] $ B.unpack xs

ctr_file_decrypt f g = do
  (key_1,key_0) <- read_keys
  xs <- B.readFile f
  B.writeFile g $ B.pack $ ctr_decrypt [key_1,key_0] $ B.unpack xs

print_keys k1 k0 =
  putStrLn $ num_to_hex_string k1 ++ " " ++ num_to_hex_string k0

read_keys = do
  putStr "Key: "
  x <- getLine
  let (y,z) = splitAt 16 x
  case z of
    ' ':r -> let (u,w) = splitAt 16 r
             in  case w of
                   [] -> return (hex_string_to_num y,hex_string_to_num u)

gen_key :: IO (Word64,Word64)
gen_key = do
  g <- getStdGen
  let (x,g') = zuf_word64 g
  let (y,g'') = zuf_word64 g'
  setStdGen g''
  return (x,y)

zuf_word64 :: RandomGen g => g -> (Word64,g)
zuf_word64 g =
  (fromIntegral x,g')
  where
    x :: Integer
    (x,g') = randomR (fromIntegral u,fromIntegral o) g
    u,o :: Word64
    u = minBound
    o = maxBound

---- Real World encryption and decryption
ctr_encrypt :: [Word64] -> [Word8] -> [Word8]
ctr_encrypt key xs =
  concat $ map word64_to_word8 zs
  where
    zs = zip_tupel_xor ys ctr_stream
    zip_tupel_xor ((u,v):ws) ((u',v'):ws') =
      (u `xor` u'):(v `xor` v'):zip_tupel_xor ws ws'
    zip_tupel_xor [] _ = []
    ctr_stream = [encryption rks ch cl | ch<-[0..maxBound], cl<-[0..maxBound]]
    ys = help $ padding 16 1 0 xs
    help (u:us) = let (y,z) = splitAt 8 u
                  in  (word8_to_word64 y,word8_to_word64 z):help us
    help [] = []
    rks = key_expansion key

ctr_decrypt :: [Word64] -> [Word8] -> [Word8]
ctr_decrypt key xs =
  de_padding "ctr_decrypt" 16 1 0 $ concat $ map word64_to_word8 zs
  where
    zs = zip_tupel_xor ys ctr_stream
    zip_tupel_xor ((u,v):ws) ((u',v'):ws') =
      (u `xor` u'):(v `xor` v'):zip_tupel_xor ws ws'
    zip_tupel_xor [] _ = []
    ctr_stream = [encryption rks ch cl | ch<-[0..maxBound], cl<-[0..maxBound]]
    ys = help $ blocks 16 xs
    help (u:us) = let (y,z) = splitAt 8 u
                  in  (word8_to_word64 y,word8_to_word64 z):help us
    help [] = []
    rks = key_expansion key

word8_to_word64 :: [Word8] -> Word64
word8_to_word64 xs =
  help 8 0 xs
  where
    help 0 acc [] = acc
    help n acc (y:ys) = help (n-1) (256 * acc + fromIntegral y) ys

word64_to_word8 :: Word64 -> [Word8]
word64_to_word8 x =
  reverse $ help 8 x
  where
    help 0 0 = []
    help n x = let y = fromIntegral (mod x 256)
                   z = (div x 256)
               in  y:help (n-1) z

padding n a b xs =
  help n xs
  where
     help m (y:ys)
       | m>0  = let (zs:zss) = help (m-1) ys in ((y:zs):zss)
       | m==0 = []:help n (y:ys)
     help m []
       | m>0  = [a:take (m-1) (repeat b)]
       | m==0 = []:[a:take (n-1) (repeat b)]

de_padding s n a b xs =
  help xs
  where
    help ys
      | not (null ws) = zs ++ help ws
      | length zs==n = help2 (reverse zs)
      where
        (zs,ws) = splitAt n ys
    help2 (y:ys)
      | y==b = help2 ys
      | y==a = reverse ys
      | otherwise = error "last block has wrong padding"

blocks n [] = []
blocks n xs
  | length ys == n = ys:blocks n zs
  | otherwise = error "last block has wrong size"
  where
    (ys,zs) = splitAt n xs

---- Spec128/128 - implemented with Word64
-- Tests the test vector
self_test
  | cipher /= cipher' = error "encryption failed"
  | plain /= plain' = error "decryption failed"
  | otherwise = True
  where
    keys = ["0f0e0d0c0b0a0908","0706050403020100"]
    plain = ("6c61766975716520","7469206564616d20")
    cipher = ("a65d985179783265","7860fedf5c570d18")
    rks = key_expansion $ map hex_string_to_num keys
    cipher' = num_tup_to_hex $ uncurry (encryption rks) (hex_tup_to_num plain)
    plain' = num_tup_to_hex $ uncurry (decryption (reverse rks)) (hex_tup_to_num cipher')
    hex_tup_to_num (x,y) = (hex_string_to_num x,hex_string_to_num y)
    num_tup_to_hex (x,y) = (num_to_hex_string x,num_to_hex_string y)

-- keys are in the order 1 0
-- round keys are in order 0..T-1
key_expansion :: [Word64] -> [Word64]
key_expansion [l0,k0] =
  take 32 $ help 0 l0 k0
  where
    help i li ki = let i' = i+1
                       li' = (ki + (rotate li (-8))) `xor` i
                       ki' = (rotate ki 3) `xor` li'
                   in  ki:help i' li' ki'

-- round_keys are in order 0..T-1
encryption :: [Word64] -> Word64 -> Word64 -> (Word64,Word64)
encryption (k:ks) x y =
  encryption ks x_new y_new
  where
    x_new = (rotate x (-8) + y) `xor` k
    y_new = (rotate y 3) `xor` x_new
encryption [] x y = (x,y)

-- round_keys are in order T-1..0
decryption :: [Word64] -> Word64 -> Word64 -> (Word64,Word64)
decryption (k:ks) x y =
  decryption ks x_new y_new
  where
    y_new = rotate (x `xor` y) (-3)
    x_new = rotate ((x `xor` k) - y_new) 8
decryption [] x y = (x,y)

---- Conversion functions
num_to_hex_string :: Word64 -> String
num_to_hex_string x =
  reverse $ take 16 $ help x
  where
    help x = (num_to_hex_digit (mod x 16)):help (div x 16)

hex_string_to_num :: String -> Word64
hex_string_to_num xs
  | length xs == 16 = help 0 xs
  where
    help acc (x:xs) = help (16*acc+hex_digit_to_num x) xs
    help acc [] = acc

num_to_hex_digit :: Word64 -> Char
num_to_hex_digit x
  | x >= 0 && x <= 9 = toEnum (fromIntegral (x+48))
  | x >= 10 && x <= 15 = toEnum (fromIntegral (x+87))

hex_digit_to_num :: Char -> Word64
hex_digit_to_num x
  | x >= '0' && x <= '9' = fromIntegral (fromEnum x) - 48
  | x >= 'a' && x <= 'f' = fromIntegral (fromEnum x) - 87
