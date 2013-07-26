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
  in_handle <- openBinaryFile f ReadMode
  out_handle <- openBinaryFile g WriteMode
  xs <- B.hGetContents in_handle
  B.hPut out_handle $ B.pack $ ctr_encrypt key_1 key_0 $ B.unpack xs
  hClose out_handle
  hClose in_handle

ctr_file_decrypt f g = do
  (key_1,key_0) <- read_keys
  in_handle <- openBinaryFile f ReadMode
  out_handle <- openBinaryFile g WriteMode
  xs <- B.hGetContents in_handle
  B.hPut out_handle $ B.pack $ ctr_decrypt key_1 key_0 $ B.unpack xs
  hClose out_handle
  hClose in_handle

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
  let (x,g') = random_word64 g
  let (y,g'') = random_word64 g'
  setStdGen g''
  return (x,y)

random_word64 :: RandomGen g => g -> (Word64,g)
random_word64 g =
  (fromIntegral x,g')
  where
    x :: Integer
    (x,g') = randomR (fromIntegral u,fromIntegral o) g
    u,o :: Word64
    u = minBound
    o = maxBound

---- Real World encryption and decryption
ctr_encrypt :: Word64 -> Word64 -> [Word8] -> [Word8]
ctr_encrypt l0 k0 xs =
  zipWith xor xs (ctr_stream l0 k0)

ctr_decrypt :: Word64 -> Word64 -> [Word8] -> [Word8]
ctr_decrypt = ctr_encrypt

ctr_stream :: Word64 -> Word64 -> [Word8]
ctr_stream l0 k0 =
  w8_stream
  where
    w8_stream =
      concat [word64_to_word8 u ++ word64_to_word8 v | (u,v) <- w64_stream]
    w64_stream = [encryption rks ch cl | ch<-[0..maxBound], cl<-[0..maxBound]]
    rks = key_expansion l0 k0

word64_to_word8 :: Word64 -> [Word8]
word64_to_word8 x =
  reverse $ help 8 x
  where
    help 0 0 = []
    help n x = let y = fromIntegral (mod x 256)
                   z = (div x 256)
               in  y:help (n-1) z

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
    rks = key_expansion l0 k0
    [l0,k0] = map hex_string_to_num keys
    cipher' = num_tup_to_hex $ uncurry (encryption rks) (hex_tup_to_num plain)
    plain' = num_tup_to_hex $ uncurry (decryption (reverse rks)) (hex_tup_to_num cipher')
    hex_tup_to_num (x,y) = (hex_string_to_num x,hex_string_to_num y)
    num_tup_to_hex (x,y) = (num_to_hex_string x,num_to_hex_string y)

-- keys are in the order 1 0
-- round keys are in order 0..T-1
key_expansion :: Word64 -> Word64 -> [Word64]
key_expansion l0 k0 =
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
