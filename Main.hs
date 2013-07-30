-- Spec-Counter-Mode-Encryption and Decryption
-- Frank Recker, 2013

module Main(main) where
import Data.Word
import System.IO
import System.Random
import System.Environment
import CounterMode
import Speck
import qualified Data.ByteString.Lazy as B

main
  | self_test  = do
      hSetBuffering stdout NoBuffering
      getArgs >>= \args -> case args of
        ["e",inp,out] -> ctr_file_encrypt inp out
        ["d",inp,out] -> ctr_file_decrypt inp out

ctr_file_encrypt f g = do
  keys <- gen_key
  print_keys keys
  ctr_process_file keys f g

ctr_file_decrypt f g = do
  keys <- read_keys
  ctr_process_file keys f g

ctr_process_file keys f g = do
  in_handle <- openBinaryFile f ReadMode
  out_handle <- openBinaryFile g WriteMode
  xs <- B.hGetContents in_handle
  B.hPut out_handle $ B.pack $ ctr_encrypt key_expansion encryption keys $ B.unpack xs
  hClose out_handle
  hClose in_handle

print_keys keys =
  putStrLn $ show keys

read_keys = do
  putStr "Key: "
  x <- getLine
  return $ read x

gen_key = do
  g <- getStdGen
  let (x,g') = random_word64 g
  let (y,g'') = random_word64 g'
  setStdGen g''
  return [x,y]

random_word64 g =
  (fromIntegral x,g')
  where
    x :: Integer
    (x,g') = randomR (fromIntegral u,fromIntegral o) g
    u,o :: Word64
    u = minBound
    o = maxBound
