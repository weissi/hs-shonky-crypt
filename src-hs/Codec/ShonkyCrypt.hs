{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleContexts #-}
module Codec.ShonkyCrypt
    ( ShonkyCryptKey(..)
    , entropy
    , encrypt, decrypt
    , encryptS, decryptS
    , contextWithKey
    , caesar, decaesar
    , encryptM, decryptM
    , encryptConduit, decryptConduit
    ) where

import Control.Monad.State.Strict
import Data.ByteString (ByteString)
import Data.Conduit (Conduit, MonadResource)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Data.Conduit.List as CL

import Codec.ShonkyCrypt.ShonkyCryptFFI ( ShonkyCryptKey(..)
                                        , ShonkyCryptContext
                                        , encrypt
                                        , decrypt
                                        , encryptS
                                        , decryptS
                                        )
import qualified Codec.ShonkyCrypt.ShonkyCryptFFI as FFI

caesar' :: (ShonkyCryptKey -> ByteString -> ByteString) -> Text -> Text
caesar' cipher input =
    let key = ShonkyCryptKey { sckKeyStart = 3
                             , sckKeyInc = 0
                             , sckOnlyAlnum = True
                             }
        utf8Bytes = encodeUtf8 input
     in decodeUtf8 $ cipher key utf8Bytes

caesar :: Text -> Text
caesar = caesar' encrypt

decaesar :: Text -> Text
decaesar = caesar' decrypt

encDecM :: MonadState ShonkyCryptContext m
        => (ShonkyCryptContext -> ByteString -> (ByteString, ShonkyCryptContext))
        -> ByteString
        -> m ByteString
encDecM f input =
    do ctx <- get
       let !(!output, !ctx') = f ctx input
       put ctx'
       return output

encryptM :: MonadState ShonkyCryptContext m => ByteString -> m ByteString
encryptM = encDecM encryptS

decryptM :: MonadState ShonkyCryptContext m => ByteString -> m ByteString
decryptM = encDecM decryptS

encDecConduit :: Monad m
              => (ShonkyCryptContext -> a -> (b, ShonkyCryptContext))
              -> ShonkyCryptKey -> Conduit a m b
encDecConduit encDecFun key =
    CL.concatMapAccum f (FFI.scAllocContextWithKey key)
    where f input ctx =
              let (output, ctx') = encDecFun ctx input
               in (ctx', [output])

encryptConduit :: MonadResource m
           => ShonkyCryptKey
           -> Conduit ByteString m ByteString
encryptConduit = encDecConduit encryptS

decryptConduit :: MonadResource m
           => ShonkyCryptKey
           -> Conduit ByteString m ByteString
decryptConduit = encDecConduit decryptS

entropy :: ByteString -> Double
entropy = FFI.scEntropy

contextWithKey :: ShonkyCryptKey -> ShonkyCryptContext
contextWithKey = FFI.scAllocContextWithKey
