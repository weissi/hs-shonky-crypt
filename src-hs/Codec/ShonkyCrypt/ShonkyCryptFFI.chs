{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-cse -fno-full-laziness #-} -- recommended by GHC manual

module Codec.ShonkyCrypt.ShonkyCryptFFI where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (liftM)
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.String (CStringLen, CString)
import Foreign.C.Types (CChar(..), CULong(..), CDouble(..))
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (mallocBytes, free)
import Foreign.Marshal.Utils (with, fromBool, toBool)
import Foreign.Ptr
import Foreign.Storable (Storable(..))
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU

#include "shonky-crypt.h"

data ShonkyCryptKey = ShonkyCryptKey
    { sckKeyStart :: !Word8
    , sckKeyInc :: !Word8
    , sckOnlyAlnum :: !Bool
    } deriving Show

instance Storable ShonkyCryptKey where
    sizeOf _ = {#sizeof shonky_crypt_key_t #}
    alignment _ = 4
    peek p = ShonkyCryptKey
               <$> liftM fromIntegral ({#get shonky_crypt_key_t->key_start #} p)
               <*> liftM fromIntegral ({#get shonky_crypt_key_t->key_inc #} p)
               <*> liftM toBool ({#get shonky_crypt_key_t->only_alnum #} p)
    poke p x =
      do {#set shonky_crypt_key_t.key_start #} p (fromIntegral $ sckKeyStart x)
         {#set shonky_crypt_key_t.key_inc #} p (fromIntegral $ sckKeyInc x)
         {#set shonky_crypt_key_t.only_alnum #} p (fromBool $ sckOnlyAlnum x)

fromMallocedStorable :: Storable a => Ptr a -> IO a
fromMallocedStorable p =
    do key <- peek p
       free p
       return key

newPointerToRelease :: Ptr ShonkyCryptContext -> IO ShonkyCryptContext
newPointerToRelease p =
    do fp <- newForeignPtr scReleaseContextPtr p
       return $ ShonkyCryptContext fp

unsafePackMallocCStringLen :: CStringLen -> IO ByteString
unsafePackMallocCStringLen (cstr, len) = do
    fp <- newForeignPtr BSI.c_free_finalizer (castPtr cstr)
    return $! BSI.PS fp 0 len

withShonkyCryptContext :: ShonkyCryptContext -> (Ptr ShonkyCryptContext -> IO b) -> IO b
{#pointer shonky_crypt_context_t as ShonkyCryptContext foreign newtype #}

foreign import ccall "shonky-crypt.h &sc_release_context"
  scReleaseContextPtr :: FunPtr (Ptr ShonkyCryptContext -> IO ())

{#pointer shonky_crypt_key_t as ShonkyCryptKeyPtr -> ShonkyCryptKey #}

withTrickC2HS :: Storable a => a -> (Ptr a -> IO b) -> IO b
withTrickC2HS = with

{#fun pure unsafe sc_alloc_context_with_key as
    ^ { withTrickC2HS* `ShonkyCryptKey' }
    -> `ShonkyCryptContext' newPointerToRelease* #}

withByteStringLen :: ByteString -> ((CString, CULong) -> IO a) -> IO a
withByteStringLen str f = BSU.unsafeUseAsCStringLen str (\(cstr, len) ->
    f (cstr, fromIntegral len))

{#fun pure unsafe sc_entropy as
    ^ { withByteStringLen *`ByteString'& } -> `Double' #}

{#fun pure unsafe sc_copy_context as
    ^ { withShonkyCryptContext* `ShonkyCryptContext' }
    -> `ShonkyCryptContext' newPointerToRelease* #}

type InPlaceEnDeCryptFun =
     Ptr ShonkyCryptContext -> Ptr CChar -> Ptr CChar -> CULong -> IO ()
type NewEnDeCryptFun =
     Ptr ShonkyCryptKey -> Ptr CChar -> CULong -> IO CString

scEnDeCryptInplace :: InPlaceEnDeCryptFun
                   -> ShonkyCryptContext
                   -> ByteString
                   -> (ByteString, ShonkyCryptContext)
scEnDeCryptInplace f ctx input =
    let !newContext = scCopyContext ctx
     in unsafePerformIO $
        BSU.unsafeUseAsCStringLen input $ \(inputBytes, inputLen) ->
        withShonkyCryptContext newContext $ \newContext' ->
        do
           outBuffer <- mallocBytes inputLen
           f newContext' inputBytes outBuffer (fromIntegral inputLen)
           out <- unsafePackMallocCStringLen (outBuffer, inputLen)
           return (out, newContext)

encryptS :: ShonkyCryptContext -> ByteString -> (ByteString, ShonkyCryptContext)
encryptS = scEnDeCryptInplace {#call unsafe sc_encrypt_inplace #}
decryptS :: ShonkyCryptContext -> ByteString -> (ByteString, ShonkyCryptContext)
decryptS = scEnDeCryptInplace {#call unsafe sc_decrypt_inplace #}

scEnDecryptNew :: NewEnDeCryptFun -> ShonkyCryptKey -> ByteString -> ByteString
scEnDecryptNew f key input =
    unsafePerformIO $
    BSU.unsafeUseAsCStringLen input $ \(inputBytes, inputLen) ->
    with key $ \key' ->
    do outputC <- f key' inputBytes (fromIntegral inputLen)
       unsafePackMallocCStringLen (outputC, inputLen)

encrypt :: ShonkyCryptKey -> ByteString -> ByteString
encrypt = scEnDecryptNew {#call unsafe sc_encrypt_new #}

decrypt :: ShonkyCryptKey -> ByteString -> ByteString
decrypt = scEnDecryptNew {#call unsafe sc_decrypt_new #}

{#fun pure unsafe sc_new_crypt_key_with as
    ^ { `Word8', `Word8', `Bool' } -> `ShonkyCryptKey' fromMallocedStorable* #}