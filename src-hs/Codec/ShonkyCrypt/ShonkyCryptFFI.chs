{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -fno-cse -fno-full-laziness #-} -- recommended by GHC manual

module Codec.ShonkyCrypt.ShonkyCryptFFI where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (liftM)
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Foreign.C.String (CStringLen, CString)
import Foreign.C.Types (CChar(..), CULong(..), CUInt(..), CDouble(..))
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc (mallocBytes, free)
import Foreign.Marshal.Utils (with, fromBool, toBool)
import Foreign.Ptr
import Foreign.Storable (Storable(..))
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BSU

#include "shonky-crypt.h"

-- | Copied from bytestring-0.10.2.0 to make this package only depend on
-- bytestring-0.10.0.0.
unsafePackMallocCStringLen :: CStringLen -> IO ByteString
unsafePackMallocCStringLen (cstr, len) = do
    fp <- newForeignPtr BSI.c_free_finalizer (castPtr cstr)
    return $! BSI.PS fp 0 len

-- | 'CSizeT' corresponds to the platform's 'size_t'
type CSizeT = {# type size_t #}

withByteStringLen :: ByteString -> ((CString, CSizeT) -> IO a) -> IO a
withByteStringLen str f = BSU.unsafeUseAsCStringLen str (\(cstr, len) ->
    f (cstr, fromIntegral len))

{#fun pure unsafe sc_entropy as
    ^ { withByteStringLen *`ByteString'& } -> `Double' #}

-- | A shonky encryption key, corresponds to 'shonky_crypt_key_t'
data ShonkyCryptKey = ShonkyCryptKey
    { sckKeyStart :: !Word8
    , sckKeyInc :: !Word8
    , sckOnlyAlnum :: !Bool
    } deriving Show

-- Make 'ShonkyCryptKey' storable.
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

-- Map C and Haskell type for the encryption keys.
{#pointer shonky_crypt_key_t as ShonkyCryptKeyPtr -> ShonkyCryptKey #}

-- Get a pointer to the 'sc_release_context' C function.
foreign import ccall "shonky-crypt.h &sc_release_context"
  scReleaseContextPtr :: FunPtr (Ptr ShonkyCryptContext -> IO ())

-- Free 'ShonkyCryptKey's with 'scReleaseContextPtr'
newShonkyCryptContextPointer :: Ptr ShonkyCryptContext -> IO ShonkyCryptContext
newShonkyCryptContextPointer p =
    do fp <- newForeignPtr scReleaseContextPtr p
       return $! ShonkyCryptContext fp

-- | 'with' renamed because of c2hs parser
withTrickC2HS :: Storable a => a -> (Ptr a -> IO b) -> IO b
withTrickC2HS = with

withShonkyCryptContext :: ShonkyCryptContext -> (Ptr ShonkyCryptContext -> IO b) -> IO b
{#pointer shonky_crypt_context_t as ShonkyCryptContext foreign newtype #}

{#fun pure unsafe sc_alloc_context_with_key as
    ^ { withTrickC2HS *`ShonkyCryptKey' }
    -> `ShonkyCryptContext' newShonkyCryptContextPointer * #}

{#fun pure unsafe sc_copy_context as
    ^ { withShonkyCryptContext *`ShonkyCryptContext' }
    -> `ShonkyCryptContext' newShonkyCryptContextPointer * #}

type InPlaceEnDeCryptFun =
     Ptr ShonkyCryptContext -> Ptr CChar -> Ptr CChar -> CSizeT -> IO ()
scEnDeCryptInplace :: InPlaceEnDeCryptFun
                   -> ShonkyCryptContext
                   -> ByteString
                   -> (ByteString, ShonkyCryptContext)
scEnDeCryptInplace f ctx input =
     unsafePerformIO $
     BSU.unsafeUseAsCStringLen input $ \(inputBytes, inputLen) ->
     withShonkyCryptContext ctx $ \ctx' ->
     do
        newContext' <- {#call unsafe sc_copy_context #} ctx'
        outBuffer <- mallocBytes inputLen
        f newContext' inputBytes outBuffer (fromIntegral inputLen)
        out <- unsafePackMallocCStringLen (outBuffer, inputLen)
        newContext <- newShonkyCryptContextPointer newContext'
        return (out, newContext)

encryptS :: ShonkyCryptContext -> ByteString -> (ByteString, ShonkyCryptContext)
encryptS = scEnDeCryptInplace {#call unsafe sc_encrypt_inplace #}

decryptS :: ShonkyCryptContext -> ByteString -> (ByteString, ShonkyCryptContext)
decryptS = scEnDeCryptInplace {#call unsafe sc_decrypt_inplace #}

type NewEnDeCryptFun =
     Ptr ShonkyCryptKey -> Ptr CChar -> CSizeT -> IO CString

fromMallocedStorable :: Storable a => Ptr a -> IO a
fromMallocedStorable p =
    do key <- peek p
       free p
       return key

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
    ^ { `Word8', `Word8', `Bool' } -> `ShonkyCryptKey' fromMallocedStorable * #}
