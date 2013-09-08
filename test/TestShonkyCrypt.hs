{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_GHC -F -pgmF htfpp #-}

import Codec.ShonkyCrypt
import Control.Monad (forM)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.State.Strict (MonadState, evalState)
import Data.ByteString (ByteString, pack)
import Data.Conduit (Conduit, ($$), ($=), runResourceT, MonadResource)
import Data.Text (Text(..))
import Data.Word (Word8)
import Debug.Trace
import Test.Framework
import Test.QuickCheck.Instances
import Test.QuickCheck.Monadic

import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Conduit.List as CL

_EPSILON_ :: Double
_EPSILON_ = 0.00001

instance Arbitrary ShonkyCryptKey where
    arbitrary =
        do key <- arbitrary
           inc <- arbitrary
           only <- arbitrary
           return $ ShonkyCryptKey key inc only

prop_encryptDecryptSymmetric :: ShonkyCryptKey -> ByteString -> Bool
prop_encryptDecryptSymmetric k plain =
    plain == (decrypt k . encrypt k) plain


prop_conduitSymmetric :: ShonkyCryptKey -> [ByteString] -> Property
prop_conduitSymmetric key input =
    monadicIO $
    do actual <- run $
                 do let expected = input
                    runResourceT $
                      CL.sourceList input
                      $= encryptConduit key
                      $= decryptConduit key
                      $$ CL.consume
       assert (expected == actual)
    where expected = input

prop_encryptDecryptMultiIsSymmetric :: ShonkyCryptKey -> [ByteString] -> Bool
prop_encryptDecryptMultiIsSymmetric k plains =
    let encCtx = contextWithKey k
        decCtx = contextWithKey k
        encs = evalState (mapM encryptM plains) encCtx
        decs = evalState (mapM decryptM encs) decCtx
     in plains == decs

prop_newCryptKeyWith :: Word8 -> Word8 -> Bool -> Bool
prop_newCryptKeyWith ks ki oa =
    let key = ShonkyCryptKey ks ki oa
        ks' = sckKeyStart key
        ki' = sckKeyInc key
        oa' = sckOnlyAlnum key
     in ks == ks' && ki == ki' && oa == oa'

prop_caesar :: Text -> Bool
prop_caesar t = (decaesar . caesar) t == t

rotKey :: Word8 -> ShonkyCryptKey
rotKey i = ShonkyCryptKey { sckKeyStart = i, sckKeyInc = 0, sckOnlyAlnum = True }

test_wrapAroundWorks :: IO ()
test_wrapAroundWorks =
    do let expected =          ["A", "0", "a"] ++              ["X", "7", "x"]
           actual = map caesar ["X", "7", "x"] ++ map decaesar ["A", "0", "a"]
       assertEqual expected actual

test_onlyAlnumWorks :: IO ()
test_onlyAlnumWorks =
    do let expected =            ["d", "D", "3", " ", "-", "!"]
           actual   = map caesar ["a", "A", "0", " ", "-", "!"]
       assertEqual expected actual

test_incWorksForAlnum :: IO ()
test_incWorksForAlnum =
    do let expected = T.pack . concat $ replicate 2 ['A'..'Z']
           key = ShonkyCryptKey { sckKeyStart=0, sckKeyInc=1, sckOnlyAlnum=True }
           actual = TE.decodeUtf8 . encrypt key . TE.encodeUtf8 $
                    T.pack (replicate (26*2) 'A')
       assertEqual expected actual

test_incWorksForNonAlnum :: IO ()
test_incWorksForNonAlnum =
    do let expected = BS.pack . concat $ replicate 2 [0..255]
           key = ShonkyCryptKey { sckKeyStart=0, sckKeyInc=1, sckOnlyAlnum=False }
           actual = encrypt key $ BS.pack (replicate (256*2) 0)
       assertEqual expected actual

test_incNeq1WorksForNonAlnum :: IO ()
test_incNeq1WorksForNonAlnum =
    do let expected = BS.pack . concat $ replicate 2 [0,4..255]
           key = ShonkyCryptKey { sckKeyStart=0, sckKeyInc=4, sckOnlyAlnum=False }
           actual = encrypt key $ BS.pack (replicate 128 0)
       assertEqual expected actual

test_inplaceEncryption :: IO ()
test_inplaceEncryption =
    do let key = ShonkyCryptKey { sckKeyStart=1
                                , sckKeyInc=4
                                , sckOnlyAlnum=False
                                }
           ctx = contextWithKey key
           (enc', ctx') = encryptS ctx $ TE.encodeUtf8 "A"
           (enc'', ctx'') = encryptS ctx' $ TE.encodeUtf8 "A"
           expected = TE.encodeUtf8 "BF"
           actual = BS.concat [enc', enc'']
       assertEqual expected actual

test_contextNotMutated :: IO ()
test_contextNotMutated =
    do let key = ShonkyCryptKey { sckKeyStart=1
                                , sckKeyInc=4
                                , sckOnlyAlnum=False
                                }
           ctx = contextWithKey key
           (enc1, _) = encryptS ctx $ TE.encodeUtf8 "A"
           (enc2, _) = encryptS ctx $ TE.encodeUtf8 "A"
           (enc3, _) = encryptS ctx $ TE.encodeUtf8 "A"
           (enc4, _) = encryptS ctx $ TE.encodeUtf8 "A"
           expected = replicate 4 (TE.encodeUtf8 "B")
           actual = [enc1, enc2, enc3, enc4]
       assertEqual expected actual

test_conduit :: IO ()
test_conduit =
    do let expected = [ TE.encodeUtf8 ""
                      , TE.encodeUtf8 "Hello"
                      , TE.encodeUtf8 "World"
                      , TE.encodeUtf8 "!"
                      ]
           key = ShonkyCryptKey { sckKeyStart=17, sckKeyInc=23, sckOnlyAlnum=False }
       actual <- runResourceT $
                 CL.sourceList expected
                 $= encryptConduit key
                 $= decryptConduit key
                 $$ CL.consume
       assertEqual expected actual

test_zero_entropy :: IO ()
test_zero_entropy =
    do let expected = 0.0
           actual = entropy $ BS.pack [0, 0, 0, 0, 0]
       assertEqual expected actual

test_entropy1 :: IO ()
test_entropy1 =
    do let expected = 3.27761 -- http://www.shannonentropy.netmark.pl/calculate
           actual = entropy $ TE.encodeUtf8 "Lorem ipsum"
       assertBool $ (abs (actual - expected)) < _EPSILON_

_T :: Text
_T="Shannon entropy is one of the most important metrics in information theory."

test_entropy2 :: IO ()
test_entropy2 =
    do let expected = 3.7474 -- http://www.shannonentropy.netmark.pl/calculate
           actual = entropy $ TE.encodeUtf8 _T
       assertBool $ (abs (actual - expected)) < _EPSILON_

main = htfMain htf_thisModulesTests
