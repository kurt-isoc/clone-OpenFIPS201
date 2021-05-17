/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/** Provides functionality for ECC PIV key objects */
public final class PIVKeyObjectECC extends PIVKeyObjectPKI {
  private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;

  // The ECC public key element tag
  private static final byte ELEMENT_ECC_POINT = (byte) 0x88;

  // The ECC private key element tag
  private static final byte ELEMENT_ECC_SECRET = (byte) 0x89;

  // The Secure Messaging CVC
  private static final byte ELEMENT_CVC = (byte) 0x8A;

  private final ECParams params;
  private final short marshaledPubKeyLen;

  // The Secure Messaging CVC object (not used for standard ECC)
  private byte[] cvc = null;
  private byte[] cvcHash = null;

  // Cipher implementations (static so they are shared with all instances of PIVKeyObjectECC)
  private static KeyAgreement keyAgreement = null;
  private static Signature signerSHA1 = null;
  private static Signature signerSHA256 = null;
  private static Signature signerSHA384 = null;
  private static Signature signerSHA512 = null;
  private static MessageDigest digestSHA256 = null;
  private static MessageDigest digestSHA384 = null;
  private static Cipher cipherAES = null;
  
  public PIVKeyObjectECC(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes) {
    super(id, modeContact, modeContactless, mechanism, role, attributes);
        
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        params = ECParamsP256.Instance();
        break;
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        params = ECParamsP384.Instance();
        break;
      default:
        params = null; // Keep the compiler happy
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Uncompressed ECC public keys are marshaled as the concatenation of:
    // CONST_POINT_UNCOMPRESSED | X | Y
    // where the length of the X and Y coordinates is the byte length of the key.
    marshaledPubKeyLen = (short) (getKeyLengthBytes() * 2 + 1);
  }

  /*
   * Allows safe allocation of cryptographic service providers at applet instantiation
   */
  public static void createProviders() {
  	
    if (keyAgreement == null) {
    	try {
			keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	keyAgreement = null;
    	}
    }

    if (signerSHA1 == null) {
    	try {
			signerSHA1 = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);    	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	signerSHA1 = null;
    	}
    }

    if (signerSHA256 == null) {
    	try {
			signerSHA256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);    	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	signerSHA256 = null;
    	}
    }

    if (signerSHA384 == null) {
    	try {
			signerSHA384 = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);    	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	signerSHA384 = null;
    	}
    }

    if (signerSHA512 == null) {
    	try {
			signerSHA512 = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);    	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	signerSHA512 = null;
    	}
    }

    if (digestSHA256 == null) {
    	try {
			digestSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false); 	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	digestSHA256 = null;
    	}
    }

    if (digestSHA384 == null) {
    	try {
			digestSHA384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false); 	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	digestSHA384 = null;
    	}
    }

    if (cipherAES == null) {
    	try {
			cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);    	
    	} catch (CryptoException ex) {
	    	// We couldn't create this algorithm, the card may not support it!
	    	cipherAES = null;
    	}
    }  	
  }
  
  /**
   * Updates the elements of the keypair with new values.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>If the card does not support ObjectDeletion, repeatedly calling this method may exhaust
   *       NV RAM.
   *   <li>The ELEMENT_ECC_POINT element must be formatted as an octet string as per ANSI X9.62.
   *   <li>The ELEMENT_ECC_SECRET must be formatted as a big-endian, right-aligned big number.
   *   <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer containing the updated element
   * @param offset first byte of the element in the buffer
   * @param length the length of the element
   */
  @Override
  public void updateElement(byte element, byte[] buffer, short offset, short length) {

    switch (element) {
      case ELEMENT_ECC_POINT:
        if (length != marshaledPubKeyLen) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Only uncompressed points are supported
        if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        allocatePublic();

        ((ECPublicKey) publicKey).setW(buffer, offset, length);
        break;

      case ELEMENT_ECC_SECRET:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        allocatePrivate();

        ((ECPrivateKey) privateKey).setS(buffer, offset, length);
        break;

        // Clear all key parts
      case ELEMENT_CVC:
      	setCVC(buffer, offset, length);
        break;

        // Clear all key parts
      case ELEMENT_CLEAR:
        clear();
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
  }

  private void setCVC(byte[] buffer, short offset, short length) {
  	
	// Re-allocate every call as we can't be sure of the length of the new object        
	if (cvc != null) {
	  cvc = null;
	  cvcHash = null;
	  runGc();
	}

	// Allocate the new object and copy across
	cvc = new byte[length];
	Util.arrayCopyNonAtomic(buffer, offset, cvc, (short) 0, length);

	// Generate the hash
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
		cvcHash = new byte[MessageDigest.LENGTH_SHA_256];		
		digestSHA256.reset();
		digestSHA256.doFinal(buffer, offset, length, cvcHash, (short)0);
        break;
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
		cvcHash = new byte[MessageDigest.LENGTH_SHA_384];
		digestSHA384.reset();
		digestSHA384.doFinal(buffer, offset, length, cvcHash, (short)0);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return; // Keep the compiler happy
    }
	
  }

  /** Clears and reallocates a private key. */
  private void allocatePrivate() {
    if (privateKey == null) {
      privateKey =
          (PrivateKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, getKeyLengthBits(), false);
      setPrivateParams();
    }
  }

  /** Clears and if necessary reallocates a public key. */
  private void allocatePublic() {
    if (publicKey == null) {
      publicKey =
          (PublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, getKeyLengthBits(), false);
      setPublicParams();
    }
  }

  @Override
  public short generate(byte[] scratch, short offset) {

    KeyPair keyPair;
    short length = 0;
    try {
      // Clear any key material
      clear();

      // Allocate both parts (this only occurs if it hasn't already been allocated)
      allocatePrivate();
      allocatePublic();

      // Since the call to clear() will delete this object automatically, it is safe to re-create
      keyPair = new KeyPair(publicKey, privateKey);
      keyPair.genKeyPair();

      TLVWriter writer = TLVWriter.getInstance();

      // Adding 12 to the key length to account for other overhead
      writer.init(scratch, offset, (short) (marshaledPubKeyLen + 5), CONST_TAG_RESPONSE);

      // adding 5 bytes to the marshaled key to account for other APDU overhead.
      writer.writeTag(ELEMENT_ECC_POINT);
      writer.writeLength(marshaledPubKeyLen);
      offset = writer.getOffset();
      offset += ((ECPublicKey) publicKey).getW(scratch, offset);

      writer.setOffset(offset);
      length = writer.finish();
    } catch (CardRuntimeException cre) {
      // At this point we are in a nondeterministic state so we will
      // clear both the public and private keys if they exist
      clear();
      CardRuntimeException.throwIt(cre.getReason());
    } finally {
      // We new'd these objects so we make sure the memory is freed up once they are out of scope.
      runGc();
    }

    return length;
  }

  /**
   * ECC Keys don't have a block length but we conform to SP 800-73-4 Part 2 Para 4.1.4 and return
   * the key length
   *
   * @return the block length equal to the key length
   */
  @Override
  public short getBlockLength() {
    return getKeyLengthBytes();
  }

  /**
   * The length, in bytes, of the key
   *
   * @return the length of the key
   */
  @Override
  public short getKeyLengthBits() {
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        return KeyBuilder.LENGTH_EC_FP_256;

      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        return KeyBuilder.LENGTH_EC_FP_384;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
  }

  /** @return true if the privateKey exists and is initialized. */
  @Override
  public boolean isInitialised() {

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
        return (privateKey != null && privateKey.isInitialized());

      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_CS7:
        // At a minimum we need the private key AND the Card Verifiable Certificate object
        return (privateKey != null && privateKey.isInitialized() && cvc != null);

      default:
        return false; // Satisfy the compiler
    }
  }

  @Override
  public void clear() {
    if (publicKey != null) {
      publicKey.clearKey();
      publicKey = null;
    }
    if (privateKey != null) {
      privateKey.clearKey();
      privateKey = null;
    }
    if (cvc != null) {
      cvc = null;
      runGc();
    }
  }

  /** Set ECC domain parameters. */
  private void setPrivateParams() {

    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    ((ECPrivateKey) privateKey).setA(a, (short) 0, (short) (a.length));
    ((ECPrivateKey) privateKey).setB(b, (short) 0, (short) (b.length));
    ((ECPrivateKey) privateKey).setG(g, (short) 0, (short) (g.length));
    ((ECPrivateKey) privateKey).setR(r, (short) 0, (short) (r.length));
    ((ECPrivateKey) privateKey).setFieldFP(p, (short) 0, (short) (p.length));
    ((ECPrivateKey) privateKey).setK(params.getH());
  }

  /** Set ECC domain parameters. */
  private void setPublicParams() {
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    ((ECPublicKey) publicKey).setA(a, (short) 0, (short) (a.length));
    ((ECPublicKey) publicKey).setB(b, (short) 0, (short) (b.length));
    ((ECPublicKey) publicKey).setG(g, (short) 0, (short) (g.length));
    ((ECPublicKey) publicKey).setR(r, (short) 0, (short) (r.length));
    ((ECPublicKey) publicKey).setFieldFP(p, (short) 0, (short) (p.length));
    ((ECPublicKey) publicKey).setK(params.getH());
  }

  @Override
  public short establishSecureMessaging(
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    //
    // EXECUTION STEPS
    //

    // C1 IDsICC = T8(SHA256(CICC))
    // - IDsICC, the left-most 8 bytes of the SHA-256 hash of CICC, is used as an input for
    //   session key derivation. (Note that IDsICC is static, and so may be pre-computed off
    //   card.)
        
    // C2 CBICC = CBH & 'F0'
    // - Create the PIV Card Applications control byte from client applications control byte,
    //   indicating that persistent binding has not been used in this transaction, even if
    //   CBH indicates that the client application supports it. This may be done by setting CBICC
    //   to the value of CBH and then setting the 4 least significant bits of CBICC to 0.
    byte cbICC = (byte)(inBuffer[inOffset] & 0xF0);
    inOffset++;
    
    // C3 Check that CBICC is 0x00
    // - Return an error ('6A 80') if CBICC is not 0x00.
    if (cbICC != (byte)0) {
	    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	    return (short)0; // Keep static analyser happy
    }

    // C4 Verify that QeH is a valid public key for the domain parameters of QsICC
    // - Perform partial public-key validation of QeH [SP800-56A, Section 5.6.2.3.3],
    //   where the domain parameters are those of QsICC. Also verify that P1 is '27' if the
    //   domain parameters of QsICC are those of Curve P-256 or that P1 is '2E' if the domain
    //   parameters of QsICC are those of Curve P-384.
    // - Return '6A 86' if P1 has the incorrect value.
    // - Return '6A 80' if publickey validation fails.
    
    //
    // NOTE:
    // We rely on the public key validation inherit in the underlying platform to achieve public
    // key domain parameter validation.
    // TODO: Test this and when it fails, use 6A80 (SW_WRONG_DATA) as the response (in try/catch)
    //
    
    // TODO: Confirm that P1 is '27' if Curve P-256, or '2E' if the domain parameters are P-384
    if (false) {
	    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	    return (short)0; // Keep static analyser happy
    }
    
    // Skip past the 8-byte IDsh for now
    inOffset += (short)8;
    
    // C5 Z = ECC_CDH (dsICC, QeH)
    // - Compute the shared secret, Z, using the ECC CDH primitive [SP800-56A, Section 5.7.1.2].
    keyAgreement.init(privateKey);
    
    short len;
    try
    {
		len = keyAgreement.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);	    
    } catch (CryptoException ex) {
    	// Step C4 describes validation of the supplied QeH value. If this fails, we return
    	// SW_WRONG_DATA for all cases, though the real case is for reason 'ILLEGAL_VALUE'.
	    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // C6 Generate nonce NICC
    // - Create a random nonce, where the length is as specified in Table 14. The nonce should be
    //   created using an approved random bit generator where the security strength supported by
    //   the random bit generator is at least as great as the bit length of the nonce being
    //   generated [SP800-56A, Section 5.3].
    

    // C7 SKCFRM || SKMAC || SKENC || SKRMAC = KDF (Z, len, Otherinfo)
    // - Compute the key confirmation key and the session keys. See Section 4.1.6.

    // C8 Zeroize Z
    // - Destroy shared secret generated in Step C5.

    // C9 AuthCryptogramICC = CMAC(SKCFRM, "KC_1_V" || IDsICC || IDsH || QeH)
    // - Compute the authentication cryptogram for key confirmation as described in Section 4.1.7.

    // C10 Zeroize SKCFRM
    // - Destroy the key confirmation key derived in Step C7.

    // C11 Return CBICC || NICC || AuthCryptogramICC || CICC
      	
      	
      }


  /**
   * Performs an ECDH key agreement
   *
   * @param inBuffer the public key of the other party
   * @param inOffset the the location of first byte of the public key
   * @param inLength the length of the public key
   * @param outBuffer the computed secret
   * @param outOffset the location of the first byte of the computed secret
   * @return the length of the computed secret
   */
  @Override
  public short keyAgreement(
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    if (inLength != marshaledPubKeyLen) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    keyAgreement.init(privateKey);
    return keyAgreement.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param csp the csp that does the signing.
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length of the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  @Override
  public short sign(
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
      	
      Signature signer = null;
      
      switch (inLength) {
        case MessageDigest.LENGTH_SHA:
          signer = signerSHA1;
          break;
        case MessageDigest.LENGTH_SHA_256:
          signer = signerSHA256;
          break;
        case MessageDigest.LENGTH_SHA_384:
          signer = signerSHA384;
          break;
        case MessageDigest.LENGTH_SHA_512:
          signer = signerSHA512;
          break;
        default:
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return (short)0; // Keep compiler happy
      }
      	
    signer.init(privateKey, Signature.MODE_SIGN);
    return signer.signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }
}
