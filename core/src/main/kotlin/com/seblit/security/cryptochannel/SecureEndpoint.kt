package com.seblit.security.cryptochannel

import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Provides basic functionality for a secure e2e channel.<br>
 * To establish a secure shared secret, ECDH is used. After the secret is established, a
 * 256-bit AES key is derived by using SHA-256 to hash the salted secret. E2E encryption utilizes
 * AES with GCM mode
 * @param curve The curve used for ECDH
 * @param random The SecureRandom used for EC key generation and generating nonces
 * @param ivLength The length for IVs that may be generated
 * @param tagLength The length of GCM tags
 * */
open class SecureEndpoint(
    curve: String = DEFAULT_CURVE,
    private val random: SecureRandom = SecureRandom(),
    protected val ivLength: Int = DEFAULT_IV_LENGTH,
    protected val tagLength: Int = DEFAULT_TAG_LENGTH,
) {

    companion object {
        /**
         * Curve used if no other was specified at initialization: secp256r1
         * */
        const val DEFAULT_CURVE = "secp256r1"

        /**
         * IV length used if no other was specified at initialization: 96-bit
         * */
        const val DEFAULT_IV_LENGTH = 96

        /**
         * Tag length used if no other was specified at initialization: 128-bit
         * */
        const val DEFAULT_TAG_LENGTH = 128

        /**
         * AES transformation used for AES encryption: AES/GCM/NoPadding
         * */
        const val AES_TRANSFORMATION = "AES/GCM/NoPadding"

        /**
         * Hash algorithm used for nonce generation: SHA-256
         * */
        const val HASH_ALGORITHM = "SHA-256"

        /**
         * Key agreement algorithm used for secret generation: ECDH
         * */
        const val KEY_AGREEMENT = "ECDH"
        private const val AES_ALGORITHM = "AES"
        private const val EC_ALGORITHM = "EC"
    }

    private val generator = KeyPairGenerator.getInstance(EC_ALGORITHM)
    private val secretDigest = MessageDigest.getInstance(HASH_ALGORITHM)

    init {
        generator.initialize(ECGenParameterSpec(curve), random)
    }

    /**
     * Generates a new EC KeyPair
     * @return the generated keys
     * */
    protected fun newKeypair(): KeyPair {
        return generator.generateKeyPair()
    }

    /**
     * Generates a new randomized ByteArray of given length. Uses the SecureRandom
     * that was provided at initialization to populate the array
     * @return the generated keys
     * @param length the desired length
     * */
    protected fun generateBytes(length: Int): ByteArray {
        return ByteArray(length).apply { random.nextBytes(this) }
    }

    /**
     * Hashes the input using [HASH_ALGORITHM]
     * @param data The data that should be hashed
     * @return the resulting hash
     * */
    protected fun hash(data: ByteArray): ByteArray {
        return secretDigest.digest(data)
    }

    /**
     * Generates a shared secret between the provided keys using [KEY_AGREEMENT]. Then prepends it
     * with the given salt and hashes it to produce a 256-bit AES key
     * @param myKey This endpoints private key
     * @param partnerKey The partners public key
     * @param secretSalt The salt used for hashing
     * @return the resulting 256-bit AES key
     * @see hash
     * */
    protected fun deriveAesKey(myKey: PrivateKey, partnerKey: PublicKey, secretSalt: ByteArray): ByteArray {
        val agreement = KeyAgreement.getInstance(KEY_AGREEMENT)
        agreement.init(myKey)
        agreement.doPhase(partnerKey, true)
        val secret = agreement.generateSecret()
        return hash(secretSalt + secret)
    }

    /**
     * Creates and initializes a Cipher for AES de- or encryption. The cipher uses the [AES_TRANSFORMATION]
     * @param isDecrypt Whether the Cipher is used for de- or encryption
     * @param tagLength The GCM tag length
     * @param iv The IV
     * @param aesKey The raw AES key which is used to initialize the [SecretKeySpec] for AES
     * @return the initialized Cipher
     * */
    protected fun createCipher(isDecrypt: Boolean, tagLength: Int, iv: ByteArray, aesKey: ByteArray): Cipher {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(tagLength, iv)
        val mode = if (isDecrypt) Cipher.DECRYPT_MODE else Cipher.ENCRYPT_MODE
        cipher.init(mode, SecretKeySpec(aesKey, AES_ALGORITHM), gcmSpec)
        return cipher;
    }

    /**
     * Response sent by a Server to perform key exchange before data upload from the client
     * @property pubKey The Servers public key
     * @property secretSalt The salt that was used by the Server to generate the AES key
     * @property sessionId The session id created by the Server that the Client uses to link the following
     * upload request to this key exchange
     * @see deriveAesKey
     * @see UploadRequest
     * */
    data class UploadInitResponse<I>(
        val pubKey: PublicKey,
        val secretSalt: ByteArray,
        val sessionId: I
    )

    /**
     * Response sent by a Server to download data to the client
     * @property iv The IV used by the server during encryption
     * @property tagLength The GCM tag length used by the server during encryption
     * @property pubKey The Servers public key
     * @property secretSalt The salt that was used by the Server to generate the AES key
     * @property encData The source the encrypted data that should be downloaded to the client
     * */
    data class DownloadResponse<T>(
        val iv: ByteArray,
        val tagLength: Int,
        val pubKey: PublicKey,
        val secretSalt: ByteArray,
        val encData: T
    )

    /**
     * Request sent by a Client when uploading data to a Server
     * @property tagLength The GCM tag length used by the client during encryption
     * @property iv The IV used by the client during encryption
     * @property sessionId The session id that was previously provided by the server during key exchange
     * @see UploadInitResponse
     * */
    data class UploadRequest<I>(
        val tagLength: Int,
        val iv: ByteArray,
        val sessionId: I
    )

}