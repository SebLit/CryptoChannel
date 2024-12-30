package com.seblit.security.cryptochannel

import java.io.InputStream
import java.io.OutputStream
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream

/**
 * Provides Server sided up- and download and streaming functionality according to [SecureEndpoint]
 * @param sessionManager The SessionManager that is used to store upload and upstream sessions between the requests
 * @param saltLength The length of the Salt used when creating the AES key during handshake
 * @param I The type for session ids
 * */
class SecureServer<I>(
    private val sessionManager: SessionManager<I>,
    curve: String =
        DEFAULT_CURVE,
    ivGenerator: SecureRandom = SecureRandom(),
    ivLength: Int = DEFAULT_IV_LENGTH,
    tagLength: Int = DEFAULT_TAG_LENGTH,
    private val saltLength: Int = DEFAULT_SALT_LENGTH
) : SecureEndpoint(curve, ivGenerator, ivLength, tagLength) {

    companion object {
        /**
         * Salt length used if no other was specified at initialization: 256-bit
         * */
        const val DEFAULT_SALT_LENGTH = 256
    }

    /**
     * Encrypts data and creates a DownloadResponse. Client must perform the ECDH handshake according to [SecureEndpoint]
     * @param data The data that should be encrypted
     * @param partnerKey The Client's public key transmitted in the request
     * @return a DownloadResponse containing all information that must be transmitted to the client for decryption
     * */
    fun encryptDownload(
        data: ByteArray,
        partnerKey: PublicKey,
    ): DownloadResponse<ByteArray> {
        val keyPair = newKeypair()
        val secretSalt = generateBytes(saltLength)
        val aesKey = deriveAesKey(keyPair.private, partnerKey, secretSalt)
        val iv = generateBytes(ivLength)
        val cipher = createCipher(false, tagLength, iv, aesKey)
        val encData = cipher.doFinal(data)
        return DownloadResponse(iv, tagLength, keyPair.public, secretSalt, encData)
    }

    /**
     * Encrypts an OutputStream and creates a DownloadResponse. Client must perform the ECDH handshake according to [SecureEndpoint]
     * @param target A OutputStream to the connection of the request
     * @param partnerKey The Client's public key transmitted in the request
     * @return a DownloadResponse containing all information that must be transmitted to the client for decryption
     * and an OutputStream, that will encrypt and send all data written to it
     * */
    fun encryptDownstream(
        target: OutputStream,
        partnerKey: PublicKey
    ): DownloadResponse<OutputStream> {
        val keyPair = newKeypair()
        val secretSalt = generateBytes(saltLength)
        val aesKey = deriveAesKey(keyPair.private, partnerKey, secretSalt)
        val iv = generateBytes(ivLength)
        val cipher = createCipher(false, tagLength, iv, aesKey)
        return DownloadResponse(iv, tagLength, keyPair.public, secretSalt, CipherOutputStream(target, cipher))
    }

    /**
     * Initializes an AES Session in response to a clients upload or upstream request. Client must perform the ECDH handshake according to [SecureEndpoint].
     * Derives the AES key and stores it via its [SessionManager].
     * @param partnerKey The Client's public key
     * @return an UploadInitResponse containing all information that must be transferred back to the Client
     */
    fun initializeAESSession(partnerKey: PublicKey): UploadInitResponse<I> {
        val keyPair = newKeypair()
        val secretSalt = generateBytes(saltLength)
        val aesKey = deriveAesKey(keyPair.private, partnerKey, secretSalt)
        val sessionId = sessionManager.storeSession(aesKey)
        return UploadInitResponse(keyPair.public, secretSalt, sessionId)
    }

    /**
     * Decrypts the received data. Client must perform the ECDH handshake according to [SecureEndpoint].
     * @param request Encryption information provided by the Client
     * @param encryptedData The received encrypted data
     * @return The decrypted data
     * */
    fun decryptUpload(request: UploadRequest<I>, encryptedData: ByteArray): ByteArray {
        return secureUp(request, encryptedData) { cipher, input -> cipher.doFinal(input) }
    }

    /**
     * Decrypts an InputStream. Client must perform the ECDH handshake according to [SecureEndpoint].
     * @param request Encryption information provided in the request
     * @param source The InputStream that reads the encrypted data
     * @return An InputStream that reads the decrypted data
     * */
    fun decryptUpstream(request: UploadRequest<I>, source: InputStream): InputStream {
        return secureUp(request, source) { cipher, input -> CipherInputStream(input, cipher) }
    }

    private fun <T> secureUp(request: UploadRequest<I>, input: T, transformer: (Cipher, T) -> T): T {
        val aesKey = sessionManager.loadSession(request.sessionId)
        val cipher = createCipher(true, tagLength, request.iv, aesKey)
        return transformer(cipher, input)
    }

    /**
     * Manages AES Sessions for uploads and upstreams
     * @param I The type for session ids
     * @see decryptUpload
     * @see decryptUpstream
     * */
    interface SessionManager<I> {
        /**
         * Stores the provided key and generates a unique session id that can later be used to retrieve the key
         * @param aesKey The AES key that must be stored
         * @return the session id linking to the stored key
         * */
        fun storeSession(aesKey: ByteArray): I

        /**
         * Loads and removes a key from storage for a given session id
         * @param sessionId The session id linked to the AES key
         * @return the AES key that was previously stored
         * */
        fun loadSession(sessionId: I): ByteArray
    }

}