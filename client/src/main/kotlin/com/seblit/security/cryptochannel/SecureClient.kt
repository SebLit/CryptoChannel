package com.seblit.security.cryptochannel

import java.io.InputStream
import java.io.OutputStream
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream

/**
 * Provides Client sided up- and download and streaming functionality according to [SecureEndpoint]
 * */
class SecureClient(
    curve: String =
        DEFAULT_CURVE,
    random: SecureRandom = SecureRandom(),
    ivLength: Int = DEFAULT_IV_LENGTH,
    tagLength: Int = DEFAULT_TAG_LENGTH
) : SecureEndpoint(curve, random, ivLength, tagLength) {

    /**
     * Decrypts data received in a DownloadResponse. Server must perform the ECDH handshake according to [SecureEndpoint]
     * @param download Performs the data request and transmits the clients public key to the server.
     * Receives and returns the encrypted response
     * @return the decrypted data
     * */
    fun decryptDownload(download: (pubKey: PublicKey) -> DownloadResponse<ByteArray>): ByteArray {
        val decryptInfo = initDecrypt(download)
        return decryptInfo.cipher.doFinal(decryptInfo.encPayload)
    }

    /**
     * Decrypts an InputStream received in a DownloadResponse. Server must perform the ECDH handshake according to [SecureEndpoint]
     * @param downstream Performs the data request and transmits the clients public key to the server.
     * Provides an InputStream to the encrypted response
     * @return an InputStream that reads the decrypted data
     * */
    fun decryptDownstream(downstream: (pubKey: PublicKey) -> DownloadResponse<InputStream>): InputStream {
        val decryptInfo = initDecrypt(downstream)
        return CipherInputStream(decryptInfo.encPayload, decryptInfo.cipher)
    }

    /**
     * Encrypts data and uploads them to a Server.
     * Upload consists of two requests. First the ECDH handshake takes place according to [SecureEndpoint].
     * Second the data will be encrypted and uploaded together with the session id received during the handshake
     * @param I Datatype of the session id
     * @param keyExchange Uploads the Clients public key to the Server and retrieves the session id
     * @param upload Uploads the encrypted data together with the session id to the Server
     * */
    fun <I> encryptUpload(
        data: ByteArray,
        keyExchange: (pubKey: PublicKey) -> UploadInitResponse<I>,
        upload: (request: UploadRequest<I>, encryptedData: ByteArray) -> Unit
    ) {
        val encryptInfo = initEncrypt(keyExchange)
        val encryptedData = encryptInfo.cipher.doFinal(data)
        upload(UploadRequest(encryptInfo.tagLength, encryptInfo.iv, encryptInfo.sessionId), encryptedData)
    }

    /**
     * Provides an encrypted OutputStream to stream data to a Server.
     * Upstream consists of two requests. First the ECDH handshake takes place according to [SecureEndpoint].
     * Second the OutputStream to the Server will be established and encrypted
     * @param I Datatype of the session id
     * @param keyExchange Uploads the Clients public key to the Server and retrieves the session id
     * @param initUpstream Uploads the sessionId to the server and opens an OutputStream to the connection
     * @return an encrypted OutputStream which writes data to the Server
     * */
    fun <I> encryptUpstream(
        keyExchange: (pubKey: PublicKey) -> UploadInitResponse<I>,
        initUpstream: (UploadRequest<I>) -> OutputStream
    ): OutputStream {
        val encryptInfo = initEncrypt(keyExchange)
        val target = initUpstream(UploadRequest(encryptInfo.tagLength, encryptInfo.iv, encryptInfo.sessionId))
        return CipherOutputStream(target, encryptInfo.cipher)
    }

    private fun <T> initDecrypt(loader: (pubKey: PublicKey) -> DownloadResponse<T>): DecryptInfo<T> {
        val keyPair = newKeypair()
        val response = loader(keyPair.public)
        val cipher = createCipher(
            true,
            response.tagLength,
            response.iv,
            deriveAesKey(keyPair.private, response.pubKey, response.secretSalt)
        )
        return DecryptInfo(response.encData, cipher)
    }

    private fun <I> initEncrypt(keyExchange: (pubKey: PublicKey) -> UploadInitResponse<I>): EncryptInfo<I> {
        val keyPair = newKeypair()
        val uploadResponse = keyExchange(keyPair.public)
        val iv = generateBytes(ivLength)
        val cipher = createCipher(
            false,
            tagLength,
            iv,
            deriveAesKey(keyPair.private, uploadResponse.pubKey, uploadResponse.secretSalt)
        )
        return EncryptInfo(iv, tagLength, uploadResponse.sessionId, cipher)
    }

    private data class EncryptInfo<I>(
        val iv: ByteArray,
        val tagLength: Int,
        val sessionId: I,
        val cipher: Cipher
    )

    private data class DecryptInfo<T>(
        val encPayload: T,
        val cipher: Cipher
    )


}