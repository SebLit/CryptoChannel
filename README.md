# CryptoChannel

This library provides encryption wrappers for Server-Client communication.  
A shared secret is established via ECDH, based of which further traffic is encrypted
using AES GCM.

## SecureEndpoint

Provides the common handshake and cryptography logic required for Client and Server

* EC key generation
* ECDH secret generation
* AES key derivation
* AES GCM encryption
* Nonce generation
* Data API for up- and downloads

## SecureClient

Used to wrap Client requests into an encrypted channel. Supports Up- and Downloads and Streaming

### Example for downloads
~~~
val secClient = SecureClient()
val decryptedData = secClient.decryptDownload { pubKey ->
            val response = <perform request to Server>
            SecureEndpoint.DownloadResponse(
                response.iv, response.tagLength, response.pubKey,
                response.salt, response.encData
            )
        }
        
val decryptStream = client.decryptDownstream { pubKey ->
            val response = <perform request to Server>
            SecureEndpoint.DownloadResponse(
                response.iv, response.tagLength, response.pubKey,
                response.salt, response.downStream
            )
        }
~~~

### Example for uploads
Uploads consist of two steps, key exchange and data upload. During key exchange the Server 
generates a session id that needs to be sent along the data upload

~~~
val secClient = SecureClient()
secClient.encryptUpload(DATA, { pubKey ->
            val response = <perform init upload request with pubKey to Server>
            SecureEndpoint.UploadInitResponse(response.pubKey, response.salt, response.sessionId)
        }, { request, encryptedData ->
            <perform upload with request information and encrypted data to Server>
        })
        
val stream = secClient.encryptUpstream({ pubKey ->
             val response = <perform init upload request with pubKey to Server>
            SecureEndpoint.UploadInitResponse(response.pubKey, response.salt, response.sessionId)
       }, { uploadRequest ->
            <produce OutputStream to Server through request with uploadRequest information>
        })
<write unencrypted data to stream>
~~~



## SecureServer
Used to wrap Server responses into an encrypted channel. Supports Up- and Downloads and Streaming

### Example for downloads
~~~
val secServer = SecureServer()
val response = secServer.encryptDownload(<rawData>, request.clientPubKey)
<respond with encryption information and encrypted data>

val streamedResponse = server.encryptDownstream(request.OutputStream, request.clientPubKey)
<respond with encryption information>
<write raw data to OutputStream streamedResponse.encData>
~~~

### Example for uploads
Uploads consist of two steps, key exchange and data upload. For this reason, 
the key needs to be stored in between requests for the current upload session. 
For this a SessionManager must be implemented and passed to the SecureServer. 
The first request delivers the Client's public key, which must be used to initialize the session. 
The initialization result then must be sent back to the Client as part of the response

~~~
val secServer = SecureServer(sessionManager)
val initResult = secServer.initializeAESSession(pubKey)
<respond to Client with initResult>
~~~

With the second step, the Client uploads or upstreams the encrypted data and 
session information to the Server, where it must be decrypted

~~~
  val decryptedData = secServer.decryptUpload(request.info, request.encData)
  
  val decryptStream = secServer.decryptUpstream(request.info, request.InputStream)
  <read decrypted data from decryptStream>
~~~