package app.bb.ssh

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.webkit.CookieManager
import android.webkit.ValueCallback
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import net.schmizz.keepalive.KeepAliveProvider
import net.schmizz.keepalive.KeepAliveRunner
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.transport.DisconnectListener
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.password.PasswordUtils
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Provider
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class OpenOptions : Record {
  @Field var attemptId: String = ""
  @Field var hostname: String = ""
  @Field var port: Int = 22
  @Field var username: String = ""
  @Field var keyRef: String = ""
  @Field var passphrase: String? = null
  @Field var hostKey: String? = null
  @Field var localHost: String = ""
  @Field var remoteHost: String = ""
  @Field var remotePort: Int = 0
}

class BbSshModule : Module() {
  private class SshCryptoProvider : Provider("BBSSHBC", 1.0, "BB SSH cryptography") {
    init { putAll(BouncyCastleProvider()) }
  }

  init {
    synchronized(BbSshModule::class.java) {
      if (Security.getProvider("BBSSHBC") == null) Security.addProvider(SshCryptoProvider())
      SecurityUtils.setRegisterBouncyCastle(false)
      SecurityUtils.setSecurityProvider("BBSSHBC")
    }
  }

  private class Attempt(val id: String, val promise: Promise, val passphrase: CharArray?, val localHost: String) {
    val tunnelId = UUID.randomUUID().toString()
    val secret = newSecret()
    val client = SSHClient(DefaultConfig().apply { keepAliveProvider = KeepAliveProvider.KEEP_ALIVE })
    val cancelled = AtomicBoolean(false)
    val closed = AtomicBoolean(false)
    val settled = AtomicBoolean(false)
    val trust = CompletableFuture<Boolean>()
    @Volatile var socket: ServerSocket? = null
    @Volatile var verifiedKey: String? = null
    @Volatile var hostKeyChanged = false
    @Volatile var hostKeyRejected = false
    @Volatile var deadline: ScheduledFuture<*>? = null
    @Volatile var cookieSet = false
    @Volatile var boundNetwork: Network? = null
    @Volatile var networkCallback: ConnectivityManager.NetworkCallback? = null
  }

  private val lock = Any()
  private val workers = Executors.newCachedThreadPool()
  private val cleanup = Executors.newCachedThreadPool()
  private val deadlines = Executors.newSingleThreadScheduledExecutor()
  private var current: Attempt? = null
  private var destroyed = false

  override fun definition() = ModuleDefinition {
    Name("BbSsh")
    Events("onState", "onHostKey", "onClosed")

    AsyncFunction("importKey") { privateKey: String ->
      val bytes = privateKey.toByteArray(Charsets.UTF_8)
      require(bytes.isNotEmpty() && bytes.size <= 65536) { "Private key must be at most 64 KiB" }
      val ref = UUID.randomUUID().toString()
      try {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, storageKey())
        keyFile(ref).writeBytes(cipher.iv + cipher.doFinal(bytes))
        ref
      } finally {
        bytes.fill(0)
      }
    }
    AsyncFunction("deleteKey") { keyRef: String ->
      val file = keyFile(keyRef)
      check(!file.exists() || file.delete()) { "Unable to delete private key" }
    }
    AsyncFunction("open") { options: OpenOptions, promise: Promise ->
      try {
        validate(options)
        val attempt = synchronized(lock) {
          check(!destroyed) { "SSH module is closed" }
          current?.let { stop(it, "Connection replaced") }
          Attempt(options.attemptId, promise, options.passphrase?.toCharArray(), options.localHost).also { current = it }
        }
        options.passphrase = null
        deadline(attempt, "SSH DNS resolution or connection timed out")
        workers.execute { connect(attempt, options, promise) }
      } catch (error: Exception) {
        promise.reject("SSH_OPEN_FAILED", "Unable to start SSH connection", null)
      }
    }
    AsyncFunction("confirmHostKey") { attemptId: String, accept: Boolean ->
      synchronized(lock) { current?.takeIf { it.id == attemptId } }?.trust?.complete(accept)
      Unit
    }
    AsyncFunction("restoreCookie") { tunnelId: String ->
      val attempt = synchronized(lock) { current?.takeIf { it.tunnelId == tunnelId && !it.cancelled.get() } }
      if (attempt != null) writeCookie(attempt.localHost, "$COOKIE_NAME=${attempt.secret}; Path=/; HttpOnly")
    }
    AsyncFunction("cancel") { attemptId: String ->
      synchronized(lock) {
        current?.takeIf { it.id == attemptId }?.let { stop(it, "Connection cancelled"); current = null }
      }
    }
    AsyncFunction("close") { tunnelId: String ->
      synchronized(lock) {
        current?.takeIf { it.tunnelId == tunnelId }?.let { stop(it, "Connection closed"); current = null }
      }
    }
    OnActivityEntersBackground {
      synchronized(lock) {
        current?.let { stop(it, "Connection closed while app is in background"); current = null }
      }
    }
    OnDestroy {
      synchronized(lock) {
        destroyed = true
        current?.let { stop(it, "Connection closed") }
        current = null
      }
      workers.shutdownNow()
      deadlines.shutdownNow()
      cleanup.shutdown()
    }
  }

  private fun validate(options: OpenOptions) {
    require(options.attemptId.isNotBlank() && options.attemptId.length <= 128)
    require(validHostname(options.hostname))
    require(options.username.isNotBlank() && options.username.length <= 256 && options.username.none { it.isISOControl() })
    require(validHostname(options.remoteHost))
    require(options.port in 1..65535 && options.remotePort in 1..65535)
    val octets = options.localHost.split('.').map { it.toIntOrNull() }
    require(octets.size == 4 && octets.all { it != null && it in 0..255 })
    val address = octets.map { it!! }
    require(address[0] == 127)
    val suffix = (address[1] shl 16) or (address[2] shl 8) or address[3]
    require(suffix in 0x400000..0x7fffff && options.localHost == address.joinToString("."))
    require(options.hostKey == null || options.hostKey!!.length <= 16384)
    require(options.passphrase == null || options.passphrase!!.length <= 65536)
    keyFile(options.keyRef)
  }

  private fun validHostname(host: String): Boolean {
    if (host.isEmpty() || host.length > 253) return false
    if (host.contains(':')) return host.matches(Regex("[0-9a-fA-F:.]+")) && host.count { it == ':' } >= 2
    return host.removeSuffix(".").split('.').all {
      it.length in 1..63 && it.matches(Regex("[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"))
    }
  }

  private fun deadline(attempt: Attempt, message: String) {
    synchronized(attempt) {
      attempt.deadline?.cancel(false)
      if (!attempt.cancelled.get()) attempt.deadline = deadlines.schedule({ stop(attempt, message, "SSH_TIMEOUT") }, 15, TimeUnit.SECONDS)
    }
  }

  private fun connect(attempt: Attempt, options: OpenOptions, promise: Promise) {
    var stage = "connect"
    try {
      state(attempt, "connecting")
      attempt.client.connectTimeout = 15000
      attempt.client.timeout = 90000
      attempt.client.transport.timeoutMs = 90000
      val keepAlive = attempt.client.connection.keepAlive
      keepAlive.keepAliveInterval = KEEP_ALIVE_INTERVAL_SECONDS
      (keepAlive as? KeepAliveRunner)?.maxAliveCount = KEEP_ALIVE_MAX_MISSED
      attempt.client.addHostKeyVerifier(object : HostKeyVerifier {
        override fun findExistingAlgorithms(hostname: String, port: Int): List<String> =
          options.hostKey?.let { listOf(it.substringBefore(' ')) } ?: emptyList()

        override fun verify(hostname: String, port: Int, key: PublicKey): Boolean {
          val bytes = Buffer.PlainBuffer().putPublicKey(key).compactData
          val algorithm = Buffer.PlainBuffer(bytes).readString()
          val encoded = "$algorithm ${Base64.encodeToString(bytes, Base64.NO_WRAP)}"
          val fingerprint = "SHA256:" + Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes), Base64.NO_WRAP or Base64.NO_PADDING)
          if (attempt.cancelled.get()) return false
          (attempt.verifiedKey ?: options.hostKey)?.let {
            if (it != encoded) {
              attempt.hostKeyChanged = true
              sendEvent("onHostKey", mapOf("attemptId" to attempt.id, "hostKey" to encoded, "fingerprint" to fingerprint, "changed" to true))
              stop(attempt, "SSH host key changed. Remove this host and add it again only after verifying its new key", "SSH_HOST_KEY_CHANGED")
              return false
            }
            attempt.verifiedKey = encoded
            return true
          }
          synchronized(attempt) { attempt.deadline?.cancel(false) }
          state(attempt, "awaitingHostKey")
          sendEvent("onHostKey", mapOf("attemptId" to attempt.id, "hostKey" to encoded, "fingerprint" to fingerprint, "changed" to false))
          val accepted = try { attempt.trust.get(60, TimeUnit.SECONDS) } catch (_: Exception) { false }
          if (!accepted && !attempt.cancelled.get()) attempt.hostKeyRejected = true
          if (accepted && !attempt.cancelled.get()) {
            attempt.verifiedKey = encoded
            deadline(attempt, "SSH key exchange timed out")
          }
          return accepted && !attempt.cancelled.get()
        }
      })
      checkActive(attempt)
      attempt.client.connect(options.hostname, options.port)
      checkActive(attempt)
      stage = "authenticate"
      deadline(attempt, "SSH authentication timed out")
      attempt.client.transport.timeoutMs = 15000
      state(attempt, "authenticating")
      val bytes = readKey(options.keyRef)
      val passphrase = attempt.passphrase?.clone()
      try {
        val provider = attempt.client.loadKeys(String(bytes, Charsets.UTF_8), null, passphrase?.let { PasswordUtils.createOneOff(it) })
        attempt.client.authPublickey(options.username, provider)
      } finally {
        bytes.fill(0)
        passphrase?.fill('\u0000')
        attempt.passphrase?.fill('\u0000')
        options.passphrase = null
      }
      checkActive(attempt)
      stage = "forward"
      deadline(attempt, "SSH forwarding timed out")
      attempt.client.newDirectConnection(options.remoteHost, options.remotePort).use { }
      val socket = ServerSocket()
      attempt.socket = socket
      socket.bind(InetSocketAddress(InetAddress.getByName(options.localHost), 38886))
      val forwarder = AuthenticatedForwarder(attempt.client, socket, options.remoteHost, options.remotePort, attempt.secret, workers)
      checkActive(attempt)
      attempt.cookieSet = true
      writeCookie(options.localHost, "$COOKIE_NAME=${attempt.secret}; Path=/; HttpOnly")
      synchronized(lock) {
        checkActive(attempt)
        synchronized(attempt) { attempt.deadline?.cancel(false) }
        attempt.client.socket.soTimeout = 0
        attempt.client.transport.setDisconnectListener(DisconnectListener { _, _ -> stop(attempt, "SSH connection closed") })
        watchNetwork(attempt)
        state(attempt, "connected")
        if (attempt.settled.compareAndSet(false, true)) {
          promise.resolve(mapOf(
            "tunnelId" to attempt.tunnelId,
            "serverUrl" to "http://${options.localHost}:${socket.localPort}",
            "tunnelSecret" to attempt.secret,
          ))
        }
      }
      workers.execute {
        try { forwarder.listen() } catch (_: Exception) { } finally { stop(attempt, "SSH connection closed") }
      }
    } catch (error: Exception) {
      val message = when {
        attempt.hostKeyChanged -> "SSH host key changed"
        attempt.hostKeyRejected -> "SSH host key was rejected or trust confirmation timed out"
        attempt.cancelled.get() -> "Connection cancelled"
        stage == "authenticate" -> "Private key or passphrase rejected, or SSH authentication failed"
        stage == "forward" -> "SSH forwarding was denied, remote server is unavailable, or local port 38886 is busy"
        else -> "SSH connection failed"
      }
      val code = when {
        attempt.hostKeyChanged -> "SSH_HOST_KEY_CHANGED"
        attempt.hostKeyRejected -> "SSH_HOST_KEY_REJECTED"
        stage == "authenticate" -> "SSH_AUTH_FAILED"
        else -> "SSH_OPEN_FAILED"
      }
      stop(attempt, message, code)
    } finally {
      options.passphrase = null
      attempt.passphrase?.fill('\u0000')
    }
  }

  private fun connectivity(): ConnectivityManager? =
    appContext.reactContext?.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

  private fun watchNetwork(attempt: Attempt) {
    val manager = connectivity() ?: return
    val callback = object : ConnectivityManager.NetworkCallback() {
      override fun onAvailable(network: Network) {
        val bound = attempt.boundNetwork
        if (bound == null) attempt.boundNetwork = network
        else if (bound != network) stop(attempt, "Network changed")
      }

      override fun onLost(network: Network) {
        if (network == attempt.boundNetwork) stop(attempt, "Network lost")
      }
    }
    attempt.networkCallback = callback
    manager.registerDefaultNetworkCallback(callback)
  }

  private fun writeCookie(localHost: String, value: String) {
    val latch = CountDownLatch(1)
    val stored = AtomicBoolean(false)
    Handler(Looper.getMainLooper()).post {
      try {
        val manager = CookieManager.getInstance()
        manager.setAcceptCookie(true)
        manager.setCookie("http://$localHost/", value, ValueCallback<Boolean> { result ->
          stored.set(result == true)
          manager.flush()
          latch.countDown()
        })
      } catch (_: Exception) {
        latch.countDown()
      }
    }
    check(latch.await(5, TimeUnit.SECONDS) && stored.get()) { "Unable to store the tunnel cookie" }
  }

  private fun removeCookie(localHost: String) {
    Handler(Looper.getMainLooper()).post {
      runCatching {
        val manager = CookieManager.getInstance()
        manager.setCookie("http://$localHost/", "$COOKIE_NAME=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT", null)
        manager.flush()
      }
    }
  }

  private fun checkActive(attempt: Attempt) {
    check(!attempt.cancelled.get()) { "Connection cancelled" }
  }

  private fun state(attempt: Attempt, state: String) {
    if (!attempt.cancelled.get()) sendEvent("onState", mapOf("attemptId" to attempt.id, "state" to state))
  }

  private fun stop(attempt: Attempt, message: String, code: String = "SSH_OPEN_FAILED") {
    attempt.cancelled.set(true)
    attempt.passphrase?.fill('\u0000')
    attempt.trust.complete(false)
    synchronized(attempt) { attempt.deadline?.cancel(false) }
    attempt.networkCallback?.let { callback ->
      attempt.networkCallback = null
      runCatching { connectivity()?.unregisterNetworkCallback(callback) }
    }
    if (attempt.cookieSet) {
      attempt.cookieSet = false
      removeCookie(attempt.localHost)
    }
    runCatching { attempt.socket?.close() }
    runCatching { attempt.client.socket?.close() }
    runCatching { cleanup.execute { runCatching { attempt.client.close() } } }
    if (attempt.settled.compareAndSet(false, true)) attempt.promise.reject(code, message, null)
    if (attempt.closed.compareAndSet(false, true)) sendEvent("onClosed", mapOf("attemptId" to attempt.id, "message" to message, "code" to code))
  }

  private fun keyFile(ref: String): File {
    require(runCatching { UUID.fromString(ref).toString() == ref }.getOrDefault(false)) { "Invalid key reference" }
    val context = requireNotNull(appContext.reactContext)
    val directory = File(context.noBackupFilesDir, "bb-ssh-keys")
    check(directory.isDirectory || directory.mkdirs())
    return File(directory, ref)
  }

  private fun storageKey(): SecretKey = synchronized(lock) {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "bb-ssh-private-keys-v1"
    (store.getKey(alias, null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
      init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .build())
    }.generateKey()
  }

  private fun readKey(ref: String): ByteArray {
    val file = keyFile(ref)
    require(file.length() in 29..65564) { "Invalid stored private key" }
    val encrypted = file.readBytes()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(128, encrypted.copyOfRange(0, 12)))
    return cipher.doFinal(encrypted, 12, encrypted.size - 12)
  }

  private companion object {
    const val COOKIE_NAME = AuthenticatedForwarder.COOKIE_NAME
    const val KEEP_ALIVE_INTERVAL_SECONDS = 15
    const val KEEP_ALIVE_MAX_MISSED = 3
    val random = SecureRandom()

    fun newSecret(): String {
      val bytes = ByteArray(32)
      random.nextBytes(bytes)
      return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
  }
}
