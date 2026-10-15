package app.bb.ssh

import net.schmizz.sshj.SSHClient
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.Executor
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicInteger

class AuthenticatedForwarder(
  private val client: SSHClient,
  private val server: ServerSocket,
  private val remoteHost: String,
  private val remotePort: Int,
  secret: String,
  private val executor: Executor,
) {
  private val expected = secret.toByteArray(Charsets.UTF_8)
  private val pending = Semaphore(MAX_PENDING)

  fun listen() {
    while (!server.isClosed) {
      val socket = server.accept()
      if (!pending.tryAcquire()) {
        closeQuietly(socket)
        continue
      }
      try {
        executor.execute { handle(socket) }
      } catch (error: Exception) {
        pending.release()
        closeQuietly(socket)
      }
    }
  }

  private fun handle(socket: Socket) {
    var permitHeld = true
    try {
      socket.tcpNoDelay = true
      val head = readAuthorizedHead(socket)
      pending.release()
      permitHeld = false
      if (head == null) {
        closeQuietly(socket)
        return
      }
      socket.soTimeout = 0
      val channel = client.newDirectConnection(remoteHost, remotePort)
      val remoteOut = channel.outputStream
      val remoteIn = channel.inputStream
      val localIn = socket.getInputStream()
      val localOut = socket.getOutputStream()
      remoteOut.write(head)
      remoteOut.flush()
      val open = AtomicInteger(2)
      val finish = {
        if (open.decrementAndGet() == 0) {
          closeQuietly(channel)
          closeQuietly(socket)
        }
      }
      executor.execute {
        try {
          copy(localIn, remoteOut)
          runCatching { remoteOut.close() }
        } catch (_: Exception) {
          closeQuietly(channel)
          closeQuietly(socket)
        } finally {
          finish()
        }
      }
      try {
        copy(remoteIn, localOut)
      } catch (_: Exception) {
      } finally {
        closeQuietly(channel)
        closeQuietly(socket)
        finish()
      }
    } catch (error: Exception) {
      closeQuietly(socket)
    } finally {
      if (permitHeld) pending.release()
    }
  }

  private fun readAuthorizedHead(socket: Socket): ByteArray? {
    val input = socket.getInputStream()
    val buffer = ByteArray(MAX_HEAD)
    var length = 0
    val deadline = System.nanoTime() + HEAD_TIMEOUT_MS * 1_000_000L
    var end = -1
    while (end < 0) {
      val remaining = (deadline - System.nanoTime()) / 1_000_000L
      if (remaining <= 0 || length == buffer.size) return null
      socket.soTimeout = remaining.toInt()
      val read = try { input.read(buffer, length, buffer.size - length) } catch (_: Exception) { return null }
      if (read < 0) return null
      val from = maxOf(0, length - 3)
      length += read
      end = indexOfHeadEnd(buffer, from, length)
    }
    val text = String(buffer, 0, end, Charsets.ISO_8859_1)
    return if (carriesSecret(text)) buffer.copyOf(length) else null
  }

  private fun indexOfHeadEnd(buffer: ByteArray, from: Int, length: Int): Int {
    var index = from
    while (index + 3 < length) {
      if (buffer[index] == CR && buffer[index + 1] == LF && buffer[index + 2] == CR && buffer[index + 3] == LF) return index
      index++
    }
    return -1
  }

  private fun carriesSecret(head: String): Boolean {
    var matched = false
    for (line in head.split("\r\n").drop(1)) {
      val colon = line.indexOf(':')
      if (colon <= 0) continue
      val name = line.substring(0, colon).trim().lowercase()
      val value = line.substring(colon + 1).trim()
      if (name == HEADER_NAME) {
        if (matches(value)) matched = true
      } else if (name == "cookie") {
        for (part in value.split(';')) {
          val trimmed = part.trim()
          if (trimmed.startsWith("$COOKIE_NAME=") && matches(trimmed.substring(COOKIE_NAME.length + 1))) matched = true
        }
      }
    }
    return matched
  }

  private fun matches(candidate: String): Boolean =
    MessageDigest.isEqual(expected, candidate.toByteArray(Charsets.UTF_8))

  private fun copy(input: InputStream, output: OutputStream) {
    val buffer = ByteArray(16384)
    while (true) {
      val read = input.read(buffer)
      if (read < 0) return
      output.write(buffer, 0, read)
      output.flush()
    }
  }

  private fun closeQuietly(closeable: java.io.Closeable) {
    runCatching { closeable.close() }
  }

  companion object {
    const val COOKIE_NAME = "bb_ssh_tunnel"
    const val HEADER_NAME = "x-bb-tunnel-secret"
    private const val MAX_HEAD = 32768
    private const val MAX_PENDING = 32
    private const val HEAD_TIMEOUT_MS = 5000L
    private const val CR = '\r'.code.toByte()
    private const val LF = '\n'.code.toByte()
  }
}
