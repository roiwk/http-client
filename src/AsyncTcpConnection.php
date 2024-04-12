<?php

namespace Workerman\Http;

use Workerman\Connection\AsyncTcpConnection as ConnectionAsyncTcpConnection;
use Workerman\Worker;

class AsyncTcpConnection extends ConnectionAsyncTcpConnection
{
    /**
     * Do connect.
     *
     * @return void
     * @throws Throwable
     */
    public function connect(): void
    {
        if (
            $this->status !== self::STATUS_INITIAL && $this->status !== self::STATUS_CLOSING &&
            $this->status !== self::STATUS_CLOSED
        ) {
            return;
        }

        if (!$this->eventLoop) {
            $this->eventLoop = Worker::$globalEvent;
        }

        $this->status = self::STATUS_CONNECTING;
        $this->connectStartTime = microtime(true);
        if ($this->transport !== 'unix') {
            if (!$this->remotePort) {
                $this->remotePort = $this->transport === 'ssl' ? 443 : 80;
                $this->remoteAddress = $this->remoteHost . ':' . $this->remotePort;
            }
            // Open socket connection asynchronously.
            if ($this->proxySocks5) {
                $this->socketContext['ssl']['peer_name'] = $this->remoteHost;
                $context = stream_context_create($this->socketContext);
                $this->socket = stream_socket_client("tcp://$this->proxySocks5", $errno, $err_str, 0, STREAM_CLIENT_ASYNC_CONNECT, $context);
            } else if ($this->proxyHttp) {
                $this->socketContext['ssl']['peer_name'] = $this->remoteHost;
                $context = stream_context_create($this->socketContext);
                $this->socket = stream_socket_client("tcp://$this->proxyHttp", $errno, $err_str, 0, STREAM_CLIENT_ASYNC_CONNECT, $context);
            } else if ($this->socketContext) {
                $context = stream_context_create($this->socketContext);
                $this->socket = stream_socket_client(
                    "tcp://$this->remoteHost:$this->remotePort",
                    $errno,
                    $err_str,
                    0,
                    STREAM_CLIENT_ASYNC_CONNECT,
                    $context
                );
            } else {
                $this->socket = stream_socket_client(
                    "tcp://$this->remoteHost:$this->remotePort",
                    $errno,
                    $err_str,
                    0,
                    STREAM_CLIENT_ASYNC_CONNECT
                );
            }
        } else {
            $this->socket = stream_socket_client(
                "$this->transport://$this->remoteAddress",
                $errno,
                $err_str,
                0,
                STREAM_CLIENT_ASYNC_CONNECT
            );
        }
        // If failed attempt to emit onError callback.
        if (!$this->socket || !is_resource($this->socket)) {
            $this->emitError(static::CONNECT_FAIL, $err_str);
            if ($this->status === self::STATUS_CLOSING) {
                $this->destroy();
            }
            if ($this->status === self::STATUS_CLOSED) {
                $this->onConnect = null;
            }
            return;
        }
        // Add socket to global event loop waiting connection is successfully established or failed.
        $this->eventLoop->onWritable($this->socket, [$this, 'checkConnection']);
        // For windows.
        if (DIRECTORY_SEPARATOR === '\\' && method_exists($this->eventLoop, 'onExcept')) {
            $this->eventLoop->onExcept($this->socket, [$this, 'checkConnection']);
        }
    }

    /**
     * Check connection is successfully established or failed.
     *
     * @return void
     * @throws Throwable
     */
    public function checkConnection(): void
    {
        // Remove EV_EXPECT for windows.
        if (DIRECTORY_SEPARATOR === '\\' && method_exists($this->eventLoop, 'offExcept')) {
            $this->eventLoop->offExcept($this->socket);
        }
        // Remove write listener.
        $this->eventLoop->offWritable($this->socket);

        if ($this->status !== self::STATUS_CONNECTING) {
            return;
        }

        // Check socket state.
      if ($address = stream_socket_get_name($this->socket, true)) {
            if ($this->proxySocks5 && $address === $this->proxySocks5) {
                fwrite($this->socket, chr(5) . chr(1) . chr(0));
                fread($this->socket, 512);
                fwrite($this->socket, chr(5) . chr(1) . chr(0) . chr(3) . chr(strlen($this->remoteHost)) . $this->remoteHost . pack("n", $this->remotePort));
                fread($this->socket, 512);
            }
            if ($this->proxyHttp && $address === $this->proxyHttp) {
                $str = "CONNECT $this->remoteHost:$this->remotePort HTTP/1.1\r\n";
                $str .= "Host: $this->remoteHost:$this->remotePort\r\n";
                $str .= "Proxy-Connection: keep-alive\r\n\r\n";
                fwrite($this->socket, $str);
                fread($this->socket, 512);
            }
            // Nonblocking.
            stream_set_blocking($this->socket, false);
            // Compatible with hhvm
            if (function_exists('stream_set_read_buffer')) {
                stream_set_read_buffer($this->socket, 0);
            }
            // Try to open keepalive for tcp and disable Nagle algorithm.
            if (function_exists('socket_import_stream') && $this->transport === 'tcp') {
                $rawSocket = socket_import_stream($this->socket);
                socket_set_option($rawSocket, SOL_SOCKET, SO_KEEPALIVE, 1);
                socket_set_option($rawSocket, SOL_TCP, TCP_NODELAY, 1);
            }
            // SSL handshake.
            if ($this->transport === 'ssl') {
                $this->sslHandshakeCompleted = $this->doSslHandshake($this->socket);
                if ($this->sslHandshakeCompleted === false) {
                    return;
                }
            } else {
                // There are some data waiting to send.
                if ($this->sendBuffer) {
                    $this->eventLoop->onWritable($this->socket, [$this, 'baseWrite']);
                }
            }
            // Register a listener waiting read event.
            $this->eventLoop->onReadable($this->socket, [$this, 'baseRead']);

            $this->status = self::STATUS_ESTABLISHED;
            $this->remoteAddress = $address;

            // Try to emit onConnect callback.
            if ($this->onConnect) {
                try {
                    ($this->onConnect)($this);
                } catch (Throwable $e) {
                    $this->error($e);
                }
            }
            // Try to emit protocol::onConnect
            if ($this->protocol && method_exists($this->protocol, 'onConnect')) {
                try {
                    [$this->protocol, 'onConnect']($this);
                } catch (Throwable $e) {
                    $this->error($e);
                }
            }
        } else {

            // Connection failed.
            $this->emitError(static::CONNECT_FAIL, 'connect ' . $this->remoteAddress . ' fail after ' . round(microtime(true) - $this->connectStartTime, 4) . ' seconds');
            if ($this->status === self::STATUS_CLOSING) {
                $this->destroy();
            }
            if ($this->status === self::STATUS_CLOSED) {
                $this->onConnect = null;
            }
        }
    }
}
