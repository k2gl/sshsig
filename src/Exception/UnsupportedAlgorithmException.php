<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Exception;

use RuntimeException;

/**
 * The signature is well-formed but uses a key type, signature algorithm, or
 * hash algorithm this library does not accept — for example the legacy
 * SHA-1 "ssh-rsa" signature algorithm, or an unknown ECDSA curve. Refusing
 * keeps untrusted input from being silently treated as verified.
 */
final class UnsupportedAlgorithmException extends RuntimeException implements SshsigException {}
