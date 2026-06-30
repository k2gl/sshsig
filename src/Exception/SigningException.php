<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Exception;

use RuntimeException;

/**
 * A signing operation could not be completed: an unloadable or unsupported
 * private key, or a failure in the underlying signature primitive.
 */
final class SigningException extends RuntimeException implements SshsigException {}
