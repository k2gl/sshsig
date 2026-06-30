<?php

declare(strict_types=1);

namespace K2gl\Sshsig\Internal;

/**
 * OpenSSH ssh_config(5) pattern-list matching: a comma-separated list of
 * patterns with '*' and '?' wildcards, where a leading '!' negates. A subject
 * matches when it matches at least one positive pattern and no negated one.
 * Used for allowed_signers principals and namespace restrictions.
 *
 * @internal
 */
final class Pattern
{
    public static function matchesList(string $patternList, string $subject): bool
    {
        $matched = false;

        foreach (explode(',', $patternList) as $pattern) {
            $pattern = trim($pattern);

            if ($pattern === '') {
                continue;
            }
            $negated = $pattern[0] === '!';

            if ($negated) {
                $pattern = substr($pattern, 1);
            }

            if (self::matches($pattern, $subject)) {
                if ($negated) {
                    return false;
                }
                $matched = true;
            }
        }

        return $matched;
    }

    private static function matches(string $pattern, string $subject): bool
    {
        $regex = '';
        $length = strlen($pattern);

        for ($i = 0; $i < $length; $i++) {
            $char = $pattern[$i];
            $regex .= match ($char) {
                '*' => '.*',
                '?' => '.',
                default => preg_quote($char, '/'),
            };
        }

        return preg_match('/^' . $regex . '$/s', $subject) === 1;
    }
}
