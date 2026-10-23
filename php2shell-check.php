<?php
// php2shell-check.php: is this PHP patched for CVE-2026-109618 and
// CVE-2026-109619 ("PHP2Shell"), and which interim mitigations are on?
//
// Run it with the SAME PHP that serves your site. The CLI binary is often a
// different version from PHP-FPM or mod_php, so also run it through the web
// server (upload it under a random name, open it once, then delete it).
// Works on PHP 7.0 and later.
//
// Exit codes (CLI): 0 = patched, 1 = vulnerable, 2 = check with your vendor.

const PHP2SHELL_FIXED = array(
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
);

// Distribution builds that keep an old upstream number but include the fix
// (Ubuntu security tracker, 21 October 2026). Key: upstream version.
const PHP2SHELL_DISTRO_FIXED = array(
    '8.5.4' => '0ubuntu1.5',          // Ubuntu 26.04
    '8.3.6' => '0ubuntu0.24.04.13',   // Ubuntu 24.04
    '8.1.2' => '1ubuntu2.28',         // Ubuntu 22.04
    '7.4.3' => '4ubuntu2.29+esm5',    // Ubuntu 20.04 (Ubuntu Pro)
);

/**
 * Decide the status from the version alone. $extra is PHP_EXTRA_VERSION:
 * distribution builds often set it, and can backport fixes without changing
 * the upstream version number.
 */
function php2shell_status($version, $extra = '')
{
    if (!preg_match('/^(\d+)\.(\d+)\.(\d+)(.*)$/', $version, $m)) {
        return array('check-vendor', "Unrecognised version string: $version");
    }
    $branch = "$m[1].$m[2]";
    $plain = "$m[1].$m[2].$m[3]";
    $suffix = $m[4] . $extra;

    $revision = ltrim($extra, '-');
    if ($revision !== '' && isset(PHP2SHELL_DISTRO_FIXED[$plain]) && strpos($revision, 'ubuntu') !== false) {
        $fixedRevision = PHP2SHELL_DISTRO_FIXED[$plain];
        return version_compare($revision, $fixedRevision, '>=')
            ? array('patched', "Ubuntu build $plain-$revision includes the backported fix ($plain-$fixedRevision or later).")
            : array('vulnerable', "Ubuntu build $plain-$revision is older than the fixed package $plain-$fixedRevision. Run apt upgrade.");
    }

    if (version_compare($branch, '8.6', '>=')) {
        // 8.6.0 RC4 and later contain the fixes; earlier pre-releases do not.
        if (preg_match('/alpha|beta|RC[1-3]\b/i', $suffix)) {
            return array('vulnerable', "$version is a pre-release without the fixes. Use 8.6.0 RC4 or later, and keep pre-releases out of production.");
        }
        return array('patched', "$version includes the fixes (8.6.0 RC4 and later).");
    }

    if (!isset(PHP2SHELL_FIXED[$branch])) {
        $note = "PHP $branch is end of life, so there is no fixed upstream release. The PHP team published source backports for 7.4, 8.0 and 8.1 only.";
        if ($extra !== '') {
            return array('check-vendor', "$note This is a vendor build ($version$extra): confirm with your vendor that it includes the backport, or upgrade to a supported branch.");
        }
        return array('vulnerable', "$note Upgrade to 8.4.27 or 8.5.12, or rebuild with the official backport.");
    }

    $fixed = PHP2SHELL_FIXED[$branch];
    if (version_compare($plain, $fixed, '>=')) {
        return array('patched', "$plain is at or above the fixed release $fixed.");
    }
    if ($extra !== '') {
        return array('check-vendor', "Upstream $plain is below $fixed, but this is a vendor build ($version$extra). Distributions backport fixes without changing the version: check the package changelog for CVE-2026-109618 and CVE-2026-109619.");
    }
    return array('vulnerable', "$plain is below the fixed release $fixed. Update now.");
}

function php2shell_bytes($value)
{
    $value = trim((string) $value);
    if ($value === '' || $value === '-1') {
        return -1;
    }
    $n = (int) $value;
    $unit = strtolower(substr($value, -1));
    if ($unit === 'g') {
        return $n * 1073741824;
    }
    if ($unit === 'm') {
        return $n * 1048576;
    }
    if ($unit === 'k') {
        return $n * 1024;
    }
    return $n;
}

/** Interim settings from the PHP advisories. They reduce risk; they do not fix it. */
function php2shell_mitigations()
{
    $memory = (string) ini_get('memory_limit');
    $post = (string) ini_get('post_max_size');
    $postBytes = php2shell_bytes($post);
    $progress = ini_get('session.upload_progress.enabled') ? '1' : '0';

    $rows = array(
        array('memory_limit', $memory, $memory === '-1', 'Set to -1 with php_admin_value until patched; restore a real limit afterwards.'),
        array('post_max_size', $post, $postBytes > 0 && $postBytes <= 33554432, 'Keep at 8M, or 32M if you need uploads.'),
        array('session.upload_progress.enabled', $progress, $progress === '0', 'Set to 0 in php.ini or the FPM pool (not ini_set or .user.ini), then restart workers.'),
    );
    if (PHP_VERSION_ID >= 80500) {
        $backtraces = (string) ini_get('fatal_error_backtraces');
        $rows[] = array('fatal_error_backtraces', $backtraces, $backtraces === '0' || $backtraces === '', 'PHP 8.5: set to 0 and restart workers.');
    }
    return $rows;
}

function php2shell_report()
{
    list($status, $reason) = php2shell_status(PHP_VERSION, PHP_EXTRA_VERSION);
    $lines = array(
        'PHP2Shell check (CVE-2026-109618, CVE-2026-109619)',
        'PHP version:  ' . PHP_VERSION . PHP_EXTRA_VERSION,
        'SAPI:         ' . PHP_SAPI . (PHP_SAPI === 'apache2handler' ? '  (mod_php: highest risk, patch first)' : ''),
        'Status:       ' . strtoupper($status),
        'Why:          ' . $reason,
        '',
        'Interim mitigations (temporary, not a fix):',
    );
    foreach (php2shell_mitigations() as $row) {
        list($name, $value, $on, $advice) = $row;
        $lines[] = sprintf('  [%s] %s = %s  %s', $on ? 'x' : ' ', $name, $value === '' ? '(empty)' : $value, $advice);
    }
    $lines[] = '';
    $lines[] = 'Linux packages can include the fix without a new version number: also compare';
    $lines[] = 'your package version (dpkg -l "php*" or rpm -qa "php*") with your distribution\'s advisory.';
    if (PHP_SAPI === 'cli') {
        $lines[] = 'This was the CLI. Run it through your web server too: FPM and mod_php can be a different PHP.';
    }
    return array($status, implode(PHP_EOL, $lines) . PHP_EOL);
}

// Only produce output when run directly, so tests can include this file.
if (isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    list($status, $report) = php2shell_report();
    if (PHP_SAPI !== 'cli') {
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Robots-Tag: noindex');
    }
    echo $report;
    if (PHP_SAPI === 'cli') {
        $codes = array('patched' => 0, 'vulnerable' => 1, 'check-vendor' => 2);
        exit($codes[$status]);
    }
}
