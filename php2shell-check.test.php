<?php
// Tests the version rules without needing every PHP build installed.
require __DIR__ . '/php2shell-check.php';

$cases = array(
    // version, PHP_EXTRA_VERSION, expected status
    array('8.5.12', '', 'patched'),
    array('8.5.11', '', 'vulnerable'),
    array('8.4.27', '', 'patched'),
    array('8.4.26', '', 'vulnerable'),
    array('8.3.36', '', 'patched'),
    array('8.3.35', '', 'vulnerable'),
    array('8.2.35', '', 'patched'),
    array('8.2.34', '', 'vulnerable'),
    // Ubuntu backports keep the old upstream number
    array('8.3.6', '-0ubuntu0.24.04.13', 'patched'),
    array('8.3.6', '-0ubuntu0.24.04.14', 'patched'),
    array('8.3.6', '-0ubuntu0.24.04.9', 'vulnerable'),
    array('8.1.2', '-1ubuntu2.28', 'patched'),
    array('8.1.2', '-1ubuntu2.27', 'vulnerable'),
    array('7.4.3', '-4ubuntu2.29+esm5', 'patched'),
    array('7.4.3', '-4ubuntu2.29+esm4', 'vulnerable'),
    array('8.5.4', '-0ubuntu1.5', 'patched'),
    // other vendor builds below the fixed release: ask the vendor
    array('8.3.20', '-1+deb.sury.org+1', 'check-vendor'),
    array('8.1.33', '', 'vulnerable'),
    array('7.4.33', '', 'vulnerable'),
    array('7.4.33', '-1+deb11u9', 'check-vendor'),
    array('5.6.40', '', 'vulnerable'),
    array('8.6.0RC3', '', 'vulnerable'),
    array('8.6.0RC4', '', 'patched'),
    array('8.6.0', '', 'patched'),
);

$failed = 0;
foreach ($cases as $case) {
    list($version, $extra, $expected) = $case;
    list($actual) = php2shell_status($version, $extra);
    $ok = $actual === $expected;
    $failed += $ok ? 0 : 1;
    printf("%s %-10s %-20s %s\n", $ok ? 'ok  ' : 'FAIL', $version, $extra === '' ? '' : $extra, $actual);
}
echo $failed === 0 ? "all " . count($cases) . " passed\n" : "$failed failed\n";
exit($failed === 0 ? 0 : 1);
