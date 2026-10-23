# php2shell-check

Check whether a PHP installation is patched for **PHP2Shell**: CVE-2026-109618 (RCE via out-of-memory corruption) and CVE-2026-109619 (RCE via stale global state), fixed on October 21, 2026 in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. It also shows which interim mitigations from PHP's advisories are active. Runs on PHP 7.0 and later.

Full write-up: [PHP2Shell: check and patch your PHP](https://www.codewares.in/blog/php2shell-cve-2026-109618-check-and-patch)

## Usage

```bash
curl -O https://raw.githubusercontent.com/AmanSin001/php2shell-check/main/php2shell-check.php
php php2shell-check.php; echo "exit code: $?"   # 0 patched, 1 vulnerable, 2 check with your vendor
```

**Also run it through your web server.** The command-line PHP is often a different version from PHP-FPM or Apache mod_php. Upload it under a random name, open it once, then delete it:

```bash
cp php2shell-check.php /var/www/html/check-$(openssl rand -hex 6).php
```

## Example output

```
PHP2Shell check (CVE-2026-109618, CVE-2026-109619)
PHP version:  8.4.26
SAPI:         cli
Status:       VULNERABLE
Why:          8.4.26 is below the fixed release 8.4.27. Update now.

Interim mitigations (temporary, not a fix):
  [ ] memory_limit = 128M  Set to -1 with php_admin_value until patched; restore a real limit afterwards.
  [x] post_max_size = 8M  Keep at 8M, or 32M if you need uploads.
  [ ] session.upload_progress.enabled = 1  Set to 0 in php.ini or the FPM pool (not ini_set or .user.ini), then restart workers.
```

Tested on official PHP 7.4.33, 8.0.30, 8.4.26 and 8.4.27 builds.

## Distribution builds

Ubuntu fixes PHP without changing the upstream version number (24.04 is fixed in `8.3.6-0ubuntu0.24.04.13`). The checker knows the fixed Ubuntu builds:

| Ubuntu | Fixed package |
|---|---|
| 26.04 LTS | 8.5.4-0ubuntu1.5 |
| 24.04 LTS | 8.3.6-0ubuntu0.24.04.13 |
| 22.04 LTS | 8.1.2-1ubuntu2.28 |
| 20.04 (Ubuntu Pro) | 7.4.3-4ubuntu2.29+esm5 |

For other vendor builds below the fixed release it reports `CHECK-VENDOR`: compare your package version (`dpkg -l 'php*'` or `rpm -qa 'php*'`) with your distribution's advisory.

## Interim mitigations

[`php2shell-mitigation.ini`](php2shell-mitigation.ini) contains the temporary settings from PHP's advisories. They reduce exposure to specific attack paths; **only updating PHP fixes the flaws**. Apply them at server level (not `ini_set()` or `.user.ini`), restart every worker, and remove them after patching.

## Tests

```bash
php php2shell-check.test.php   # 24 version cases
```

## License

MIT. Want it patched for you? [CodeWares PHP security update](https://www.codewares.in/gigs/php-security-update).
