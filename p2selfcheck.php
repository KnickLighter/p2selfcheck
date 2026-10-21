<?php
/*
+----------------------------------------------------------------------------+
|  p2selfcheck.php — am I vulnerable to "php2shell" or not?                 |
|                                                                            |
|  A passive self-check for managed web hosting users: upload one file,     |
|  open it in a browser (or run `php p2selfcheck.php` from the account     |
|  shell). Tells you whether YOUR PHP is in the php2shell-affected         |
|  range, whether it can even be reached, and what it would take to        |
|  get hit.                                                                  |
|                                                                            |
|  What it checks                                                            |
|    - the version of PHP that is serving this file, compared to the        |
|      fixed builds (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, released 2026-10-21) |
|    - the PHP extensions/ini settings the exploit chain depends on,        |
|      including the session extension and the upload-progress mechanism    |
|      the bug abuses (this is a "does the mechanism even exist" check,     |
|      not an activation of it)                                              |
|                                                                            |
|  What it deliberately does NOT do                                          |
|    - no exploit chain. No multipart upload of a poisoned file, no         |
|      session hijacked by attacker-chosen ID, no PHP payload dropped      |
|      anywhere.                                                             |
|    - no outbound requests, no reads from other files, no reads of        |
|      /etc/passwd or any app file.                                          |
|    - no PHP extensions required: pure standard-library PHP.               |
|      Works on PHP 5.4+ (even on PHP old enough to be part of the         |
|      vulnerability range itself).                                         |
|                                                                            |
|  How to use                                                                |
|    1. Upload this file to the web root of EACH app/domain (public_html   |
|       / htdocs / www) — each may run a different PHP.                     |
|    2. Open  https://your-domain/p2selfcheck.php   (or:  php              |
|       p2selfcheck.php   from the shell if you have one).                 |
|    3. Read the verdict + table + next steps, then act.                    |
|    4. Delete this file. It reveals your PHP version to anyone who can    |
|       reach the URL.                                                      |
|                                                                            |
|  Colours:   red    = enabler of the exploit chain is present on this     |
|             server                                                         |
|             green   = blocking / not an enabler                           |
|             yellow  = partial, informational, or ambiguous               |
|             info    = context, not a risk factor                          |
|                                                                            |
|  Note: the *application-side* part of the chain (an LFI / local file     |
|  inclusion sink in YOUR code) can only be found by looking at the code.   |
|  That row below says what to search for.                                  |
|                                                                            |
|  CVE-2026-109618 / CVE-2026-109619  ·  affected: PHP 5.4+ < fix builds    |
+----------------------------------------------------------------------------+
*/

error_reporting(E_ALL);
$IS_CLI = (php_sapi_name() === 'cli');
if ($IS_CLI) {
    ini_set('display_errors', '1');
} else {
    ini_set('display_errors', '0');
}

/* ===================== small, self-contained helpers ===================== */

function p2s_e($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

/*
 * p2s_version_status("x.y.z…")
 * Returns array(status, human_text)
 *   status  ∈ {vulnerable, eol, fixed, likely-fixed, unknown}
 *   human   is a plain-English explanation a non-sysadmin can act on
 */
function p2s_version_status($v) {
    if (!preg_match('/^(\d+)\.(\d+)/', $v, $m)) {
        return array('unknown', sprintf(
            "cannot parse version '%s' — ask your hosting provider exactly which PHP build your account runs",
            $v
        ), null);
    }
    $maj = (int)$m[1];
    $min = (int)$m[2];

    /* the fixed builds, by PHP minor branch (2026-10-21 release) */
    $FIXED = array(
        2 => '8.2.35',
        3 => '8.3.36',
        4 => '8.4.27',
        5 => '8.5.12',
    );

    if ($maj === 8 && isset($FIXED[$min])) {
        $f = $FIXED[$min];
        if (version_compare($v, $f, '>=')) {
            return array('fixed', sprintf(
                "%s is at or above the fixed build %s for this branch",
                $v, $f
            ), $f);
        }
        return array('vulnerable', sprintf(
            "%s is below the fixed build %s — inside the affected range",
            $v, $f
        ), $f);
    }
    if ($maj === 8) {
        return array('likely-fixed', sprintf(
            "PHP 8.%d has no recorded fix on its branch — newer than 8.5, assume fixed",
            $min
        ), null);
    }
    if ($maj > 8) {
        return array('likely-fixed', sprintf(
            "PHP %d.x is newer than the fixes — assume fixed",
            $maj
        ), null);
    }
    return array('eol', sprintf(
        "PHP %d.x is end-of-life — no fix ships for it, it stays in the affected range",
        $maj
    ), null);
}

/*
 * p2s_ini_bool($name) — read a boolean ini value, tolerate '', 'on','off',
 * '0','1','true','false'. Returns (effective_bool, was_set_explicitly).
 */
function p2s_ini_bool($name) {
    $raw  = ini_get($name);
    $str  = trim((string)$raw);
    $true = array('1','on','true','yes');
    $false= array('0','off','false','no');
    $low  = strtolower($str);
    if (in_array($low, $true, true))  return array(true,  true);
    if (in_array($low, $false,true))  return array(false, true);
    return array(null, false);  /* '' or unparseable → PHP default applies */
}

function p2s_ini_str($name) {
    $v = ini_get($name);
    return ($v === false) ? '' : $v;
}

/* Is the session save path a writable plain directory? (payload landing
 * zone for the exploit — a non-writable dir would break the chain.)      */
function p2s_savepath_check() {
    $p = session_save_path();
    $r = array('path' => ($p === false || $p === '') ? '(not set)' : $p,
               'writable' => null);
    if ($p !== false && $p !== '' && is_dir($p)) {
        $r['writable'] = is_writable($p);
    }
    return $r;
}

/* ========================= build the check list ========================== */

$PHP_VER = preg_replace('/\s.*$/', '', (string)PHP_VERSION);
list($VSTATUS, $VHUMAN, $VFIXED) = p2s_version_status($PHP_VER);

$SV = p2s_savepath_check();

$rows = array();

/* --- 1. The core verdict: PHP version ---------------------------------- */
$sevmap = array(
    'vulnerable'   => 'red',
    'eol'          => 'red',
    'fixed'        => 'green',
    'likely-fixed' => 'green',
    'unknown'      => 'yellow',
);
$rows[] = array(
    'sev'     => isset($sevmap[$VSTATUS]) ? $sevmap[$VSTATUS] : 'yellow',
    'label'   => 'PHP version (the one serving this file)',
    'value'   => $PHP_VER,
    'meaning' => $VHUMAN . ($VFIXED ? ' — this branch needs ' . $VFIXED . ' or later' : ''),
);

/* --- 2. Required extension: session (the mechanism the bug rides on)---- */
$hasSession = extension_loaded('session');
$rows[] = array(
    'sev'     => $hasSession ? 'green' : 'yellow',
    'label'   => 'session extension',
    'value'   => $hasSession ? 'loaded' : 'NOT loaded',
    'meaning' => 'the php2shell chain rides the internal upload-progress session mechanism — it cannot fire on a PHP without the session extension. Loaded = the mechanism is in principle reachable. (Almost always loaded; managed hosts ship it by default.)',
);

/* --- 3. upload_progress mechanism — core of the bug --------------------- */
list($upeOn, $upeSet) = p2s_ini_bool('session.upload_progress.enabled');
$upeDefault = true;   /* PHP default: enabled */
$upeEff = ($upeSet === true) ? $upeOn : $upeDefault;
$rows[] = array(
    'sev'     => $upeEff ? 'red' : 'green',
    'label'   => 'session.upload_progress.enabled',
    'value'   => $upeEff ? 'On' : 'Off' . ($upeSet !== true ? '  (PHP default applies)' : ''),
    'meaning' => 'This is the internal mechanism the bug abuses. On: the mechanism is available to the exploit (PHP default). Off: the upload-progress session record is not materialised — the core step of the chain is weakened (rare setting).',
);

/* --- 4. session.upload_progress.cleanup --------------------------------- */
list($clnOn, $clnSet)  = p2s_ini_bool('session.upload_progress.cleanup');
$clnDefault  = true;
$clnEff      = ($clnSet === true) ? $clnOn : $clnDefault;
$rows[] = array(
    'sev'     => $clnEff ? 'yellow' : 'red',
    'label'   => 'session.upload_progress.cleanup',
    'value'   => $clnEff ? 'On  (default)' : 'Off',
    'meaning' => 'Off keeps the poisoned progress data in the session file after the request ends (helps the attacker). On (default) removes it at the end of each request — still exploitable, but less persistent.',
);

/* --- 5. multipart parser limit the exploit overflows -------------------- */
$maxmbp = p2s_ini_str('max_multipart_body_parts');
$rows[] = array(
    'sev'     => 'yellow',
    'label'   => 'max_multipart_body_parts',
    'value'   => ($maxmbp !== '') ? $maxmbp : 'not set (old parser pre-limit)',
    'meaning' => 'The buggy parsing path fires when the request contains MORE file-parts than this limit. The verified exploit payload uses 6 parts; if your limit is ≥ that (or unset), the trigger is straightforward for an attacker.',
);

/* --- 6. session ID acceptance ------------------------------------------ */
list($strictOn, $strictSet) = p2s_ini_bool('session.use_strict_mode');
$strictDefault = false;
$strictEff     = ($strictSet === true) ? $strictOn : $strictDefault;
$rows[] = array(
    'sev'     => 'yellow',
    'label'   => 'session.use_strict_mode',
    'value'   => $strictEff ? 'On' : 'Off  (PHP default)',
    'meaning' => 'Off: PHP honours an attacker-supplied session ID on first contact — the simplest exploit path. On: PHP ignores client-provided IDs — the exploit still works via the Set-Cookie header the server itself emits, so this is friction, not a fix.',
);

/* --- 7. Payload landing zone -------------------------------------------- */
$svSev = ($SV['writable'] === true) ? 'red'
       : (($SV['writable'] === false) ? 'green' : 'yellow');
$svVal = (string)$SV['path'] . (
    $SV['writable'] === true ? '  —  writable'
    : ($SV['writable'] === false ? '  —  NOT writable' : '')
);
$rows[] = array(
    'sev'     => $svSev,
    'label'   => 'session.save_path (where a payload would land)',
    'value'   => $svVal,
    'meaning' => 'The attack leaves a small file  sess_<id>  in this directory. If it is not writable, or is a custom (redis/db) handler, the chain breaks at the "read the payload" step. Non-writable = green above is genuinely helpful here.',
);

/* --- 8. What scanners see (informational) -------------------------------- */
list($exposeOn, $exposeSet) = p2s_ini_bool('expose_php');
$exposeDefault = true;
$exposeEff     = ($exposeSet === true) ? $exposeOn : $exposeDefault;
$rows[] = array(
    'sev'     => $exposeEff ? 'yellow' : 'green',
    'label'   => 'expose_php',
    'value'   => $exposeEff ? 'On  (default)' : 'Off',
    'meaning' => 'On: the PHP version is advertised in the X-Powered-By header — scanner-style tools that check response headers see it. Off hides it from header-based scans. Neither setting fixes the bug by itself.',
);

/* --- 9. Upload size headroom (informational) ----------------------------- */
$ums = p2s_ini_str('upload_max_filesize');
$pms = p2s_ini_str('post_max_size');
$rows[] = array(
    'sev'     => 'info',
    'label'   => 'upload_max_filesize / post_max_size',
    'value'   => ($ums !== '' ? $ums : '2M (default)') . '  |  ' . ($pms !== '' ? $pms : '8M (default)'),
    'meaning' => 'The exploit body is about 1 KB. Any sensible limit is more than enough headroom — these two values are context, not a risk factor of their own.',
);

/* --- 10. Application-side sink — the piece we CANNOT check from here ----- */
$rows[] = array(
    'sev'     => 'yellow',
    'label'   => 'LFI sink in YOUR app code',
    'value'   => 'search manually (see meaning)',
    'meaning' => 'The full RCE chain also needs a page in your application that includes or reads a user-controlled path — e.g.  include($_GET[\'page\']),  require, or  file_get_contents on request input. Search your codebase for those patterns (or ask your developer). If no such page exists, the bug is harder to reach but the PHP version is still in the affected range.',
);

/* ============================ VERDICT banner ============================ */

$SEV_OF = array(
    'red'   => 'RED',   'green' => 'GREEN',
    'yellow'=> 'YELLOW','info'  => 'INFO',
);

if ($VSTATUS === 'vulnerable' || $VSTATUS === 'eol') {
    $banner_sev = 'red';
    $banner_title = 'VERDICT: LIKELY VULNERABLE — inside the affected range';
    $banner_points = array(
        'This PHP (' . $PHP_VER . ') is in the php2shell-affected range (CVE-2026-109618 / CVE-2026-109619).'
        . ($VFIXED ? ' Your branch was fixed in ' . $VFIXED . ' — ask your hosting provider to upgrade; managed hosts usually have a one-click PHP version switch. This is a PHP-core update, not something to do in application code.' : ''),
        'The red rows above are enablers of the exploit chain that are present on THIS server. The yellow rows need a decision. The full RCE path also needs an LFI sink in your APPLICATION code (row 10) — search your codebase for that.',
        'After the upgrade, re-run this check on EVERY domain/subdomain/staging box you host — each may run its own PHP.',
    );
} elseif ($VSTATUS === 'fixed' || $VSTATUS === 'likely-fixed') {
    $banner_sev = 'green';
    $banner_title = 'VERDICT: PATCHED (this PHP)';
    $banner_points = array(
        'PHP ' . $PHP_VER . ' is ' . ($VFIXED ? 'at or above the fixed build ' . $VFIXED . ' for its branch' : 'newer than the affected releases') . '.',
        'Caveat: this verdict covers only the PHP that serves THIS file. Other domains, subdomains, or app servers you own can still run an older PHP — drop a copy of this file on each, or check their versions from any remote HTTP check.',
    );
} else {
    $banner_sev = 'yellow';
    $banner_title = 'VERDICT: UNKNOWN';
    $banner_points = array(
        sprintf('We could not confidently map version \'%s\' to the fixed-build table. Ask your hosting provider to confirm the exact PHP build on your account.', $PHP_VER),
    );
}

$next_steps = array(
    'Ask your hosting provider to move your account to a fixed PHP build — 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later, whichever matches your branch.',
    'While waiting for the upgrade: search your codebase for  include(…$_GET…),  require(…$_POST…),  file_get_contents(…request input…),  or any include/require that uses a query string. Note every hit — those are your LFI-sink candidates.',
    'Re-run this check after the upgrade, and on every other domain you host.',
    'Delete p2selfcheck.php when you are done — it reveals your PHP version to anyone who can reach the URL.',
);

/* ============================ RENDER — CLI ============================== */

if ($IS_CLI) {
    $BANNER_LINE = '=' . str_repeat('=', 71) . '=';
    $DIVIDER     = '-' . str_repeat('-', 71) . '-';
    echo "p2selfcheck — php2shell self check (CVE-2026-109618/9)\n";
    echo $BANNER_LINE . "\n";
    printf("  [%-6s] %s\n", $SEV_OF[$banner_sev], $banner_title);
    foreach ($banner_points as $li) {
        echo "      - " . $li . "\n";
    }
    echo $DIVIDER . "\n";
    foreach ($rows as $r) {
        printf("  [%-6s] %-42s %s\n",
               $SEV_OF[$r['sev']], $r['label'], $r['value']);
        echo "             " . $r['meaning'] . "\n\n";
    }
    echo "Next steps:\n";
    foreach ($next_steps as $li) {
        echo "  * " . $li . "\n";
    }
    return;
}

/* ============================ RENDER — WEB ============================== */

header('Content-Type: text/html; charset=utf-8');
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>p2selfcheck — is this PHP vulnerable to php2shell?</title>
<style>
 body{font:14px/1.55 ui-monospace,Consolas,Menlo,monospace;max-width:980px;margin:24px auto;padding:0 16px;background:#13151b;color:#dde3ee}
 h1{font-size:17px;margin:0 0 4px}
 .dim{color:#8b95a8;font-size:12.5px}
 .banner{padding:14px 16px;border-radius:8px;font-weight:bold;margin:18px 0;color:#fff}
 .b-red{background:#3a1216;border:1px solid #b3404a;color:#ffb3ba}
 .b-green{background:#0f2a17;border:1px solid #2f9e57;color:#a7f0c0}
 .b-yellow{background:#332a0f;border:1px solid #b3922f;color:#ffe9a8}
 .banner ul{margin:8px 0 0;padding-left:18px;font-weight:normal}
 .banner li{margin:4px 0}
 table{border-collapse:collapse;width:100%;margin:14px 0}
 th,td{border:1px solid #2c3342;padding:8px 10px;text-align:left;vertical-align:top}
 th{color:#8fa3c8;font-weight:normal;font-size:12.5px}
 td.sev{width:80px;font-weight:bold;text-align:center;font-size:12px;letter-spacing:0.5px}
 .red{color:#ff8891}.green{color:#7fd6a0}.yellow{color:#e8c86a}.info{color:#8fa3c8}
 .meaning{color:#aab4c8;font-size:12.5px}
 ul.next{padding-left:18px}
 ul.next li{margin:6px 0}
 footer{margin-top:22px;padding-top:10px;border-top:1px solid #2c3342;color:#8b95a8;font-size:12.5px}
 .note{background:#171b26;border:1px solid #2c3342;border-radius:6px;padding:8px 12px;margin:10px 0;font-size:12.5px;color:#aab4c8}
</style>
</head>
<body>
<h1>p2selfcheck — is this PHP vulnerable to "php2shell"?</h1>
<p class="dim">CVE-2026-109618 / CVE-2026-109619 · affected: PHP 5.4+ below the 2026-10-21 fix builds (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) · SAPI: <b><?= p2s_e(php_sapi_name()) ?></b></p>

<div class="banner b-<?= p2s_e($banner_sev) ?>">
  <?= p2s_e($banner_title) ?>
  <ul>
  <?php foreach ($banner_points as $li): ?>
    <li><?= p2s_e($li) ?></li>
  <?php endforeach; ?>
  </ul>
</div>

<div class="note">
This check is <b>passive</b>: it reads the local PHP version and the relevant
ini settings, and tells you what an attacker would find here.
It does <b>not</b> run the exploit, send anything over the network, or leave
any file on your disk. Worst side-effect of a web visit: one line in the
access log.
</div>

<table>
  <thead>
    <tr>
      <th style="width:80px">status</th>
      <th>check</th>
      <th>value on this server</th>
      <th>what it means for the php2shell chain</th>
    </tr>
  </thead>
  <tbody>
    <?php foreach ($rows as $r): ?>
    <tr>
      <td class="sev <?= p2s_e($r['sev']) ?>"><?= p2s_e(strtoupper($r['sev'])) ?></td>
      <td><?= p2s_e($r['label']) ?></td>
      <td><?= p2s_e($r['value']) ?></td>
      <td class="meaning"><?= p2s_e($r['meaning']) ?></td>
    </tr>
    <?php endforeach; ?>
  </tbody>
</table>

<h3>What to do now</h3>
<ul class="next">
<?php foreach ($next_steps as $li): ?>
  <li><?= p2s_e($li) ?></li>
<?php endforeach; ?>
</ul>

<footer>
  p2selfcheck · single-file, passive, no extensions required ·
  colours: <span class="red">RED</span> = enabler present ·
  <span class="green">GREEN</span> = blocking or not an enabler ·
  <span class="yellow">YELLOW</span> = partial/ambiguous ·
  <span class="info">INFO</span> = context ·
  <b>delete this file after checking</b> — it reveals your PHP version
</footer>
</body></html>
<?php
/* end */
?>
