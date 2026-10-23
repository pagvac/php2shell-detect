<?php
// Benchmark router for php2shell-detect (PHP built-in server).
//
// BENCH_PROFILE selects which detection method this fixture exercises; each profile
// plants ONLY that method's signal so the benchmark proves every path, not just the
// X-Powered-By banner. expose_php is disabled (see Dockerfile) so nothing leaks a
// version unless a profile sets one deliberately. Detection-only scaffolding.
$profile = getenv('BENCH_PROFILE') ?: 'banner';
$ver     = getenv('FAKE_PHP_VERSION') ?: '';
$uri     = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$is_php  = is_string($uri) && substr($uri, -4) === '.php';

switch ($profile) {
    case 'banner':      // method "headers": advertise an exact version
        if ($ver !== '') {
            header("X-Powered-By: PHP/$ver");
        }
        echo "bench\n";
        break;

    case 'suspect':     // presence only: PHPSESSID cookie, no version
        session_start();
        echo "bench\n";
        break;

    case 'phpinfo':     // method "phpinfo": real phpinfo() at /phpinfo.php
        if ($uri === '/phpinfo.php') {
            // Intentional: this local, throwaway benchmark fixture serves phpinfo() ON
            // PURPOSE so the detector's "phpinfo" method can be exercised. Never deployed.
            phpinfo();  // nosemgrep: php.lang.security.phpinfo-use.phpinfo-use
        } else {
            echo "bench\n";
        }
        break;

    case 'composer':    // method "exposed": composer.json require.php floor
        if ($uri === '/composer.json') {
            header('Content-Type: application/json');
            echo json_encode(['require' => ['php' => ($ver ?: '8.3.35')]]);
        } else {
            echo "bench\n";
        }
        break;

    case 'cms':         // method "cms": WordPress generator -> PHP>=7.2 floor
        echo '<!doctype html><html><head>'
           . '<meta name="generator" content="WordPress 6.4.2">'
           . '</head><body>bench</body></html>';
        break;

    case 'dummyphp':    // method "dummyphp": static /, *.php routed to PHP w/ version
        if ($is_php) {
            header('X-Powered-By: PHP/' . PHP_VERSION);
            echo "router\n";
        } else {
            echo "bench static\n";
        }
        break;

    default:
        http_response_code(500);
        echo "unknown BENCH_PROFILE\n";
}
