<?php
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

$model = null;
$build = null;

if (preg_match('/model\/([a-zA-Z0-9,]+)/', $userAgent, $mMatches)) {
    $model = $mMatches[1];
}

if (preg_match('/build\/([a-zA-Z0-9]+)/', $userAgent, $bMatches)) {
    $build = $bMatches[1];
}

if ($model && $build) {
    if (strpos($model, '..') !== false || strpos($build, '..') !== false) {
        http_response_code(403);
        exit();
    }

    $baseDir = __DIR__ . '/plists';
    $filePath = $baseDir . '/' . $model . '/' . $build . '/patched.plist';

    if (file_exists($filePath)) {
        header('Content-Description: File Transfer');
        header('Content-Encoding: identity');
        header('Content-Type: application/xml');
        header('Content-Disposition: attachment; filename="patched.plist"');
        header('Content-Length: ' . filesize($filePath));
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        
        readfile($filePath);
        exit();
    }
}

http_response_code(403);
echo "Forbidden";
exit();
?>