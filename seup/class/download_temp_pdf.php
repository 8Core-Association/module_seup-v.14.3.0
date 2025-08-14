<?php
require '../../main.inc.php';

// Validate input
$filename = basename(GETPOST('file', 'alpha')); // this ensures only filename, no path
$fullpath = DOL_DATA_ROOT . '/temp/' . $filename;

if (!preg_match('/^[a-zA-Z0-9_\-\.]+\.pdf$/', $filename)) {
    http_response_code(400);
    echo "Invalid filename.";
    exit;
}

if (!file_exists($fullpath)) {
    http_response_code(404);
    echo "File not found.";
    exit;
}

// Force download
header('Content-Type: application/pdf');
header('Content-Disposition: inline; filename="' . basename($filename) . '"');
header('Content-Length: ' . filesize($fullpath));
readfile($fullpath);
exit;
