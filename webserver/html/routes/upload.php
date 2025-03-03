<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
require_once '../includes/curlHelper.php';

define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('MAX_FILE_SIZE', 5 * 1024 * 1024 * 1024); // 5 GB

define('VALID_MIME_TYPES', [
    'application/x-iso9660-image',
    'application/octet-stream',
    'application/x-cd-image',
    'application/x-iso',
    'application/x-udf-image',
]);

define('ALLOWED_EXTENSIONS', ['iso']);

function validateFile($file)
{
    $fileName = $file['name'];
    $fileSize = $file['size'];
    $fileTmp = $file['tmp_name'];
    $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

    if (!in_array($fileExt, ALLOWED_EXTENSIONS, true)) {
        logError("Invalid file extension: " . var_export($fileExt, true));
        jsonResponse(false, "Invalid file. Please upload a valid ISO file.", null, 400);
        exit;
    }

    if ($fileSize === null || $fileSize === 0) {
        logError("File size is invalid or empty: " . var_export($fileName, true));
        jsonResponse(false, "Invalid file. Please upload a valid ISO file.", null, 400);
        exit;
    }

    if ($fileSize > MAX_FILE_SIZE) {
        logError("File too large: " . var_export($fileName, true));
        jsonResponse(false, "File is too large.", null, 400);
        exit;
    }

    if (!is_uploaded_file($fileTmp)) {
        logError("Potential file upload attack detected: " . var_export($fileName, true));
        jsonResponse(false, "An unexpected error occurred.", null, 400);
        exit;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $fileTmp);
    finfo_close($finfo);

    if (!in_array($mimeType, VALID_MIME_TYPES, true)) {
        logError("Invalid file type: " . var_export($mimeType, true));
        jsonResponse(false, "Invalid file. Please upload a valid ISO file.", null, 400);
        exit;
    }
}

$node = filter_input(INPUT_POST, 'node', FILTER_SANITIZE_SPECIAL_CHARS);

if(empty(trim($node))){
    logError("Invalid request parameters: node=" . var_export($node, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

if (!isset($_FILES['isoFile']) || empty($_FILES['isoFile']['tmp_name'])) {
    logError("Missing or invalid file upload: " . var_export($_FILES, true));
    jsonResponse(false, "Invalid or missing parameters", null, 400);
    exit;
}

if (!is_dir(UPLOAD_DIR) && !mkdir(UPLOAD_DIR, 0755, true) && !is_dir(UPLOAD_DIR)) {
    logError("Failed to create upload directory: " . var_export(UPLOAD_DIR, true));
    jsonResponse(false, "An unexpected error occurred.", null, 500);
    exit;
}

validateFile($_FILES['isoFile']);
$safeFileName = preg_replace('/[^a-zA-Z0-9_\-.]/', '_', basename($_FILES['isoFile']['name']));
$filePath = UPLOAD_DIR . DIRECTORY_SEPARATOR . $safeFileName;

if (!move_uploaded_file($_FILES['isoFile']['tmp_name'], $filePath)) {
    logError("Error moving uploaded file to " . var_export($filePath, true));
    jsonResponse(false, "An unexpected error occurred.", null, 500);
    exit;
}

$endpoint = "/api2/json/nodes/$node/storage/local/upload";

$post_params = [
    'content' => 'iso',
    'filename' => new CURLFile($filePath)
];

$authHeaders = getAuthHeaders("multipart/form-data");
$result = makeCurlRequest($endpoint, 'POST', $authHeaders, $post_params);

if (!$result) {
    logError("cURL error while uploading ISO $safeFileName.");
    jsonResponse(false, "Service temporarily unavailable.", null, 503);
    exit;
}
$response = $result['response'];
$httpCode = $result['http_code'];

$responseData = json_decode($response, true);

if (!$responseData || $httpCode !== 200) {
    logError("Unexpected response from Proxmox: HTTP $httpCode, Response: " . json_encode($responseData));
    jsonResponse(false, "An unexpected error occurred.", null, 500);
    exit;
}

jsonResponse(true, "ISO is getting uploaded.", null);

if (file_exists($filePath)) {
    if (strpos(realpath($filePath), realpath(UPLOAD_DIR)) !== 0) {
        logError("Security warning: Attempt to delete a file outside the upload directory: $filePath");
        exit;
    }
    if (!unlink($filePath)) {
        logError("Failed to delete file: $filePath");
        exit;
    }
    logInfo("ISO=$safeFileName uploaded successfully and removed locally");
}
?>
