<?php
require_once '../includes/auth.php';
require_once '../includes/response.php';
require_once '../includes/logger.php';
$authData = loginToProxmox();
if($authData === null){
    logError("Proxmox authentication failed.");
    jsonResponse(false, "An unexpected error occurred.", null, 500);
    exit;
}
$cookie = "PVEAuthCookie=" . $authData['ticket'];
$base_url = $authData['base_url'];

$node = filter_input(INPUT_GET, 'node', FILTER_SANITIZE_SPECIAL_CHARS);

if (empty(trim($node))) {
    logError("Invalid request parameters: node=" . var_export($node, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

$url = "$base_url/api2/json/nodes/$node/storage/local/content?content=iso";

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Cookie: $cookie"
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (!$response) {
    logError("cURL error while listing isos on node $node.");
    jsonResponse(false, "Service temporarily unavailable.", null, 503);
    curl_close($ch);
    exit;
}

$responseData = json_decode($response, true);
curl_close($ch);

if (!$responseData || $httpCode !== 200) {
    logError("Unexpected response from Proxmox: HTTP $httpCode, Response: " . json_encode($responseData));
    jsonResponse(false, "An unexpected error occurred.", null, 500);
    exit;
}

jsonResponse(true, "Iso listing initiated.", $responseData);
logInfo("Iso listing initiated.");
?>
