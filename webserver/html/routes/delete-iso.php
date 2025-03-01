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
$csrfToken = $authData['CSRFPreventionToken'];
$base_url = $authData['base_url'];

$isoName = filter_input(INPUT_POST, 'iso_name', FILTER_SANITIZE_SPECIAL_CHARS);
$node = filter_input(INPUT_POST, 'node', FILTER_SANITIZE_SPECIAL_CHARS);
$storage = filter_input(INPUT_POST, 'storage', FILTER_SANITIZE_SPECIAL_CHARS);

if (empty(trim($isoName)) || empty(trim($node)) || empty(trim($storage))) {
    logError("Invalid request parameters: isoName=" . var_export($isoName, true) . ", node=" . var_export($node, true) . ", storage=" . var_export($storage, true));
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

$url = "$base_url/api2/json/nodes/$node/storage/$storage/content/$storage:iso/$isoName";

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Cookie: $cookie",
    "CSRFPreventionToken: $csrfToken"
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (!$response) {
    logError("cURL error while deleting iso $isoName on node $node with storage $storage.");
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

jsonResponse(true, "Iso is getting deleted.", null);
logInfo("ISO=$isoName is getting deleted.");
?>
