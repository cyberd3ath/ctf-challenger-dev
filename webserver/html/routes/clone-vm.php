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

$sourceVmId = filter_input(INPUT_POST, 'source_vm_id', FILTER_VALIDATE_INT, ["options" => ["min_range" => 100]]);
$newVmId = filter_input(INPUT_POST, 'new_vm_id', FILTER_VALIDATE_INT, ["options" => ["min_range" => 100]]);
$sourceNode = filter_input(INPUT_POST, 'node', FILTER_SANITIZE_SPECIAL_CHARS);
$newVmName = filter_input(INPUT_POST, 'new_vm_name', FILTER_SANITIZE_SPECIAL_CHARS);
$targetNode = filter_input(INPUT_POST, 'target_node', FILTER_SANITIZE_SPECIAL_CHARS);
$fullClone = filter_input(INPUT_POST, 'full', FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

if ($sourceVmId === false || $newVmId === false || empty(trim($sourceNode)) ||empty(trim($newVmName)) || empty(trim($targetNode)) || empty(trim($fullClone))) {
    logError("Invalid request parameters: sourceVmId=" . var_export($sourceVmId, true) . ", newVmId=" . var_export($newVmId, true) . ", node=". var_export($sourceNode, true) . ", newVmName=" . var_export($newVmName, true) . ", targetNode=" . var_export($targetNode, true) . ", fullClone=" . var_export($fullClone, true)) ;
    jsonResponse(false, "Invalid or missing parameters.", null, 400);
    exit;
}

$url = "$base_url/api2/json/nodes/$sourceNode/qemu/$sourceVmId/clone";
$post_params = json_encode([
    'newid' => $newVmId,
    'name' => $newVmName,
    'target' => $targetNode,
    'full' => $fullClone ? 1 : 0
]);

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Cookie: $cookie",
    "CSRFPreventionToken: $csrfToken",
    "Content-Type: application/json"
]);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post_params);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (!$response) {
    logError("cURL error while cloning VM ID $sourceVmId to VM ID $newVmId on node $targetNode.");
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

jsonResponse(true, "VM is getting cloned.", null);
logInfo("VM ID=$sourceVmId cloned to VM ID=$newVmId");
?>
