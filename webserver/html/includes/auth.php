<?php
function loginToProxmox() {
    require __DIR__ . '/../vendor/autoload.php';
    require_once __DIR__ . '/logger.php';
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . "/..");
    $dotenv->load();

    $username = $_ENV['PROXMOX_USERNAME'];
    $password = $_ENV['PROXMOX_PASSWORD'];
    $base_url = $_ENV['PROXMOX_BASE_URL'];

    $url = $base_url."/api2/json/access/ticket";
    $post_params = json_encode([
        'username' => $username,
        'password' => $password
    ]);

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_params);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json"
    ]);

    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        logError("cURL error while Authenticating to Proxmox");
        curl_close($ch);
        return null;
    }
    curl_close($ch);

    $decodedResponse = json_decode($response, true);

    if (!(isset($decodedResponse['data']))) {
        logError("Proxmox Authentication Error");
        return null;
    }
    return [
        'ticket' => $decodedResponse['data']['ticket'],
        'CSRFPreventionToken' => $decodedResponse['data']['CSRFPreventionToken'],
        'base_url' => $base_url
    ];

}
