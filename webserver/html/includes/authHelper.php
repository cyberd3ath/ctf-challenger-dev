<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class AuthHelper implements IAuthHelper
{
    private ILogger $logger;
    private IEnv $env;

    public function __construct(
        ILogger $logger = null,
        ISystem $system = new SystemWrapper(),
        IEnv $env = new Env()
    )
    {
        $this->logger = $logger ?? new Logger(system: $system);
        $this->env = $env;
    }

    public function getAuthHeaders($contentType = null)
    {
        $username = $this->env['PROXMOX_USER'];
        $password = $this->env['PROXMOX_PASSWORD'];
        $base_url = $this->env['PROXMOX_HOSTNAME'];
        if (isset($this->env['PROXMOX_PORT'])) {
            $base_url .= ":" . $this->env['PROXMOX_PORT'];
        }

        $url = 'https://' . $base_url . "/api2/json/access/ticket";
        $post_params = json_encode([
            'username' => $username,
            'password' => $password
        ]);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_params);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Content-Type: application/json"
        ]);

        $response = curl_exec($ch);
        if (curl_errno($ch)) {
            $this->logger->logError("cURL error while authenticating to Proxmox");
            curl_close($ch);
            exit;
        }

        $decodedResponse = json_decode($response, true);
        curl_close($ch);

        if (!isset($decodedResponse['data'])) {
            $this->logger->logError("Proxmox Authentication Error");
            exit;
        }

        $cookie = "PVEAuthCookie=" . $decodedResponse['data']['ticket'];
        $csrfToken = $decodedResponse['data']['CSRFPreventionToken'];

        $headers = [
            "Cookie: $cookie",
            "CSRFPreventionToken: $csrfToken"
        ];

        if ($contentType !== null) {
            $headers[] = "Content-Type: $contentType";
        }

        return $headers;
    }

    public function getBackendHeaders($contentType = 'application/json'): array
    {
        $BACKEND_AUTHENTICATION_TOKEN = $this->env['BACKEND_AUTHENTICATION_TOKEN'] ?? null;

        return [
            'Content-Type: ' . $contentType,
            'Authentication-Token: ' . $BACKEND_AUTHENTICATION_TOKEN
        ];
    }
}

