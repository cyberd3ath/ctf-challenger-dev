<?php

use PHPUnit\Framework\TestCase;

class ApiTest extends TestCase
{
    private function makeRequest($method, $url, $data = [])
    {
        $ch = curl_init();

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, 1);

            $hasFile = false;
            foreach ($data as $key => $value) {
                if ($value instanceof CURLFile) {
                    $hasFile = true;
                    break;
                }
            }

            if ($hasFile) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: multipart/form-data']);
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
            }
        }

        if ($method === 'GET' && !empty($data)) {
            $url .= '?' . http_build_query($data);
        }

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            return [$httpCode, ['success' => false, 'message' => $curlError, 'data' => null]];
        }

        $decodedResponse = json_decode($response, true);

        if (!is_array($decodedResponse)) {
            return [$httpCode, ['success' => false, 'message' => 'Invalid response', 'data' => $response]];
        }

        return [$httpCode, $decodedResponse];
    }

    public function test00UploadIso()
    {
        $filePath = __DIR__ . '/alpine-test.iso';
        $curlFile = new CURLFile($filePath);

        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/upload.php', [
            'isoFile' => $curlFile,
            'node' => 'pve'
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test01ListIsos()
    {
        list($status, $response) = $this->makeRequest('GET', 'http://localhost/routes/list-isos.php', ['node' => 'pve']);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test02CreateVmFromIso()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/create-vm-from-iso.php', [
            'node' => 'pve',
            'vm_id' => 100,
            'iso_name' => 'local:iso/alpine-test.iso',
            'vm_name' => 'testVm'
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test03ListVms()
    {
        list($status, $response) = $this->makeRequest('GET', 'http://localhost/routes/list-ressources.php', []);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test04VmStatus()
    {
        list($status, $response) = $this->makeRequest('GET', 'http://localhost/routes/status-vm.php', ['node' => 'pve', 'vm_id' => 100]);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test05StartVm()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/start-vm.php', [
            'node' => 'pve',
            'vm_id' => 100
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test06StopVm()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/stop-vm.php', [
            'node' => 'pve',
            'vm_id' => 100
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test07CloneVm()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/clone-vm.php', [
            'source_vm_id' => 100,
            'new_vm_id' => 123,
            'new_vm_name' => 'cloned-vm',
            'target_node' => 'pve',
            'full' => 1,
            'node' => 'pve'
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test08ConvertVm()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/convert-to-template.php', [
            'vm_id' => 123,
            'node' => 'pve'
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test09CreateVmFromTemplate()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/create-vm-from-template.php', [
            'template_id' => 123,
            'vm_id' => 133,
            'vm_name' => 'vm-from-template',
            'node' => 'pve',
            'target_node' => 'pve'
        ]);
        sleep(5);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test10DeleteIso()
    {
        list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/delete-iso.php', [
            'iso_name' => 'alpine-test.iso',
            'node' => 'pve',
            'storage' => 'local'
        ]);
        var_dump($response);
        $this->assertTrue($response['success']);
    }

    public function test11DeleteVmOrTemplate()
    {
        foreach ([100, 123, 133] as $vmId) {
            list($status, $response) = $this->makeRequest('POST', 'http://localhost/routes/delete-vm-template.php', [
                'vm_id' => $vmId,
                'node' => 'pve'
            ]);
            var_dump($response);
            $this->assertTrue($response['success']);
        }
    }
}
