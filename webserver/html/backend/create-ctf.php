<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

class CtfCreationHandler
{
    private PDO $pdo;
    private int $userId;
    private string $action;
    private int $isActive;
    private array $inputData;
    private array $config;
    private array $generalConfig;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ICurlHelper $curlHelper;
    private IAuthHelper $authHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IGet $get;
    private IPost $post;
    private IFiles $files;

    private ISystem $system;

    /**
     * @throws Exception
     */
    public function __construct(
        array $config,
        array $generalConfig,

        IDatabaseHelper $databaseHelper = null,
        ISecurityHelper $securityHelper = null,
        ICurlHelper $curlHelper = null,
        IAuthHelper $authHelper = null,
        ILogger $logger = null,

        ISession $session = new Session(),
        IServer $server = new Server(),
        IGet $get = new Get(),
        IPost $post = new Post(),
        IFiles $files = new Files(),

        ISystem $system = new SystemWrapper(),
        IEnv $env = new Env()
    )
    {
        $this->session = $session;
        $this->server = $server;
        $this->get = $get;
        $this->post = $post;
        $this->files = $files;

        $this->databaseHelper = $databaseHelper ?? new DatabaseHelper($logger, $system);
        $this->securityHelper = $securityHelper ?? new SecurityHelper($logger, $session, $system);
        $this->curlHelper = $curlHelper ?? new CurlHelper($env);
        $this->authHelper = $authHelper ?? new AuthHelper($logger, $system, $env);
        $this->logger = $logger ?? new Logger(system: $system);

        $this->system = $system;

        header('Content-Type: application/json');
        $this->config = $config;
        $this->generalConfig = $generalConfig;
        $this->pdo = $this->databaseHelper->getPDO();
        $this->initSession();
        $this->validateAccess();
        $this->userId = $this->session['user_id'];
        $this->action = $this->get['action'] ?? '';
        $this->inputData = $this->parseInputData();

        $this->logger->logDebug("Initialized CTFCreationHandler for user ID: $this->userId, Action: $this->action");
    }

    private function initSession(): void
    {
        try {
            $this->securityHelper->initSecureSession();
        } catch (Exception $e) {
            $this->logger->logError("Session initialization failed: " . $e->getMessage());
            throw new RuntimeException('Session initialization error', 401);
        }
    }

    /**
     * @throws Exception
     */
    private function validateAccess(): void
    {
        if (!$this->securityHelper->validateSession()) {
            $this->logger->logWarning("Unauthorized access attempt from IP: " . $this->logger->anonymizeIp($this->server['REMOTE_ADDR'] ?? 'unknown'));
            throw new RuntimeException('Unauthorized - Please login', 401);
        }

        $csrfToken = $this->server['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!$this->securityHelper->validateCsrfToken($csrfToken)) {
            $this->logger->logWarning("Invalid CSRF token from user ID: " . ($this->session['user_id'] ?? 'unknown'));
            throw new RuntimeException('Invalid request token', 403);
        }

        if (!$this->securityHelper->validateAdminAccess($this->pdo)) {
            $this->logger->logWarning("Unauthorized admin access attempt by user ID: ". ($this->session['user_id'] ?? 'unknown'));
            throw new RuntimeException('Unauthorized - Admin access required', 403);
        }
    }

    private function parseInputData(): array
    {
        if ($this->server['REQUEST_METHOD'] === 'GET') {
            return [];
        }

        $jsonInput = json_decode($this->system->file_get_contents('php://input'), true);
        if ($jsonInput !== null) {
            return array_merge($this->post->all(), $jsonInput);
        }

        return $this->post->all();
    }

    public function handleRequest(): void
    {
        try {
            switch ($this->server['REQUEST_METHOD']) {
                case 'GET':
                    $this->handleGetRequest();
                    break;
                case 'POST':
                    $this->handlePostRequest();
                    break;
                default:
                    throw new RuntimeException('Method not allowed', 405);
            }
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }

    private function handleGetRequest(): void
    {
        $ovas = $this->getAvailableOVAs();
        echo json_encode(['success' => true, 'ovas' => $ovas]);
    }

    /**
     * @throws Exception
     */
    private function handlePostRequest(): void
    {
        $validationResult = $this->validateInput();
        if (!empty($validationResult['errors'])) {
            $this->logger->logWarning("Validation errors for user $this->userId: " . implode(', ', $validationResult['errors']));
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'errors' => $validationResult['errors'],
                'fields' => array_unique($validationResult['errorFields'])
            ]);
            defined('PHPUNIT_RUNNING') || exit;
        }

        $this->checkDuplicateChallengeName();

        $imagePath = $this->handleImageUpload();
        $challengeId = $this->createChallenge($imagePath);

        echo json_encode([
            'success' => true,
            'message' => 'CTF challenge created successfully',
            'challenge_id' => $challengeId
        ]);
    }

    private function validateInput(): array
    {
        $errors = [];
        $errorFields = [];

        function validateFieldLength(string $value, int $maxLength, string $fieldName, string $fieldKey, array &$errors, array &$errorFields): void
        {
            if ($fieldName === 'name' || $fieldName === 'description') {
                if (empty($value)) {
                    $errors[] = "$fieldName is required";
                    $errorFields[] = "ctf-$fieldKey";
                }
            }
            if (strlen($value) > $maxLength) {
                $errors[] = "$fieldName cannot exceed $maxLength characters";
                $errorFields[] = "ctf-$fieldKey";
            }
        }

        $fields = [
            'name' => [$this->generalConfig['ctf']['MAX_CTF_NAME_LENGTH'], 'CTF name', 'name'],
            'description' => [$this->generalConfig['ctf']['MAX_CTF_DESCRIPTION_LENGTH'], 'Description', 'description'],
            'hint' => [$this->generalConfig['ctf']['MAX_GENERAL_HINT_LENGTH'], 'Hint', 'hint'],
            'solution' => [$this->generalConfig['ctf']['MAX_SOLUTION_LENGTH'], 'Solution', 'solution'],
        ];

        foreach ($fields as $key => [$max, $label, $fieldKey]) {
            $value = trim($this->inputData[$key] ?? '');
            validateFieldLength($value, $max, $label, $fieldKey, $errors, $errorFields);

            if ($key === 'name' && !empty($value) && !preg_match('/' . $this->generalConfig['ctf']['CTF_NAME_REGEX'] . '/', $value)) {
                $errors[] = "$label contains invalid characters";
                $errorFields[] = "ctf-$fieldKey";
            }
        }

        $category = trim($this->inputData['category'] ?? '');
        if (empty($category)) {
            $errors[] = 'Category is required';
            $errorFields[] = 'ctf-category';
        } elseif (!in_array($category, $this->config['challenge']['VALID_CATEGORIES'])) {
            $errors[] = 'Invalid category';
            $errorFields[] = 'ctf-category';
        }

        $difficulty = trim($this->inputData['difficulty'] ?? '');
        if (empty($difficulty)) {
            $errors[] = 'Difficulty is required';
            $errorFields[] = 'ctf-difficulty';
        } elseif (!in_array($difficulty, $this->config['challenge']['VALID_DIFFICULTIES'])) {
            $errors[] = 'Invalid difficulty';
            $errorFields[] = 'ctf-difficulty';
        }

        $this->isActive = (int)filter_var($this->inputData['isActive'], FILTER_VALIDATE_BOOLEAN);

        try {
            $subnets = $this->getValidatedJson('subnets');
            $vms = $this->getValidatedJson('vms');
            $flags = $this->getValidatedJson('flags');
            $hints = $this->getValidatedJson('hints');
        } catch (RuntimeException $e) {
            $errors[] = $e->getMessage();
            return compact('errors', 'errorFields');
        }

        $counts = [
            ['items' => $vms, 'label' => 'VM', 'min' => 1, 'max' => $this->generalConfig['ctf']['MAX_VM_COUNT']],
            ['items' => $subnets, 'label' => 'Subnet', 'min' => 1, 'max' => $this->generalConfig['ctf']['MAX_SUBNET_COUNT']],
            ['items' => $flags, 'label' => 'flag', 'min' => 1, 'max' => $this->generalConfig['ctf']['MAX_FLAG_COUNT']],
            ['items' => $hints, 'label' => 'hint', 'min' => 0, 'max' => $this->generalConfig['ctf']['MAX_HINT_COUNT']],
        ];

        foreach ($counts as ['items' => $items, 'label' => $label, 'min' => $min, 'max' => $max]) {
            $count = count($items);
            if ($count < $min) {
                $errors[] = "Please add at least $min $label" . ($min > 1 ? 's' : '');
            } elseif ($count > $max) {
                $errors[] = ucfirst($label) . " limit of $max exceeded";
            }
        }

        $vmNames = [];
        foreach ($vms as $vm) {
            $vmName = trim($vm['name'] ?? '');
            if (empty($vmName)) {
                $errors[] = "VM name is required";
            } elseif (strlen($vmName) > $this->generalConfig['ctf']['MAX_VM_NAME_LENGTH']) {
                $errors[] = "VM name cannot exceed " . $this->generalConfig['ctf']['MAX_VM_NAME_LENGTH'] . " characters";
            } elseif (!preg_match('/' . $this->generalConfig['ctf']['VM_SUBNET_NAME_REGEX'] . '/', $vmName)) {
                $errors[] = "VM Name $vmName contains invalid characters";
            } elseif (in_array($vmName, $vmNames)) {
                $errors[] = "Duplicate VM name found: $vmName";
            }
            $vmNames[] = $vmName;

            $cores = $vm['cores'] ?? 0;
            if ($cores < 1 || $cores > $this->generalConfig['ctf']['MAX_VM_CORES']) {
                $errors[] = "VM $vmName: CPU cores must be between 1-" . $this->generalConfig['ctf']['MAX_VM_CORES'];
            }

            $ram = $vm['ram_gb'] ?? 0;
            if ($ram < 1 || $ram > $this->generalConfig['ctf']['MAX_VM_RAM']) {
                $errors[] = "VM $vmName: RAM must be between 1-" . $this->generalConfig['ctf']['MAX_VM_RAM'] . "GB";
            }

            $domain = trim($vm['domain_name'] ?? '');
            if (empty($domain)) {
                $errors[] = "VM $vmName: Domain name is required";
            } elseif (strlen($domain) > $this->generalConfig['ctf']['MAX_VM_DOMAIN_LENGTH']) {
                $errors[] = "VM $vmName: Domain name cannot exceed " . $this->generalConfig['ctf']['MAX_VM_DOMAIN_LENGTH'];
            } elseif (!preg_match('/' . $this->generalConfig['ctf']['DOMAIN_REGEX'] . '/', $domain)) {
                $errors[] = "VM $vmName: Domain name contains invalid characters or has invalid structure";
            }
        }

        $subnetNames = [];
        foreach ($subnets as $subnet) {
            $subnetName = trim($subnet['name'] ?? '');
            if (empty($subnetName)) {
                $errors[] = "Subnet name is required";
            } elseif (strlen($subnetName) > $this->generalConfig['ctf']['MAX_SUBNET_NAME_LENGTH']) {
                $errors[] = "Subnet name cannot exceed " . $this->generalConfig['ctf']['MAX_SUBNET_NAME_LENGTH'] . " characters";
            } elseif (!preg_match('/' . $this->generalConfig['ctf']['VM_SUBNET_NAME_REGEX'] . '/', $subnetName)) {
                $errors[] = "Subnet Name $subnetName contains invalid characters";
            } elseif (in_array($subnetName, $subnetNames)) {
                $errors[] = "Duplicate subnet name found: $subnetName";
            }
            $subnetNames[] = $subnetName;

            if (empty($subnet['attached_vms'] ?? [])) {
                $errors[] = "Subnet $subnetName has no attached VMs";
            }
        }

        foreach ($flags as $i => $flag) {
            $n = $i + 1;
            if (empty(trim($flag['flag'] ?? ''))) {
                $errors[] = "Flag #$n: Flag text is required";
            } elseif (strlen($flag['flag']) > $this->generalConfig['ctf']['MAX_FLAG_LENGTH']) {
                $errors[] = "Flag #$n: Flag cannot exceed " . $this->generalConfig['ctf']['MAX_FLAG_LENGTH'] . " characters";
            }

            $points = $flag['points'] ?? 0;
            if ($points < 1) {
                $errors[] = "Flag #$n: Points must be at least 1";
            } elseif ($points > $this->generalConfig['ctf']['MAX_FLAG_POINTS']) {
                $errors[] = "Flag #$n: Points cannot exceed " . $this->generalConfig['ctf']['MAX_FLAG_POINTS'];
            }

            if (strlen($flag['description'] ?? '') > $this->generalConfig['ctf']['MAX_FLAG_DESCRIPTION_LENGTH']) {
                $errors[] = "Flag #$n: Description cannot exceed " . $this->generalConfig['ctf']['MAX_FLAG_DESCRIPTION_LENGTH'];
            }
        }

        foreach ($hints as $i => $hint) {
            $n = $i + 1;
            if (empty(trim($hint['hint_text'] ?? ''))) {
                $errors[] = "Hint #$n: Hint text is required";
            } elseif (strlen($hint['hint_text']) > $this->generalConfig['ctf']['MAX_HINT_LENGTH']) {
                $errors[] = "Hint #$n: Hint cannot exceed " . $this->generalConfig['ctf']['MAX_HINT_LENGTH'] . " characters";
            }

            $points = $hint['unlock_points'] ?? -1;
            if ($points < 0) {
                $errors[] = "Hint #$n: Points must be 0 or greater";
            } elseif ($points > $this->generalConfig['ctf']['MAX_HINT_POINTS']) {
                $errors[] = "Hint #$n: Maximum points per hint cannot exceed " . $this->generalConfig['ctf']['MAX_HINT_POINTS'];
            }
        }

        try {
            $this->validateNetworkReachability($vms, $subnets);
        } catch (Exception $e) {
            $errors[] = $e->getMessage();
        }

        return compact('errors', 'errorFields');
    }

    private function getValidatedJson(string $field): array
    {
        try {
            $json = json_decode($this->inputData[$field] ?? '[]', true, 512, JSON_THROW_ON_ERROR);
            return is_array($json) ? $json : [];
        } catch (JsonException $e) {
            $this->logger->logError("Invalid JSON input for field $field from user $this->userId: " . $e->getMessage());
            throw new RuntimeException("Invalid input format for $field", 400);
        }
    }

    private function checkDuplicateChallengeName(): void
    {
        $name = trim($this->inputData['name']);
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) FROM challenge_templates 
            WHERE LOWER(name) = LOWER(:name) AND creator_id = :user_id
        ");
        $stmt->execute([
            'name' => $name,
            'user_id' => $this->userId
        ]);

        if ($stmt->fetchColumn() > 0) {
            $this->logger->logWarning("Duplicate challenge name attempt by user $this->userId: $name");
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'errors' => ['A challenge with this name already exists. Please choose a different name.'],
                'fields' => ['ctf-name']
            ]);
            defined('PHPUNIT_RUNNING') || exit;
        }
    }

    private function handleImageUpload(): ?string
    {
        if (empty($this->files['image']['tmp_name'])) {
            return null;
        }

        $file = $this->files['image'];

        if (!in_array($file['type'], $this->generalConfig['ctf']['ALLOWED_IMAGE_TYPES'])) {
            throw new RuntimeException('Invalid image type. Only JPG, PNG and GIF are allowed', 400);
        }

        if ($file['size'] > $this->generalConfig['ctf']['MAX_CTF_IMAGE_SIZE']) {
            throw new RuntimeException('Image size too large. Maximum 2MB allowed', 400);
        }

        $imageInfo = @getimagesize($file['tmp_name']);
        if ($imageInfo === false) {
            throw new RuntimeException('Uploaded file is not a valid image', 400);
        }

        $uploadDir = __DIR__ . '/..' . $this->config['challenge']['UPLOAD_DIR'];
        if (!$this->system->file_exists($uploadDir)) {
            if (!$this->system->mkdir($uploadDir, 0755, true)) {
                throw new RuntimeException('Failed to create upload directory', 500);
            }
        }

        $extension = $this->system->pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = uniqid('challenge_') . '.' . $extension;
        $destination = $uploadDir . $filename;

        if (!$this->system->move_uploaded_file($file['tmp_name'], $destination)) {
            $error = error_get_last();
            throw new RuntimeException('Failed to save uploaded image: ' . ($error['message'] ?? 'Unknown error'), 500);
        }

        $this->system->chmod($destination, 0644);
        return $this->config['challenge']['UPLOAD_DIR'] . $filename;
    }

    /**
     * @throws Exception
     */
    private function createChallenge(?string $imagePath): int
    {
        $this->pdo->beginTransaction();

        try {
            $challengeId = $this->insertChallengeTemplate($imagePath);
            $this->processVMs($challengeId);
            $this->processSubnets($challengeId);
            $this->processFlags($challengeId);
            $this->processHints($challengeId);

            $this->pdo->commit();

            $this->importMachineTemplates($challengeId);
            return $challengeId;
        } catch (Exception $e) {
            $this->pdo->rollBack();
            $this->logger->logError("Database transaction rolled back due to error: " . $e->getMessage());

            if (!empty($imagePath)) {
                $fullPath = __DIR__ . '/..' . $imagePath;
                if ($this->system->file_exists($fullPath)) {
                    @$this->system->unlink($fullPath);
                    $this->logger->logDebug("Cleaned up uploaded image after error: $fullPath");
                }
            }

            throw $e;
        }
    }

    private function insertChallengeTemplate(?string $imagePath): int
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO challenge_templates (
                name, description, category, difficulty, 
                image_path, is_active, creator_id, hint, solution
            ) VALUES (
                :name, :description, :category, :difficulty, 
                :image_path, :is_active, :creator_id, :hint, :solution
            ) RETURNING id
        ");

        $stmt->execute([
            'name' => trim($this->inputData['name']),
            'description' => trim($this->inputData['description']),
            'category' => trim($this->inputData['category']),
            'difficulty' => trim($this->inputData['difficulty']),
            'image_path' => $imagePath,
            'is_active' => $this->isActive,
            'creator_id' => $this->userId,
            'hint' => $this->inputData['hint'] ?? null,
            'solution' => $this->inputData['solution'] ?? null,
        ]);

        $challengeId = $stmt->fetchColumn();
        $this->logger->logInfo("Challenge template created with ID: $challengeId");
        return $challengeId;
    }

    private function processVMs(int $challengeId): void
    {
        $vms = $this->getValidatedJson('vms');

        foreach ($vms as $vm) {
            $vmName = $vm['name'];

            $stmt = $this->pdo->prepare("
                SELECT proxmox_filename FROM disk_files 
                WHERE display_name = :filename AND user_id = :user_id
            ");
            $stmt->execute([
                'filename' => $vm['ova_name'],
                'user_id' => $this->userId
            ]);
            $proxmoxFilename = $stmt->fetchColumn();

            if (!$proxmoxFilename) {
                $this->logger->logError("Invalid OVA file reference by user $this->userId: " . $vm['ova_name']);
                throw new RuntimeException("Invalid OVA file reference for VM: $vmName", 400);
            }

            $stmt = $this->pdo->prepare("
                INSERT INTO machine_templates (
                    challenge_template_id, name, disk_file_path, 
                    cores, ram_gb
                ) VALUES (
                    :challenge_id, :name, :ova_file_path, 
                    :cores, :ram_gb
                ) RETURNING id
            ");

            $stmt->execute([
                'challenge_id' => $challengeId,
                'name' => $vmName,
                'ova_file_path' => '/var/lib/vz/import/' . $proxmoxFilename,
                'cores' => $vm['cores'],
                'ram_gb' => $vm['ram_gb']
            ]);

            $machineId = $stmt->fetchColumn();

            if (!empty($vm['domain_name'])) {
                $stmt = $this->pdo->prepare("
                    INSERT INTO domain_templates (
                        machine_template_id, domain_name
                    ) VALUES (
                        :machine_id, :domain_name
                    )
                ");

                $stmt->execute([
                    'machine_id' => $machineId,
                    'domain_name' => $vm['domain_name']
                ]);
            }
        }
    }

    private function processSubnets(int $challengeId): void
    {
        $subnets = $this->getValidatedJson('subnets');

        foreach ($subnets as $subnet) {
            $subnetName = $subnet['name'];

            $stmt = $this->pdo->prepare("
                INSERT INTO network_templates (
                    name, accessible, is_dmz
                ) VALUES (
                    :name, :accessible, :is_dmz
                ) RETURNING id
            ");

            $stmt->bindValue(':name', $subnetName, PDO::PARAM_STR);
            $stmt->bindValue(':accessible', (bool)($subnet['accessible'] ?? false), PDO::PARAM_BOOL);
            $stmt->bindValue(':is_dmz', (bool)($subnet['dmz'] ?? false), PDO::PARAM_BOOL);

            $stmt->execute();
            $networkId = $stmt->fetchColumn();

            foreach ($subnet['attached_vms'] as $vmName) {
                $stmt = $this->pdo->prepare("
                    SELECT id FROM machine_templates 
                    WHERE name = :vm_name AND challenge_template_id = :challenge_id
                ");
                $stmt->execute([
                    'vm_name' => $vmName,
                    'challenge_id' => $challengeId
                ]);
                $machineId = $stmt->fetchColumn();

                if (!$machineId) {
                    $this->logger->logError("Machine template not found for VM $vmName in challenge $challengeId");
                    throw new RuntimeException("Machine template '$vmName' not found for this challenge");
                }

                $stmt = $this->pdo->prepare("
                    INSERT INTO network_connection_templates (
                        machine_template_id, network_template_id
                    ) VALUES (
                        :machine_id, :network_id
                    )
                ");
                $stmt->execute([
                    'machine_id' => $machineId,
                    'network_id' => $networkId
                ]);
            }
        }
    }

    private function processFlags(int $challengeId): void
    {
        $flags = $this->getValidatedJson('flags');

        foreach ($flags as $flag) {
            $stmt = $this->pdo->prepare("
                INSERT INTO challenge_flags (
                    challenge_template_id, flag, description, points, order_index
                ) VALUES (
                    :challenge_id, :flag, :description, :points, :order_index
                )
            ");

            $stmt->execute([
                'challenge_id' => $challengeId,
                'flag' => $flag['flag'],
                'description' => $flag['description'],
                'points' => $flag['points'],
                'order_index' => $flag['order_index']
            ]);
        }
    }

    private function processHints(int $challengeId): void
    {
        $hints = $this->getValidatedJson('hints');

        foreach ($hints as $hint) {
            $stmt = $this->pdo->prepare("
                INSERT INTO challenge_hints (
                    challenge_template_id, hint_text, unlock_points, order_index
                ) VALUES (
                    :challenge_id, :hint_text, :unlock_points, :order_index
                )
            ");

            $stmt->execute([
                'challenge_id' => $challengeId,
                'hint_text' => $hint['hint_text'],
                'unlock_points' => $hint['unlock_points'],
                'order_index' => $hint['order_index']
            ]);
        }
    }

    private function importMachineTemplates(int $challengeId): void
    {
        $response = $this->curlHelper->makeBackendRequest(
            '/import-machine-templates',
            'POST',
            $this->authHelper->getBackendHeaders(),
            ['challenge_template_id' => $challengeId]
        );

        if (!$response['success']) {
            $this->logger->logError("Failed to import machine templates for challenge $challengeId. Response: " . json_encode($response));
            $this->revertChallengeCreation($challengeId);
            throw new RuntimeException('Failed to import machine templates', 500);
        }

        $this->logger->logDebug("Successfully imported machine templates for challenge $challengeId");
    }

    private function revertChallengeCreation(int $challengeId): void
    {
        try {
            $this->pdo->beginTransaction();

            $this->pdo->prepare("DELETE FROM challenge_flags WHERE challenge_template_id = ?")
                ->execute([$challengeId]);

            $this->pdo->prepare("DELETE FROM challenge_hints WHERE challenge_template_id = ?")
                ->execute([$challengeId]);

            $stmt = $this->pdo->prepare("SELECT id FROM machine_templates WHERE challenge_template_id = ?");
            $stmt->execute([$challengeId]);
            $machineIds = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (!empty($machineIds)) {
                $placeholders = implode(',', array_fill(0, count($machineIds), '?'));
                $this->pdo->prepare("DELETE FROM network_connection_templates WHERE machine_template_id IN ($placeholders)")
                    ->execute($machineIds);

                $this->pdo->prepare("DELETE FROM domain_templates WHERE machine_template_id IN ($placeholders)")
                    ->execute($machineIds);

                $this->pdo->prepare("DELETE FROM machine_templates WHERE id IN ($placeholders)")
                    ->execute($machineIds);
            }

            $this->pdo->prepare("DELETE FROM network_templates WHERE id IN (
                SELECT network_template_id FROM network_connection_templates 
                WHERE machine_template_id IN (
                    SELECT id FROM machine_templates WHERE challenge_template_id = ?
                )
            )")->execute([$challengeId]);

            $this->pdo->prepare("DELETE FROM challenge_templates WHERE id = ?")
                ->execute([$challengeId]);

            $this->pdo->commit();
            $this->logger->logInfo("Successfully reverted challenge creation for ID: $challengeId");
        } catch (Exception $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            $this->logger->logError("Failed to revert challenge creation for ID $challengeId: " . $e->getMessage());
        }
    }

    private function getAvailableOVAs(): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT 
                    id,
                    display_name AS name,
                    upload_date AS date
                FROM disk_files
                WHERE user_id = :user_id
                ORDER BY upload_date DESC
            ");

            $stmt->execute(['user_id' => $this->userId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->logger->logError("Error fetching OVAs for user $this->userId: " . $e->getMessage());
            throw new RuntimeException('Could not retrieve OVAs', 500);
        }
    }

    private function validateNetworkReachability(array $vms, array $subnets): void
    {
        foreach ($subnets as $subnet) {
            if (empty($subnet['attached_vms'])) {
                throw new RuntimeException(
                    "Subnet '{$subnet['name']}' has no attached VMs. Remove it or add VMs."
                );
            }
        }

        $vmSubnetMap = [];
        $subnetVmMap = [];
        $publicSubnets = [];

        foreach ($subnets as $subnet) {
            $subnetName = $subnet['name'];
            $subnetVmMap[$subnetName] = $subnet['attached_vms'];

            if ($subnet['accessible'] ?? false) {
                $publicSubnets[] = $subnetName;
            }

            foreach ($subnet['attached_vms'] as $vmName) {
                $vmSubnetMap[$vmName][] = $subnetName;
            }
        }

        $unreachableVms = [];
        foreach ($vms as $vm) {
            $vmName = $vm['name'];
            if (!$this->isVMReachable($vmName, $vmSubnetMap, $subnetVmMap, $publicSubnets)) {
                $unreachableVms[] = $vmName;
            }
        }

        if (!empty($unreachableVms)) {
            throw new RuntimeException(
                "Unreachable VMs detected (no path to public subnets): " .
                implode(', ', $unreachableVms)
            );
        }

        foreach ($subnets as $subnet) {
            $subnetName = $subnet['name'];
            $onlyHere = true;

            foreach ($subnet['attached_vms'] as $vm) {
                if (count($vmSubnetMap[$vm] ?? []) > 1) {
                    $onlyHere = false;
                    break;
                }
            }

            if ($onlyHere && !($subnet['accessible'] ?? false)) {
                throw new RuntimeException(
                    "Subnet '$subnetName' is not reachable and contains only VMs that are exclusively in it. These VMs would be isolated."
                );
            }
        }
    }

    private function isVMReachable(
        string $vmName,
        array  $vmSubnetMap,
        array  $subnetVmMap,
        array  $publicSubnets
    ): bool
    {
        $visitedSubnets = [];
        $queue = $vmSubnetMap[$vmName] ?? [];

        while (!empty($queue)) {
            $subnet = array_shift($queue);

            if (in_array($subnet, $publicSubnets)) {
                return true;
            }

            $visitedSubnets[] = $subnet;

            foreach ($subnetVmMap[$subnet] as $connectedVm) {
                foreach ($vmSubnetMap[$connectedVm] as $connectedSubnet) {
                    if (!in_array($connectedSubnet, $visitedSubnets)) {
                        $queue[] = $connectedSubnet;
                    }
                }
            }
        }

        return false;
    }

    private function handleError(Exception $e): void
    {
        $code = $e->getCode() >= 400 && $e->getCode() < 600 ? $e->getCode() : 500;
        $errorMessage = $code >= 500 ? 'An internal server error occurred' : $e->getMessage();

        if ($code >= 500) {
            $this->logger->logError("Internal error : " . $e->getMessage());
        } else {
            $this->logger->logWarning("CTF creation error: " . $e->getMessage());
        }

        http_response_code($code);
        echo json_encode([
            'success' => false,
            'message' => $errorMessage,
            'redirect' => $code === 401 ? '/login' : null
        ]);
        defined('PHPUNIT_RUNNING') || exit;
    }
}

// @codeCoverageIgnoreStart

if(defined('PHPUNIT_RUNNING'))
    return;

try {
    $config = require __DIR__ . '/../config/backend.config.php';
    $system = new SystemWrapper();
    $generalConfig = json_decode($system->file_get_contents(__DIR__ . '/../config/general.config.json'), true);

    $handler = new CtfCreationHandler(config: $config, generalConfig: $generalConfig);
    $handler->handleRequest();
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    http_response_code($errorCode);
    $logger = new Logger();
    $logger->logError("Error in create-ctf endpoint: " . $e->getMessage() . " (Code: $errorCode)");
    $response = [
        'success' => false,
        'message' => $e->getMessage()
    ];

    if ($errorCode === 401) {
        $response['redirect'] = '/login';
    }

    echo json_encode($response);
}

// @codeCoverageIgnoreEnd
