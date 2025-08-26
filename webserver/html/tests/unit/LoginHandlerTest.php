<?php
declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use PHPUnit\Framework\TestCase;

class LoginHandlerTest extends TestCase
{
    private PDO $pdo;

    private IDatabaseHelper $databaseHelper;
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;
    private IPost $post;

    private ISystem $system;

    protected function setUp(): void
    {
        // Mock dependencies
        $this->databaseHelper = $this->createMock(IDatabaseHelper::class);
        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->logger = $this->createMock(ILogger::class);

        $this->session = $this->createMock(ISession::class);
        $this->server = $this->createMock(IServer::class);
        $this->post = $this->createMock(IPost::class);

        $this->system = $this->createMock(ISystem::class);
    }

    public function testAlreadyAuthenticatedWithoutCsrfTokenRedirectsCorrectly(): void
    {
        $this->session = new MockSession();
        $this->securityHelper = new SecurityHelper($this->logger, $this->session, new MockSystem());

        $this->server['REQUEST_METHOD'] = 'GET';
        $this->server['REMOTE_ADDR'] = '10.0.0.200';

        $this->session['user_id'] = 1;
        $this->session['username'] = 'admin';
        $this->session['csrf_token'] = null;
        $this->session['authenticated'] = true;

        $this->system = new MockSystem();

        $this->assertEmpty($this->system->getCookies());

        ob_start();
        $loginHandler = new LoginHandler(
            $this->databaseHelper,
            $this->securityHelper,
            $this->logger,
            $this->session,
            $this->server,
            $this->post,
            $this->system
        );
        $loginHandler->handleRequest();
        $output = ob_get_clean();
        $jsonOutput = json_decode($output, true);

        $this->assertTrue($jsonOutput['success']);
        $this->assertNotNull($jsonOutput['csrf_token']);
        $this->assertEquals('/dashboard', $jsonOutput['redirect']);
    }
}
