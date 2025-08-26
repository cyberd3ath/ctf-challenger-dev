<?php
declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';
use PHPUnit\Framework\TestCase;

class LogoutHandlerTest extends TestCase
{
    private ISecurityHelper $securityHelper;
    private ILogger $logger;

    private ISession $session;
    private IServer $server;

    public function setUp(): void {
        $this->securityHelper = $this->createMock(ISecurityHelper::class);
        $this->logger = $this->createMock(ILogger::class);

        $this->session = new MockSession();
        $this->server = new MockServer();
    }

    public function testFailedInitSecureSessionThrowsException(): void {
        $securityHelper = $this->createMock(ISecurityHelper::class);
        $securityHelper->method('initSecureSession')->will($this->throwException(new Exception('Session init failed')));

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Session init failed');

        new LogoutHandler(
            $securityHelper,
            $this->logger,
            $this->session,
            $this->server
        );
    }

    public function testInvalidSessionThrowsException(): void
    {
        $this->securityHelper->method('validateSession')->willReturn(false);
        $this->logger->method('anonymizeIp')->willReturn('anonymized-ip');
        $this->server['REMOTE_ADDR'] = '10.0.0.10';

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unauthorized - Please login');
        $this->expectExceptionCode(401);

        new LogoutHandler(
            $this->securityHelper,
            $this->logger,
            $this->session,
            $this->server
        );
    }

    public function testSuccessfulLogout(): void
    {
        $this->securityHelper->method('validateSession')->willReturn(true);
        $this->securityHelper->method('validateCsrfToken')->willReturn(true);
        $this->session['authenticated'] = true;
        $this->session['user_id'] = 1;

        $this->server['HTTP_X_CSRF_TOKEN'] = 'valid-csrf-token';

        $this->assertNotEmpty($this->session);

        ob_start();
        $handler = new LogoutHandler(
            $this->securityHelper,
            $this->logger,
            $this->session,
            $this->server
        );
        $handler->handleRequest();
        ob_get_clean();

        $this->assertEmpty($this->session->all());
    }

    public function testInvalidCsrfTokenGivesError(): void
    {
        $this->securityHelper->method('validateSession')->willReturn(true);
        $this->securityHelper->method('validateCsrfToken')->willReturn(false);
        $this->session['authenticated'] = true;
        $this->session['user_id'] = 1;

        $this->server['HTTP_X_CSRF_TOKEN'] = 'invalid-csrf-token';

        ob_start();
        $handler = new LogoutHandler(
            $this->securityHelper,
            $this->logger,
            $this->session,
            $this->server
        );
        $handler->handleRequest();
        $output = ob_get_clean();
        $json = json_decode($output, true);

        $this->assertFalse($json['success']);
        $this->assertEquals('Invalid security token', $json['message']);
    }
}