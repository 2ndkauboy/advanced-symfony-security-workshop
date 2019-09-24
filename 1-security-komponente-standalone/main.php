<?php

require_once 'vendor/autoload.php';

use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;
use Symfony\Component\Security\Core\Encoder\PlaintextPasswordEncoder;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\User;

const PROVIDER_KEY = 'default';

// WRITE CODE AFTER THIS

/**
 * Verwenden solltet ihr:
 * - InMemoryUserProvider
 * - PlaintextPasswordEncoder
 * - DaoAuthenticationProvider
 */
$userProvider = new InMemoryUserProvider(
    [
        'admin' => [
            'password' => 'admin-password',
            'roles'    => ['ROLE_ADMIN'],
        ],
        'user'  => [
            'password' => 'user-password',
            'roles'    => ['ROLE_USER'],
        ],
        'never' => [
            'password' => 'never-password',
            'roles'    => [],
        ],
    ]
);
$userChecker = new UserChecker();
$encoderFactory = new EncoderFactory(
    [
        User::class => new PlaintextPasswordEncoder(),
    ]
);
$authenticationManager = new AuthenticationProviderManager(
    [
        new DaoAuthenticationProvider($userProvider, $userChecker, PROVIDER_KEY, $encoderFactory),
    ]
);

// WRITE CODE BEFORE THIS

// Tokens
$adminToken = new UsernamePasswordToken('admin', 'admin-password', PROVIDER_KEY);
$userToken = new UsernamePasswordToken('user', 'user-password', PROVIDER_KEY);
$neverAuthenticateToken = new UsernamePasswordToken('never', 'never-password', PROVIDER_KEY);

// Authentication
$adminToken = $authenticationManager->authenticate($adminToken);
$userToken = $authenticationManager->authenticate($userToken);
$neverAuthenticateToken = $authenticationManager->authenticate($neverAuthenticateToken);
if (!$adminToken->isAuthenticated() || !$userToken->isAuthenticated()) {
    throw new RuntimeException('User is not authenticated!');
}
if ($neverAuthenticateToken->isAuthenticated()) {
    throw new RuntimeException('$neverAuthenticateToken must not be authenticated!');
}
echo 'Authentication succeeded!'.PHP_EOL;

// Authorization
$accessDecisionManager = new AccessDecisionManager([new RoleVoter()]);

$adminIsAdmin = $accessDecisionManager->decide($adminToken, ['ROLE_ADMIN']);
$adminIsUser = $accessDecisionManager->decide($adminToken, ['ROLE_USER']);
$userIsAdmin = $accessDecisionManager->decide($userToken, ['ROLE_ADMIN']);
$userIsUser = $accessDecisionManager->decide($userToken, ['ROLE_USER']);

if (!$adminIsAdmin || $adminIsUser || $userIsAdmin || !$userIsUser) {
    throw new RuntimeException('Somethings not right yet!');
}
echo 'Well, it is now!'.PHP_EOL;
