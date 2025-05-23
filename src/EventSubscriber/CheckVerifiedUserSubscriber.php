<?php

namespace App\EventSubscriber;

use App\Security\AccountNotVerifiedAuthenticationException;
use App\Entity\User;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Authenticator\Passport\UserPassportInterface;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;

class CheckVerifiedUserSubscriber implements EventSubscriberInterface
{
    private RouterInterface $router;

    public function __construct(RouterInterface $router)
    {
        $this->router = $router;
    }

    public function onCheckPassport(CheckPassportEvent $event)
    {
        $passport = $event->getPassport();

        if (!$passport instanceof UserPassportInterface) {
            throw new \InvalidArgumentException('Invalid passport instance.');
        }   

        $user = $passport->getUser();

        if (!$user instanceof User) {
            throw new \Exception('Unexpected user type.');
        }
  
        if (!$user->getIsVerified()) {
            throw new AccountNotVerifiedAuthenticationException(); 
        }
    }

    public function onLoginFailure(LoginFailureEvent $event)
    {
        if (!$event->getException() instanceof AccountNotVerifiedAuthenticationException) {
            return;
        }

        $response = new RedirectResponse($this->router->generate('app_verify_resend_email'));

        $event->setResponse($response);
    }

    public static function getSubscribedEvents()
    {
        return [
            CheckPassportEvent::class => ['onCheckPassport', -10],
            LoginFailureEvent::class => ['onLoginFailure'],
        ];
    }
}