<?php

namespace App\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Component\Routing\Annotation\Route;
use App\Controller\BaseController;

class UserController extends BaseController
{
    /**
     * @Route("/api/me")
     * @IsGranted("IS_AUTHENTICATED_REMEMBERED") 
     */
    public function apiMe() 
    {
        return $this->json($this->getUser(), 200, [], [
            'groups' => ['user:read']
        ]); 
    }
}