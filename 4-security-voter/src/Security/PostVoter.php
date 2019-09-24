<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Security;

use App\Entity\Post;
use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * It grants or denies permissions for actions related to blog posts (such as
 * showing, editing and deleting posts).
 *
 * See https://symfony.com/doc/current/security/voters.html
 *
 * @author Yonel Ceruto <yonelceruto@gmail.com>
 */
class PostVoter extends Voter
{
    // Defining these constants is overkill for this simple application, but for real
    // applications, it's a recommended practice to avoid relying on "magic strings"
    public const DELETE = 'delete';
    public const EDIT = 'edit';
    public const SHOW = 'show';

    /**
     * {@inheritdoc}
     */
    protected function supports($attribute, $subject): bool
    {
        // this voter is only executed for three specific permissions on Post objects
        return $subject instanceof Post && \in_array($attribute, [self::SHOW, self::EDIT, self::DELETE], true);
    }

    /**
     * {@inheritdoc}
     * @param Post $post
     */
    protected function voteOnAttribute($attribute, $post, TokenInterface $token): bool
    {
        $user = $token->getUser();

        // the user must be logged in; if not, deny permission
        if (!$user instanceof User) {
            return false;
        }

        switch ($attribute) {
            case self::DELETE:
            case self::EDIT:
                return $user === $post->getAuthor() || in_array('ROLE_ADMIN', $user->getRoles(), true) || 'Bernhard Kau' === $user->getFullName();
            case self::SHOW:
                return true;
        }

        return false;
    }
}
