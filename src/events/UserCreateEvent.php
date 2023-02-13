<?php
/**
 * @link https://craftcms.com/
 * @copyright Copyright (c) Pixel & Tonic, Inc.
 * @license MIT
 */

namespace levinriegner\craftcognitoauth\events;

use craft\elements\User;
use yii\base\Event;

/**
 * Class UserCreateEvent
 *
 * @author    Levinriegner
 * @since     0.5
 */
class UserCreateEvent extends Event
{
    // Properties
    // =========================================================================

    /**
     * @var User
     */
    public $user;

    /**
     * @var string
     */
    public $issuer;
}
