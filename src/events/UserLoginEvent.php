<?php
/**
 * @link https://craftcms.com/
 * @copyright Copyright (c) Pixel & Tonic, Inc.
 * @license MIT
 */

namespace levinriegner\craftcognitoauth\events;

use yii\base\Event;

/**
 * Class UserLoginEvent
 *
 * @author    Levinriegner
 * @since     1.0
 */
class UserLoginEvent extends Event
{
    // Properties
    // =========================================================================

    /**
     * @var string
     */
    public $email;
}
