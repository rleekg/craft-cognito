<?php

namespace levinriegner\craftcognitoauth\helpers;

use levinriegner\craftcognitoauth\services\AbstractValidator;
use levinriegner\craftcognitoauth\services\validators\JWT;
use levinriegner\craftcognitoauth\services\validators\SAML;

class ValidatorsHelper {

    private static $validators = [
        'jwt' => JWT::class,
        'saml' => SAML::class
    ];

    public static function getAllTypes(): array {
        return static::$validators;
    }

    public static function getType($name): AbstractValidator
    {
        return static::$validators[$name];
    }
}