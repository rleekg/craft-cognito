<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

/**
 * Craft JWT Auth config.php
 *
 * This file exists only as a template for the Craft JWT Auth settings.
 * It does nothing on its own.
 *
 * Don't edit this file, instead copy it to 'craft/config' as 'craft-jwt-auth.php'
 * and make your changes there to override default settings.
 *
 * Once copied to 'craft/config', this file will be multi-environment aware as
 * well, so you can have different settings groups for each environment, just as
 * you do for 'general.php'
 */

return [
    // Whether to automatically create a user for verified JWTs that don't match an account
    "autoCreateUser" => true,

    // Cognito region
    "region" => 'us-east-1',

    // Cognito client id
    "clientId" => '5v2eh83n5olecdumomvrjlapmt',

    // Cognito user pool id
    'userpoolId' => 'us-east-1_S6QiPjbAW',

    // Cognito JSON Web Key Set URL (JWKS) used for verifying incoming Cognito JWTs
    "jwks" => '',
];
