<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace levinriegner\craftcognitoauth\models;

use craft\base\Model;
use craft\behaviors\EnvAttributeParserBehavior;
use craft\helpers\App;

/**
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 */
class Settings extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public $autoCreateUser = false;
    public $region = '';
    public $profile = '';
    public $clientId = '';
    public $userpoolId = '';
    public $callbackUrl = '';
    public $cognitoDomain = '';
    public $jwks = '';
    public $jwtEnabled = true;
    
    //Saml cert path to validate SAML tokens
    public $samlCert = '';

    //Login URL of the SAML IdP
    public $samlIdPLogin;
    
    public $samlEnabled = false;

    // Public Methods
    // =========================================================================
    public function behaviors(): array
    {
        return [
            'parser' => [
                'class' => EnvAttributeParserBehavior::class,
                'attributes' => [
                    'autoCreateUser',
                    'region','profile','clientId','callbackUrl','cognitoDomain','userpoolId','jwks',
                    'samlCert', 'samlIdPLogin'
                ],
            ],
        ];
    }

    /**
     * @inheritdoc
     */
    public function rules(): array
    {
        return [
            ['jwtEnabled', 'boolean'],
            ['autoCreateUser', 'boolean'],
            ['region', 'string'],
            ['profile', 'string'],
            ['clientId', 'string'],
            ['userpoolId', 'string'],
            ['callbackUrl', 'string'],
            ['cognitoDomain', 'string'],
            ['jwks', 'string'],
            ['samlEnabled', 'boolean'],
            ['samlCert', 'string'],
            ['samlIdPLogin', 'string'],
        ];
    }

    public function getAutoCreateUser(): bool
    {
        return boolval(App::parseEnv($this->autoCreateUser));
    }

    public function getProfile(): string
    {
        return App::parseEnv($this->profile);
    }

    public function getRegion(): string
    {
        return App::parseEnv($this->region);
    }

    public function getClientId(): string
    {
        return App::parseEnv($this->clientId);
    }

    public function getUserPoolId(): string
    {
        return App::parseEnv($this->userpoolId);
    }

    public function getCallbackUrl(): string
    {
        return App::parseEnv($this->callbackUrl);
    }

    public function getCognitoDomain(): string
    {
        return App::parseEnv($this->cognitoDomain);
    }

    public function getJwks(): string
    {
        return App::parseEnv($this->jwks);
    }

    public function getSamlCert(): string
    {
        return App::parseEnv($this->samlCert);
    }

    public function getSamlIdpLogin(): string
    {
        return App::parseEnv($this->samlIdPLogin);
    }

    public function getSamlEnabled(): bool
    {
        return $this->samlEnabled;
    }

    public function getJwtEnabled(): bool
    {
        return $this->jwtEnabled;
    }
}
