<?php

/**
 * Craft JWT Auth plugin for Craft CMS 3.x
 *
 * Enable authentication to Craft through the use of JSON Web Tokens (JWT)
 *
 * @link      https://edenspiekermann.com
 * @copyright Copyright (c) 2019 Mike Pierce
 */

namespace levinriegner\craftcognitoauth\services\validators;

use Craft;
use craft\elements\User;
use craft\helpers\StringHelper;
use levinriegner\craftcognitoauth\CraftJwtAuth;
use Lcobucci\JWT\Signer\Rsa\Sha256;

use CoderCat\JWKToPEM\JWKConverter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use levinriegner\craftcognitoauth\services\AbstractValidator;

/**
 * @author    Mike Pierce
 * @package   CraftJwtAuth
 * @since     0.1.0
 */
class JWT extends AbstractValidator
{
    // Public Methods
    // =========================================================================

    private $jwtEnabled;
    private $jwksUrl;

    public function __construct()
    {
        $this->jwtEnabled = CraftJwtAuth::getInstance()->settingsService->get()->normal->getJwtEnabled();
        $this->jwksUrl = CraftJwtAuth::getInstance()->settingsService->get()->normal->getJwks();

        parent::__construct();
    }

    public function isEnabled(){
        return $this->jwtEnabled;
    }


    protected function getTokenFromRequest()
    {
        // Look for an access token in the settings
        $accessToken = Craft::$app->request->headers->get('authorization') ?: Craft::$app->request->headers->get('x-access-token');

        // If "Bearer " is present, strip it to get the token.
        if (StringHelper::startsWith($accessToken, 'Bearer ')) {
            $accessToken = StringHelper::substr($accessToken, 7);
        }

        // If we find one, and it looks like a JWT...
        if ($accessToken) {
            return $accessToken;
        }

        return null;
    }

    protected function parseToken($accessToken)
    {
        if (count(explode('.', $accessToken)) === 3) {
            $parser = new Parser(new JoseEncoder());
            $token = $parser->parse((string) $accessToken);

            return $token;
        }

        return null;
    }

    /**
     * @param \Lcobucci\JWT\Token\Plain $token
     */
    protected function verifyToken($token)
    {
        $jwks = json_decode(file_get_contents($this->jwksUrl), true);
        $jwk = [];
        foreach($jwks['keys'] as $struct) {
            if ($token->headers()->get('kid') === $struct['kid']) {
                $jwk = $struct;
                break;
            }
        }

        $jwkConverter = new JWKConverter();
        $convertedJwk = $jwkConverter->toPEM($jwk);

        // Attempt to verify the token
        return (new Validator())->validate($token, new SignedWith(new Sha256(), InMemory::plainText($convertedJwk)));
    }

    protected function getIssuerByToken($token){
        //TODO Diferentiate different issuers inside cognito?
        return 'cognito';
    }

    /**
     * @param \Lcobucci\JWT\Token\Plain $token
     */
    protected function getUserByToken($token)
    {
        // Derive the username from the subject in the token
        $email = $token->claims()->get('email', '');
        $userName = $token->claims()->get('sub', '');

        // Look for the user with email
        $user = Craft::$app->users->getUserByUsernameOrEmail($email ?: $userName);

        return $user;
    }

    /**
     * @param \Lcobucci\JWT\Token\Plain $token
     */
    protected function createUserByToken($token)
    {
        // Email is a mandatory field
        if ($token->claims()->has('email')) {
            $email = $token->claims()->get('email');

            // Create a new user and populate with claims
            $user = new User();

            // Set username and email
            $user->email = $email;
            $user->username = $token->claims()->get('cognito:username', $email);

            // These are optional, so pass empty string as the default
            $user->firstName = $token->claims()->get('given_name', '');
            $user->lastName = $token->claims()->get('family_name', '');

            // Attempt to save the user
            $success = Craft::$app->getElements()->saveElement($user);

            // If user saved ok...
            if ($success) {
                // Assign the user to the default public group
                Craft::$app->users->assignUserToDefaultGroup($user);

                return $user;
            } 
        }

        return null;
    }
}
