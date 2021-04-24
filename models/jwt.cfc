component {

    variables.algorithmMap = {
        HS256: 'HmacSHA256',
        HS384: 'HmacSHA384',
        HS512: 'HmacSHA512',
        RS256: 'SHA256withRSA',
        RS384: 'SHA384withRSA',
        RS512: 'SHA512withRSA',
        ES256: 'SHA256withECDSAinP1363Format',
        ES384: 'SHA384withECDSAinP1363Format',
        ES512: 'SHA512withECDSAinP1363Format'
    };

    variables.legacyAlgorithmMap = {
        ES256: 'SHA256withECDSA',
        ES384: 'SHA384withECDSA',
        ES512: 'SHA512withECDSA'
    };

    public any function init() {
        variables.encodingUtils = new encodingUtils();
        variables.jss = createObject( 'java', 'java.security.Signature' );
        variables.messageDigest = createObject( 'java', 'java.security.MessageDigest' );
        variables.javaVersion = getJavaVersion();

        if ( variables.javaVersion < 11 ) {
            structAppend( variables.algorithmMap, variables.legacyAlgorithmMap );
        }

        return this;
    }

    public string function encode(
        required struct payload,
        required any key,
        required string algorithm,
        struct headers = { }
    ) {
        if ( !algorithmMap.keyExists( algorithm ) ) {
            throw(
                type = 'jwtcfml.InvalidAlgorithm',
                message = 'Invalid JWT Algorithm.',
                detail = 'The passed in algorithm is not supported.'
            );
        }

        var header = { };
        header.append( headers );
        header.append( {
            'typ': 'JWT',
            'alg': algorithm
        } );

        var duplicatedPayload = duplicate( payload );
        for ( var claim in [ 'iat', 'exp', 'nbf' ] ) {
            if ( duplicatedPayload.keyExists( claim ) && isDate( duplicatedPayload[ claim ] ) ) {
                duplicatedPayload[ claim ] = encodingUtils.convertDateToUnixTimestamp( duplicatedPayload[ claim ] );
            }
        }

        var stringToSignParts = [
            encodingUtils.binaryToBase64Url( charsetDecode( serializeJSON( header ), 'utf-8' ) ),
            encodingUtils.binaryToBase64Url( charsetDecode( serializeJSON( duplicatedPayload ), 'utf-8' ) )
        ];
        var stringToSign = stringToSignParts.toList( '.' );

        return stringToSign & '.' & encodingUtils.binaryToBase64Url( sign( stringToSign, key, algorithm ) );
    }

    public struct function decode(
        required string token,
        any key,
        any algorithms = [ ],
        struct claims = { },
        boolean verify = true
    ) {
        var parts = listToArray( token, '.' );

        if ( arrayLen( parts ) != 3 ) {
            throw(
                type = 'jwtcfml.InvalidToken',
                message = 'Invalid JWT.',
                detail = 'The passed in token does not have three `.` delimited parts.'
            );
        }

        algorithms = isArray( algorithms ) ? algorithms : [ algorithms ];

        var decoded = {
            header: deserializeJSON( charsetEncode( encodingUtils.base64UrlToBinary( parts[ 1 ] ), 'utf-8' ) ),
            payload: deserializeJSON( charsetEncode( encodingUtils.base64UrlToBinary( parts[ 2 ] ), 'utf-8' ) )
        };

        if ( verify ) {
            if (
                !algorithms.find( decoded.header.alg ) ||
                !algorithmMap.keyExists( decoded.header.alg )
            ) {
                throw(
                    type = 'jwtcfml.InvalidAlgorithm',
                    message = 'Unsupported or invalid algorithm',
                    detail = 'The passed in token does not have an algorithm declaration or its declared algorithm does not match the specified algorithms of #serializeJSON( algorithms )#.'
                );
            }

            var stringToSign = parts[ 1 ] & '.' & parts[ 2 ];
            var signature = encodingUtils.base64UrlToBinary( parts[ 3 ] );

            if (
                !verifySignature(
                    stringToSign,
                    key,
                    signature,
                    decoded.header.alg
                )
            ) {
                throw(
                    type = 'jwtcfml.InvalidSignature',
                    message = 'Signature is Invalid',
                    detail = 'The signature of the passed in token is invalid.'
                );
            }

            var baseClaims = {
                'exp': true,
                'nbf': true
            };
            baseClaims.append( claims );
            verifyClaims( decoded.payload, baseClaims );
        }

        for ( var claim in [ 'iat', 'exp', 'nbf' ] ) {
            if ( decoded.payload.keyExists( claim ) ) {
                decoded.payload[ claim ] = encodingUtils.convertUnixTimestampToDate( decoded.payload[ claim ] );
            }
        }

        return decoded.payload;
    }

    public struct function getHeader( required string token ) {
        return deserializeJSON( charsetEncode( encodingUtils.base64UrlToBinary( listFirst( token, '.' ) ), 'utf-8' ) );
    }

    public function parsePEMEncodedKey( required string pemKey ) {
        return encodingUtils.parsePEMEncodedKey( pemKey );
    }

    public function parseJWK( required struct jwk ) {
        return encodingUtils.parseJWK( jwk );
    }

    private function sign( message, key, algorithm ) {
        if ( left( algorithm, 1 ) == 'H' ) {
            var sig = binaryDecode(
                hmac(
                    message,
                    key,
                    algorithmMap[ algorithm ],
                    'utf-8'
                ),
                'hex'
            );
        } else {
            if ( isSimpleValue( key ) ) {
                key = encodingUtils.parsePEMEncodedKey( key );
            } else if ( isStruct( key ) ) {
                key = encodingUtils.parseJWK( key );
            }

            var jssInstance = variables.jss.getInstance( algorithmMap[ algorithm ] );
            jssInstance.initSign( key );
            jssInstance.update( charsetDecode( message, 'utf-8' ) );
            var sig = jssInstance.sign();
            if ( variables.javaVersion < 11 && left( algorithm, 1 ) == 'E' ) {
                sig = encodingUtils.convertDERtoP1363( sig, algorithm );
            }
        }
        return sig;
    }

    private function verifySignature( message, key, signature, algorithm ) {
        if ( left( algorithm, 1 ) == 'H' ) {
            var sig = binaryDecode(
                hmac(
                    message,
                    key,
                    algorithmMap[ algorithm ],
                    'utf-8'
                ),
                'hex'
            );
            return MessageDigest.isEqual( signature, sig );
        }

        if ( variables.javaVersion < 11 && left( algorithm, 1 ) == 'E' ) {
            signature = encodingUtils.convertP1363ToDER( signature );
        }

        if ( isSimpleValue( key ) ) {
            key = encodingUtils.parsePEMEncodedKey( key );
        } else if ( isStruct( key ) ) {
            key = encodingUtils.parseJWK( key );
        }

        var jssInstance = variables.jss.getInstance( algorithmMap[ algorithm ] );
        jssInstance.initVerify( key );
        jssInstance.update( charsetDecode( message, 'utf-8' ) );
        return jssInstance.verify( signature );
    }

    private function verifyClaims( payload, claims ) {
        if (
            structKeyExists( payload, 'exp' )
            && !verifyDateClaim( payload.exp, claims.exp, -1 )
        ) {
            throw(
                type = 'jwtcfml.ExpiredSignature',
                message = 'Token has expired',
                detail = 'The passed in token has expired.'
            );
        }

        if (
            structKeyExists( payload, 'nbf' )
            && !verifyDateClaim( payload.nbf, claims.nbf, 1 )
        ) {
            throw(
                type = 'jwtcfml.NotBeforeException',
                message = 'Token is not valid',
                detail = 'The passed in token has not yet become valid.'
            );
        }



        if ( structKeyExists( claims, 'iss' ) ) {
            if ( !structKeyExists( payload, 'iss' ) || compare( payload.iss, claims.iss ) != 0 ) {
                throw(
                    type = 'jwtcfml.InvalidIssuer',
                    message = 'Token has an invalid issuer',
                    detail = 'The passed in token either does not specify an issuer or the claimed issuer is not valid.'
                );
            }
        }

        if ( structKeyExists( claims, 'aud' ) ) {
            var audArray = isArray( claims.aud ) ? claims.aud : [ claims.aud ];
            if ( !structKeyExists( payload, 'aud' ) || !audArray.find( payload.aud ) ) {
                throw(
                    type = 'jwtcfml.InvalidAudience',
                    message = 'Token has an invalid audience',
                    detail = 'The passed in token either does not specify an audience or the claimed audience is not valid.'
                );
            }
        }
    }

    private function verifyDateClaim( payloadDate, claim, failState ) {
        var pd = encodingUtils.convertUnixTimestampToDate( payloadDate );
        var cd = claim;
        if ( !isBoolean( cd ) || cd ) {
            if ( isNumeric( cd ) ) {
                cd = encodingUtils.convertUnixTimestampToDate( cd );
            } else if ( !isDate( cd ) ) {
                cd = now();
            }
            return dateCompare( pd, cd ) != failState;
        }
        return true;
    }

    private numeric function getJavaVersion() {
        var javaVersion = createObject( 'java', 'java.lang.System' ).getProperty( 'java.version' );
        if ( javaVersion.startswith( '1.' ) ) {
            return int( listGetAt( javaVersion, 2, '.' ) );
        }
        return int( listFirst( javaVersion, '.' ) );
    }

}
