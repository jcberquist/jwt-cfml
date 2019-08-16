component extends=testbox.system.BaseSpec {

    function run() {
        describe( 'The jwt component', function() {
            var jwt = new models.jwt();

            it( 'can return the unverified header', function() {
                var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o';
                var header = jwt.getHeader( token );
                expect( header ).toBe( {
                    'alg': 'HS256',
                    'typ': 'JWT'
                } );
            } );

            describe( 'The encode() method', function() {
                it( 'throws an error if the algorithm specified is not in the algorithm array', function() {
                    var key = 'secret';
                    expect( function() {
                        payload = jwt.encode( { }, key, 'RS' );
                    } ).toThrow( 'jwtcfml.InvalidAlgorithm' );
                } );

                it( 'supports HS algorithms', function() {
                    var payload = {
                        'name': 'John Doe'
                    };
                    var key = 'secret';
                    var token = jwt.encode( payload, key, 'HS256' );
                    var expectedToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.GQIdMj0gO4DCPcon_oRn1nFMjfGzA4sOPRIIhRRorLs';
                    expect( token ).toBe( expectedToken );
                } );

                it( 'supports RS algorithms', function() {
                    var payload = {
                        'name': 'John Doe'
                    };
                    var expectedToken = fileRead( expandPath( '/sampleTokens/RS512Token.txt' ) ).trim();

                    var key = fileRead( expandPath( '/sampleKeys/sampleRSA.key' ) );
                    var token = jwt.encode( payload, key, 'RS512' );
                    expect( token ).toBe( expectedToken );

                    var key = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleRSAPrivate.json' ) ) );
                    var token = jwt.encode( payload, key, 'RS512' );
                    expect( token ).toBe( expectedToken );
                } );

                it( 'supports ES algorithms', function() {
                    var payload = {
                        'name': 'John Doe'
                    };

                    var key = fileRead( expandPath( '/sampleKeys/sampleEC.key' ) );
                    var token = jwt.encode( payload, key, 'ES256' );

                    // EC signatures change every time so just decode and verify that
                    var publickey = fileRead( expandPath( '/sampleKeys/sampleEC.pub' ) );

                    var payload = jwt.decode( token, publickey, 'ES256' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var key = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleECPrivate.json' ) ) );
                    var token = jwt.encode( payload, key, 'ES256' );
                    var payload = jwt.decode( token, publickey, 'ES256' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'supports using Java private key classes', function() {
                    var payload = {
                        'name': 'John Doe'
                    };

                    var key = jwt.parsePEMEncodedKey( fileRead( expandPath( '/sampleKeys/sampleEC.key' ) ) );
                    var token = jwt.encode( payload, key, 'ES256' );

                    // EC signatures change every time so just decode and verify that
                    var publickey = fileRead( expandPath( '/sampleKeys/sampleEC.pub' ) );
                    var payload = jwt.decode( token, publickey, 'ES256' );

                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var key = jwt.parseJWK(
                        deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleECPrivate.json' ) ) )
                    );
                    var token = jwt.encode( payload, key, 'ES256' );

                    // EC signatures change every time so just decode and verify that
                    var publickey = fileRead( expandPath( '/sampleKeys/sampleEC.pub' ) );
                    var payload = jwt.decode( token, publickey, 'ES256' );

                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'supports adding extra headers', function() {
                    var payload = {
                        'name': 'John Doe'
                    };
                    var key = 'secret';
                    var token = jwt.encode(
                        payload,
                        key,
                        'HS256',
                        {
                            'kid': '123abc'
                        }
                    );
                    var header = jwt.getHeader( token );
                    expect( header ).toBe( {
                        'typ': 'JWT',
                        'alg': 'HS256',
                        'kid': '123abc'
                    } );
                } );

                it( 'supports converting CFML dates to UNIX timestamps for "iat", "exp", and "nbf" claims', function() {
                    var encodingUtils = new models.encodingUtils();
                    var ts = now();
                    var ut = encodingUtils.convertDateToUnixTimestamp( ts );

                    var payload = {
                        'iat': ts,
                        'exp': ts,
                        'nbf': ts
                    };
                    var token = jwt.encode( payload, 'secret', 'HS256' );

                    var decodedPayload = deserializeJSON(
                        charsetEncode( encodingUtils.base64UrlToBinary( listGetAt( token, 2, '.' ) ), 'utf-8' )
                    );

                    expect( decodedPayload ).toBe( {
                        'iat': ut,
                        'exp': ut,
                        'nbf': ut
                    } );
                } );
            } );

            describe( 'The decode() method', function() {
                it( 'throws an error if the algorithm specified in header is not in the algorithm array', function() {
                    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o';
                    var key = 'secret';
                    expect( function() {
                        payload = jwt.decode( token, key, 'RS256' );
                    } ).toThrow( 'jwtcfml.InvalidAlgorithm' );
                } );

                it( 'throws an error if the signature is invalid', function() {
                    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o';
                    var key = 'secret2';
                    expect( function() {
                        payload = jwt.decode( token, key, 'HS256' );
                    } ).toThrow( 'jwtcfml.InvalidSignature' );
                } );


                it( 'allows verification to be bypassed', function() {
                    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o';
                    var key = 'secret2';
                    expect( function() {
                        payload = jwt.decode(
                            token = token,
                            key = key,
                            algorithms = 'HS256',
                            verify = false
                        );
                    } ).notToThrow( 'jwtcfml.InvalidSignature' );
                } );

                it( 'supports HS algorithms', function() {
                    var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.GQIdMj0gO4DCPcon_oRn1nFMjfGzA4sOPRIIhRRorLs';
                    var key = 'secret';
                    var payload = jwt.decode( token, key, 'HS256' );

                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'supports RS algorithms', function() {
                    var token = fileRead( expandPath( '/sampleTokens/RS512Token.txt' ) ).trim();

                    var key = fileRead( expandPath( '/sampleKeys/sampleRSA.pub' ) );
                    var payload = jwt.decode( token, key, 'RS512' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var key = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleRSAPublic.json' ) ) );
                    var payload = jwt.decode( token, key, 'RS512' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'supports ES algorithms', function() {
                    var token = fileRead( expandPath( '/sampleTokens/ES256Token.txt' ) ).trim();

                    var key = fileRead( expandPath( '/sampleKeys/sampleEC.pub' ) );
                    var payload = jwt.decode( token, key, 'ES256' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var key = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleECPublic.json' ) ) );
                    var payload = jwt.decode( token, key, 'ES256' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var token = fileRead( expandPath( '/sampleTokens/ES384Token.txt' ) ).trim();

                    var key = fileRead( expandPath( '/sampleKeys/sampleEC384.pub' ) );
                    var payload = jwt.decode( token, key, 'ES384' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var key = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleEC384Public.json' ) ) );
                    var payload = jwt.decode( token, key, 'ES384' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'supports using PEM certificates when decoding', function() {
                    var token = fileRead( expandPath( '/sampleTokens/RS512Token.txt' ) ).trim();
                    var key = fileRead( expandPath( '/sampleKeys/sampleRSA.crt' ) );
                    var payload = jwt.decode( token, key, 'RS512' );

                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var token = fileRead( expandPath( '/sampleTokens/ES256Token.txt' ) ).trim();
                    var key = fileRead( expandPath( '/sampleKeys/sampleEC.crt' ) );
                    var payload = jwt.decode( token, key, 'ES256' );

                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'supports using java public key classes when decoding', function() {
                    var token = fileRead( expandPath( '/sampleTokens/RS512Token.txt' ) ).trim();
                    var key = jwt.parsePEMEncodedKey( fileRead( expandPath( '/sampleKeys/sampleRSA.crt' ) ) );
                    var payload = jwt.decode( token, key, 'RS512' );

                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var token = fileRead( expandPath( '/sampleTokens/ES256Token.txt' ) ).trim();

                    var key = jwt.parsePEMEncodedKey( fileRead( expandPath( '/sampleKeys/sampleEC.crt' ) ) );
                    var payload = jwt.decode( token, key, 'ES256' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );

                    var key = jwt.parseJWK(
                        deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleECPublic.json' ) ) )
                    );
                    var payload = jwt.decode( token, key, 'ES256' );
                    expect( payload ).toBe( {
                        'name': 'John Doe'
                    } );
                } );

                it( 'verifies the "exp" claim', function() {
                    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjU0MjMwMDB9.0F2ysJpLbaf3hFAQ6zwZoQ1L2pBYgzdOHOdz0he5GWo';
                    var key = 'secret';
                    expect( function() {
                        jwt.decode( token, key, 'HS256' );
                    } ).toThrow( 'jwtcfml.ExpiredSignature' );
                } );

                it( 'verifies the "nbf" claim', function() {
                    var payload = {
                        nbf: dateAdd( 'h', 1, now() )
                    };
                    var token = jwt.encode( payload, 'secret', 'HS256' );
                    expect( function() {
                        jwt.decode( token, 'secret', 'HS256' );
                    } ).toThrow( 'jwtcfml.NotBeforeException' );
                } );

                it( 'verifies the "iss" claim', function() {
                    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0VEVTVCJ9.WT1ydOldEYxXVxM91LHwk4gW1fwQMS9zJ3n9SbUbOwE';
                    var key = 'secret';
                    expect( function() {
                        jwt.decode(
                            token,
                            key,
                            'HS256',
                            {
                                'iss': 'testtest'
                            }
                        );
                    } ).toThrow( 'jwtcfml.InvalidIssuer' );
                    expect( function() {
                        jwt.decode(
                            token,
                            key,
                            'HS256',
                            {
                                'iss': 'testTEST'
                            }
                        );
                    } ).notToThrow();
                } );

                it( 'verifies the "aud" claim', function() {
                    var token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhIn0.F5RHqgQAiCrHsrVEJO4ZQjQ5CY4L3AKH1nClXHa0JeU';
                    var key = 'secret';
                    expect( function() {
                        jwt.decode(
                            token,
                            key,
                            'HS256',
                            {
                                'aud': 'b'
                            }
                        );
                    } ).toThrow( 'jwtcfml.InvalidAudience' );
                    expect( function() {
                        jwt.decode(
                            token,
                            key,
                            'HS256',
                            {
                                'aud': [ 'a', 'b' ]
                            }
                        );
                    } ).notToThrow();
                } );

                it( 'supports converting UNIX timestamps to CFML dates for "iat", "exp", and "nbf" claims', function() {
                    var encodingUtils = new models.encodingUtils();
                    var ts = now();
                    var ut = encodingUtils.convertDateToUnixTimestamp( ts );

                    var payload = {
                        'iat': ut,
                        'exp': ut,
                        'nbf': ut
                    };
                    var token = jwt.encode( payload, 'secret', 'HS256' );
                    var decodedPayload = jwt.decode(
                        token,
                        'secret',
                        'HS256',
                        {
                            exp: false
                        }
                    );
                    for ( var key in payload ) {
                        expect( decodedPayload[ key ] ).toBe( ts );
                    }
                } );
            } );
        } );
    }

}
