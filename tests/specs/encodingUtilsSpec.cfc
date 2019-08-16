component extends=testbox.system.BaseSpec {

    function run() {
        describe( 'The encodingUtils component', function() {
            var encodingUtils = new models.encodingUtils();

            it( 'can convert dates to UNIX timestamps', function() {
                var dt = parseDateTime( '2019-09-01T00:00:00Z' );
                var ut = encodingUtils.convertDateToUnixTimestamp( dt );
                expect( ut ).toBe( 1567296000 );
            } );

            it( 'can convert UNIX timestamps to dates', function() {
                var dt = encodingUtils.convertUnixTimestampToDate( 1567296000 );
                expect( dt ).toBe( parseDateTime( '2019-09-01T00:00:00Z' ) );
            } );

            it( 'can convert binary data to Base64 URL encoding', function() {
                var binaryData = binaryDecode( 'gIecWZe5dS6rVhI7MXgoxeZ/IcUjJ5qZ9+2GUuR3ejk=', 'base64' );
                var encoded = encodingUtils.binaryToBase64Url( binaryData );
                expect( encoded ).toBe( 'gIecWZe5dS6rVhI7MXgoxeZ_IcUjJ5qZ9-2GUuR3ejk' );
            } );

            it( 'can convert Base64 URL encoded data to binary', function() {
                var encoded = 'gIecWZe5dS6rVhI7MXgoxeZ_IcUjJ5qZ9-2GUuR3ejk';
                var converted = encodingUtils.base64UrlToBinary( encoded );
                var binaryData = binaryDecode( 'gIecWZe5dS6rVhI7MXgoxeZ/IcUjJ5qZ9+2GUuR3ejk=', 'base64' );
                expect( converted ).toBe( binaryData );
            } );

            it( 'can convert an EC P1363 signature to an ASN.1 DER signature', function() {
                var P1363Data = binaryDecode(
                    'tyh+VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP/3cYHBw7AhHale5wky6+sVA==',
                    'base64'
                );
                var DERData = binaryDecode(
                    'MEYCIQC3KH5V+7MjELIZgOWQEDsN/KOuqZIe7qlDaGhm4WpRIgIhAM81jY3SakdveeTkrXsdY//dxgcHDsCEdqV7nCTLr6xU',
                    'base64'
                );
                expect( encodingUtils.convertP1363ToDER( P1363Data ) ).toBe( DERData );
            } );

            it( 'can convert an EC ASN.1 DER signature to an P1363 signature', function() {
                var P1363Data = binaryDecode(
                    'tyh+VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP/3cYHBw7AhHale5wky6+sVA==',
                    'base64'
                );
                var DERData = binaryDecode(
                    'MEYCIQC3KH5V+7MjELIZgOWQEDsN/KOuqZIe7qlDaGhm4WpRIgIhAM81jY3SakdveeTkrXsdY//dxgcHDsCEdqV7nCTLr6xU',
                    'base64'
                );
                expect( encodingUtils.convertDERtoP1363( DERData, 'ES256' ) ).toBe( P1363Data );
            } );

            describe( 'the parsePEMEncodedKey() method', function() {
                it( 'throws a jwtcfml.InvalidPrivateKey exception when given a non PKCS8 format RSA or EC private key', function() {
                    var rsaKey = fileRead( expandPath( '/sampleKeys/unsupported/sampleRSA.key' ) );
                    expect( function() {
                        encodingUtils.parsePEMEncodedKey( rsaKey );
                    } ).toThrow( type = 'jwtcfml.InvalidPrivateKey' );

                    var ecKey = fileRead( expandPath( '/sampleKeys/unsupported/sampleEC.key' ) );
                    expect( function() {
                        encodingUtils.parsePEMEncodedKey( ecKey );
                    } ).toThrow( type = 'jwtcfml.InvalidPrivateKey' );

                    var ecKeyWithParams = fileRead( expandPath( '/sampleKeys/unsupported/sampleECWithParams.key' ) );
                    expect( function() {
                        encodingUtils.parsePEMEncodedKey( ecKeyWithParams );
                    } ).toThrow( type = 'jwtcfml.InvalidPrivateKey' );
                } );

                it( 'can parse an RSA private key in PKCS8 Format', function() {
                    var rsaKey = fileRead( expandPath( '/sampleKeys/sampleRSA.key' ) );
                    var key = encodingUtils.parsePEMEncodedKey( rsaKey );
                    expect( key.getAlgorithm() ).toBe( 'RSA' );
                    expect( key.getFormat() ).toBe( 'PKCS##8' );
                } );

                it( 'can parse an RSA public key', function() {
                    var rsaKey = fileRead( expandPath( '/sampleKeys/sampleRSA.pub' ) );
                    var key = encodingUtils.parsePEMEncodedKey( rsaKey );
                    expect( key.getAlgorithm() ).toBe( 'RSA' );
                    expect( key.getFormat() ).toBe( 'X.509' );
                } );

                it( 'can parse an RSA certificate', function() {
                    var rsaCert = fileRead( expandPath( '/sampleKeys/sampleRSA.crt' ) );
                    var key = encodingUtils.parsePEMEncodedKey( rsaCert );
                    expect( key.getAlgorithm() ).toBe( 'RSA' );
                    expect( key.getFormat() ).toBe( 'X.509' );
                } );

                it( 'can parse an EC private key in PKCS8 Format', function() {
                    var ecKey = fileRead( expandPath( '/sampleKeys/sampleEC.key' ) );
                    var key = encodingUtils.parsePEMEncodedKey( ecKey );
                    expect( key.getAlgorithm() ).toBe( 'EC' );
                    expect( key.getFormat() ).toBe( 'PKCS##8' );
                } );

                it( 'can parse an EC public key', function() {
                    var ecKey = fileRead( expandPath( '/sampleKeys/sampleEC.pub' ) );
                    var key = encodingUtils.parsePEMEncodedKey( ecKey );
                    expect( key.getAlgorithm() ).toBe( 'EC' );
                    expect( key.getFormat() ).toBe( 'X.509' );
                } );

                it( 'can parse an EC certificate', function() {
                    var ecCert = fileRead( expandPath( '/sampleKeys/sampleEC.crt' ) );
                    var key = encodingUtils.parsePEMEncodedKey( ecCert );
                    expect( key.getAlgorithm() ).toBe( 'EC' );
                    expect( key.getFormat() ).toBe( 'X.509' );
                } );
            } );

            describe( 'the parseJWK() method', function() {
                it( 'can parse an RSA public key', function() {
                    var jwk = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleRSAPublic.json' ) ) );
                    var key = encodingUtils.parseJWK( jwk );
                    expect( key.getAlgorithm() ).toBe( 'RSA' );
                    expect( key.getFormat() ).toBe( 'X.509' );
                } );


                it( 'can parse an RSA private key', function() {
                    var jwk = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleRSAPrivate.json' ) ) );
                    var key = encodingUtils.parseJWK( jwk );
                    expect( key.getAlgorithm() ).toBe( 'RSA' );
                    expect( key.getFormat() ).toBe( 'PKCS##8' );

                    jwk = jwk.filter( function( k, v ) {
                        return arrayFind( [ 'kty', 'n', 'd' ], k );
                    } );
                    var key = encodingUtils.parseJWK( jwk );
                    expect( key.getAlgorithm() ).toBe( 'RSA' );
                    expect( key.getFormat() ).toBe( 'PKCS##8' );
                } );

                it( 'can parse an EC public key', function() {
                    var jwk = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleECPublic.json' ) ) );
                    var key = encodingUtils.parseJWK( jwk );
                    expect( key.getAlgorithm() ).toBe( 'EC' );
                    expect( key.getFormat() ).toBe( 'X.509' );
                } );

                it( 'can parse an EC private key', function() {
                    var jwk = deserializeJSON( fileRead( expandPath( '/sampleJWK/sampleECPrivate.json' ) ) );
                    var key = encodingUtils.parseJWK( jwk );
                    expect( key.getAlgorithm() ).toBe( 'EC' );
                    expect( key.getFormat() ).toBe( 'PKCS##8' );
                } );
            } );
        } );
    }

}
