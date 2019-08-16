component {

    public any function init() {
        variables.utcBaseDate = createObject( 'java', 'java.util.Date' ).init( javacast( 'int', 0 ) );
        variables.ECParameterSpecCache = { };
    }

    function convertDateToUnixTimestamp( required date dateToConvert ) {
        return dateDiff( 's', utcBaseDate, parseDateTime( dateToConvert ) );
    }

    function convertUnixTimestampToDate( required numeric timestamp ) {
        return dateAdd( 's', timestamp, utcBaseDate );
    }

    function base64UrlToBinary( base64url ) {
        var base64 = base64url.replace( '-', '+', 'all' ).replace( '_', '/', 'all' );
        var padded = base64 & repeatString( '=', 4 - ( len( base64 ) % 4 ) );
        return binaryDecode( padded, 'base64' );
    }

    function binaryToBase64Url( source ) {
        return binaryEncode( source, 'base64' )
            .replace( '+', '-', 'all' )
            .replace( '/', '_', 'all' )
            .replace( '=', '', 'all' );
    }

    /**
    * The INTEGER encoding for DER consists of a 02 tag a length encoding of the value
    * and then a signed, minimum sized, big endian encoding of the encoded number.
    *
    * - https://stackoverflow.com/questions/54718741/how-to-der-encode-an-ecdsa-signature
    */
    function derEncodeIntegerBytes( byteArray ) {
        // first remove any padding
        for ( var i = 1; i <= arrayLen( byteArray ); i++ ) {
            if ( byteArray[ i ] != 0 ) break;
        }
        var unpadded = arraySlice( byteArray, i );

        // add sign if negative
        if ( unpadded[ 1 ] < 0 ) {
            unpadded.prepend( 0 );
        }

        // if len > 127 the length encoding will be wrong, but that won't happen for the supported signature sizes
        var derEncoded = [ 2, unpadded.len() ];

        derEncoded.append( unpadded, true );

        return derEncoded;
    }


    /**
    * The SEQUENCE encoding is simply a tag set to the byte value 30, the
    * length encoding and then the concatenation of the two INTEGER
    * structures.
    *
    * https://stackoverflow.com/questions/54718741/how-to-der-encode-an-ecdsa-signature
    *
    * Also see:
    * https://crypto.stackexchange.com/questions/57731/ecdsa-signature-rs-to-asn1-der-encoding-question
    */
    function convertP1363ToDER( signature ) {
        var split = len( signature ) / 2;
        var r = derEncodeIntegerBytes( arraySlice( signature, 1, split ) );
        var s = derEncodeIntegerBytes( arraySlice( signature, split + 1, split ) );

        var DERSignature = [ 48 ];

        var length = r.len() + s.len();

        if ( length > 255 ) {
            throw(
                type = 'jwtcfml.InvalidSignature',
                message = 'Invalid P1363 key.',
                detail = 'The P1363 signature is too long.'
            );
        }

        /*
            The length is simply a single byte if it is smaller than 128 (or hex 80)
            of the size. If it is larger then it is two byte: one byte set to 81,
            which indicates that one length byte will follow, and one byte
            containing the actual value.

            https://stackoverflow.com/questions/54718741/how-to-der-encode-an-ecdsa-signature
        */
        if ( length > 127 ) {
            DERSignature.append( -127 );
            length -= 256;
        }
        DERSignature.append( length );

        DERSignature.append( r, true );
        DERSignature.append( s, true );

        return javacast( 'byte[]', DERSignature );
    }

    function convertDERtoP1363( required any signature, required string algorithm ) {
        // extract the two integers from the DER signature
        // assuming a 02 tag byte followed by a single length byte since we should not see
        // anything larger in the supported algorithms
        var start = 3;
        while ( signature[ start ] != 2 ) start++;
        var r = arraySlice( signature, start + 2, signature[ start + 1 ] );
        var s = arraySlice( signature, start + 2 + r.len() + 2 );

        if ( r[ 1 ] == 0 ) r = arraySlice( r, 2 );
        if ( s[ 1 ] == 0 ) s = arraySlice( s, 2 );

        var lengthMap = {
            ES256: 32,
            ES384: 48,
            ES512: 64
        };

        var P1363Signature = [ ];

        for ( var i = 1; i <= lengthMap[ algorithm ] - r.len(); i++ ) P1363Signature.append( 0 );
        P1363Signature.append( r, true );

        for ( var i = 1; i <= lengthMap[ algorithm ] - s.len(); i++ ) P1363Signature.append( 0 );
        P1363Signature.append( s, true );

        return javacast( 'byte[]', P1363Signature );
    }

    function parsePEMEncodedKey( required string pemKey ) {
        if ( reFind( '^-----BEGIN (RSA|EC) (PARAMETERS|PRIVATE)', pemKey ) ) {
            throw(
                type = 'jwtcfml.InvalidPrivateKey',
                message = 'Invalid private key format.',
                detail = 'Please encode your private key in PKCS8 format, e.g.: `openssl pkcs8 -topk8 -nocrypt -in privatekey.pem -out privatekey.pk8'
            )
        }

        var binaryKey = binaryDecode(
            trim( pemKey ).reReplace( '-----[A-Z\s]+-----', '', 'all' ).reReplace( '[\r\n]', '', 'all' ),
            'base64'
        );

        if ( find( '-----BEGIN CERTIFICATE-----', pemKey ) ) {
            var bis = createObject( 'java', 'java.io.ByteArrayInputStream' ).init( binaryKey );
            return createObject( 'java', 'java.security.cert.CertificateFactory' )
                .getInstance( 'X.509' )
                .generateCertificate( bis )
                .getPublicKey();
        }

        if ( find( '-----BEGIN PUBLIC KEY-----', pemKey ) ) {
            var publicKeySpec = createObject( 'java', 'java.security.spec.X509EncodedKeySpec' ).init( binaryKey );
            try {
                return createObject( 'java', 'java.security.KeyFactory' )
                    .getInstance( 'RSA' )
                    .generatePublic( publicKeySpec );
            } catch ( any e ) {
            }
            try {
                return createObject( 'java', 'java.security.KeyFactory' )
                    .getInstance( 'EC' )
                    .generatePublic( publicKeySpec );
            } catch ( any e ) {
            }
        }

        if ( find( '-----BEGIN PRIVATE KEY-----', pemKey ) ) {
            var privateKeySpec = createObject( 'java', 'java.security.spec.PKCS8EncodedKeySpec' ).init( binaryKey );
            try {
                return createObject( 'java', 'java.security.KeyFactory' )
                    .getInstance( 'RSA' )
                    .generatePrivate( privateKeySpec );
            } catch ( any e ) {
            }
            try {
                return createObject( 'java', 'java.security.KeyFactory' )
                    .getInstance( 'EC' )
                    .generatePrivate( privateKeySpec );
            } catch ( any e ) {
            }
        }

        throw(
            type = 'jwtcfml.InvalidPEMKey',
            message = 'Invalid PEM key.',
            detail = 'Please ensure you are using an RSA or EC public or private key or certificate.'
        )
    }

    function parseJWK( required struct jwk ) {
        if ( jwk.kty == 'RSA' ) {
            if ( jwk.keyExists( 'd' ) ) {
                try {
                    var bigInts = bigIntegers( jwk, [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi' ] );
                    var keySpec = createObject( 'java', 'java.security.spec.RSAPrivateCrtKeySpec' ).init(
                        bigInts.n,
                        bigInts.e,
                        bigInts.d,
                        bigInts.p,
                        bigInts.q,
                        bigInts.dp,
                        bigInts.dq,
                        bigInts.qi
                    );
                    var kf = createObject( 'java', 'java.security.KeyFactory' ).getInstance( 'RSA' );
                    return kf.generatePrivate( keySpec );
                } catch ( any e ) {
                }

                try {
                    var bigInts = bigIntegers( jwk, [ 'n', 'd' ] );
                    var keySpec = createObject( 'java', 'java.security.spec.RSAPrivateKeySpec' ).init(
                        bigInts.n,
                        bigInts.d
                    );
                    var kf = createObject( 'java', 'java.security.KeyFactory' ).getInstance( 'RSA' );
                    return kf.generatePrivate( keySpec );
                } catch ( any e ) {
                }
            } else {
                try {
                    var bigInts = bigIntegers( jwk, [ 'n', 'e' ] );
                    var ks = createObject( 'java', 'java.security.spec.RSAPublicKeySpec' ).init( bigInts.n, bigInts.e );
                    var kf = createObject( 'java', 'java.security.KeyFactory' ).getInstance( 'RSA' );
                    return kf.generatePublic( ks );
                } catch ( any e ) {
                }
            }
        }

        if ( jwk.kty == 'EC' ) {
            var kf = createObject( 'java', 'java.security.KeyFactory' ).getInstance( 'EC' );
            var ECParameterSpec = getECParameterSpec( jwk.crv );

            if ( jwk.keyExists( 'd' ) ) {
                var bigInts = bigIntegers( jwk, [ 'd' ] );
                var ks = createObject( 'java', 'java.security.spec.ECPrivateKeySpec' ).init(
                    bigInts.d,
                    ECParameterSpec
                );
                return kf.generatePrivate( ks );
            } else {
                var bigInts = bigIntegers( jwk, [ 'x', 'y' ] );
                var ECPoint = createObject( 'java', 'java.security.spec.ECPoint' ).init( bigInts.x, bigInts.y );
                var ks = createObject( 'java', 'java.security.spec.ECPublicKeySpec' ).init( ECPoint, ECParameterSpec );
                return kf.generatePublic( ks );
            }
        }

        throw(
            type = 'jwtcfml.InvalidJWK',
            message = 'Invalid JWK key.',
            detail = 'Please ensure you are using an valid JWK RSA or EC public or private key.'
        )
    }

    private function bigIntegers( jwk, keys ) {
        var bigInts = { };
        for ( var key in keys ) {
            bigInts[ key ] = createObject( 'java', 'java.math.BigInteger' ).init( 1, base64UrlToBinary( jwk[ key ] ) );
        }
        return bigInts;
    }

    private function getECParameterSpec( crv ) {
        if ( !variables.ECParameterSpecCache.keyExists( crv ) ) {
            var kpg = createObject( 'java', 'java.security.KeyPairGenerator' ).getInstance( 'EC' );
            var ecgp = createObject( 'java', 'java.security.spec.ECGenParameterSpec' ).init(
                'secp#crv.listLast( '-' )#r1'
            );
            kpg.initialize( ecgp );
            variables.ECParameterSpecCache[ crv ] = kpg
                .generateKeyPair()
                .getPublic()
                .getParams();
        }
        return variables.ECParameterSpecCache[ crv ];
    }

}
