# jwt-cfml

**jwt-cfml** is a CFML (Lucee and ColdFusion) library for encoding and decoding JSON Web Tokens.

It supports the following algorithms:

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- ES256
- ES384
- ES512

In the case of the `RS` and `ES` algorithms, asymmetric keys are expected to be provided in unencrypted PEM or JWK format (in the latter case first deserialize the JWK to a CFML struct). When using PEM, private keys need to be encoded in PKCS#8 format.

If your private key is not currently in this format, conversion should be straightforward:

```bash
$ openssl pkcs8 -topk8 -nocrypt -in privatekey.pem -out privatekey.pk8
```

When decoding tokens, either a public key or certificate can be provided. (If a certificate is provided, the public key will be extracted from it.)

*You can pre-parse your encoded keys and pass the returned Java classes to the `encode()` and `decode()` methods, to avoid having them parsed on every method call. See [Parsing Asymmetric Keys](https://github.com/jcberquist/jwt-cfml-dev/blob/master/README.md#parsing-asymmetric-keys) below.*

## Installation

Installation is done via CommandBox:

```bash
$ box install jwt-cfml
```

`jwt-cfml` will be installed into a `jwtcfml` package directory by default.

*Alternatively the git repository can be cloned into the desired directory.*

### Standalone

Once the library has been installed, the core `jwt` component can be instantiated directly:

```cfc
jwt = new path.to.jwtcfml.models.jwt();
```

### ColdBox Module

You can make use of the library via the injection DSL: `jwt@jwtcfml`

## Usage

### Encoding tokens:

```cfc
payload = {'key': 'value'};
secret = 'secret';
token = jwt.encode(payload, secret, 'HS256');
```

```cfc
pemPrivateKey = '
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
';
token = jwt.encode(payload, pemPrivateKey, 'RS256');
```

```cfc
jwk = {
    "alg": "RS256",
    "d": "...",
    "dp": "...",
    "dq": "...",
    "e": "AQAB",
    "kty": "RSA",
    "n": "...",
    "p": "...",
    "q": "...",
    "qi": "..."
};
token = jwt.encode(payload, jwk, 'RS256');
```

When a token is encoded, a header is automatically included containing
`"typ"` set to `"JWT"` and `"alg"` set to the passed in algorithm. If you
need to add additional headers a fourth argument, `headers`, is available
for this:

```cfc
token = jwt.encode(payload, pemPrivateKey, 'RS256', {'kid': 'abc123'});
```

If your token payload contains `"iat"`, `"exp"`, or `"nbf"` claims, you can
set these to CFML date objects, and they will automatically be converted to
UNIX timestamps in the generated token for you.

```cfc
payload = {'iat': now()};
token = jwt.encode(payload, secret, 'HS256');
```

### Decoding tokens:

```cfc
token = 'eyJ0e...';
secret = 'secret';
payload = jwt.decode(token, secret, 'HS256');
```

```cfc
token = 'eyJ0e...';
pemPublicKey = '
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
';
payload = jwt.decode(token, pemPublicKey, 'RS256');
```

```cfc
token = 'eyJ0e...';
pemCertificate = '
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
';
payload = jwt.decode(token, pemCertificate, 'RS256');
```

```cfc
token = 'eyJ0e...';
jwk = {
    "e": "AQAB",
    "kty": "RSA",
    "alg": "RS256",
    "n": "...",
    "use": "sig"
}
payload = jwt.decode(token, jwk, 'RS256');
```

*Note: This library does not rely solely on the algorithm specified in the token header. You **must** specify the allowed algorithms (either as a string or an array) when calling `decode()`. The algorithm in the token header must match one of the allowed algorithms.*

If the decoded payload contains `"iat"`, `"exp"`, or `"nbf"` claims, they will be automatically converted from UNIX timestamps to CFML date objects for you.

#### Getting the token header

If you need to get the token header before decoding (e.g. you need a `"kid"` from it), you can use the `jwt.getHeader()` method. This will return the token header as a struct.

```cfc
token = 'eyJ0e...';
header = jwt.getHeader(token);

```

#### Token validity

If a token signature is invalid, the `jwt.decode()` method will throw an error. Further, if the payload contains a `"exp"` or `"nbf"` claim these will be verified as well.

If you also wish to verify an audience or issuer claim, you can pass valid claims into the decode method:

```cfc
claims = {
    "iss": "somissuer",
    "aud": "someaudience" // this can also be an array
};

payload = jwt.decode(token, pemCertificate, 'RS256', claims);
```

This argument can also be used to ignore the `"exp"` and `"nbf"` claims or to validate them against a timestamp other than the current time:

```cfc
claims = {
    // `exp` will be validated against 1 min in the past instead of the current time
    "exp": dateAdd('n', -1, now()),
    // `nbf` will be ignored
    "nbf": false
};

payload = jwt.decode(token, pemCertificate, 'RS256', claims);
```

#### Unverified Payload

If you need to get the payload without doing any verification at all you can pass `verify=false` into the decode method:

```cfc
jwt.decode(token = token, verify = false);
```

### Parsing Asymmetric Keys

Every time a PEM key or JWK is passed into `encode()` and `decode()` it must be converted to binary data and then the appropriate Java class created. You can avoid this (minor) overhead by parsing your key upfront, and then passing the generated Java key class directly into `encode()` and `decode()`:

```cfc
pemCertificate = '
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
';
publicKey = jwt.parsePEMEncodedKey(pemCertificate);
payload = jwt.decode(token, publicKey, 'RS256');
```

```cfc
jwk = {
    "e": "AQAB",
    "kty": "RSA",
    "alg": "RS256",
    "n": "AN...",
    "use": "sig"
};
publicKey = jwt.parseJWK(jwk);
payload = jwt.decode(token, publicKey, 'RS256');
```

### Acknowledgments

- <https://github.com/jpadilla/pyjwt>
- <https://github.com/jwtk/jjwt>
- <https://github.com/apache/cxf>
- <https://bitbucket.org/b_c/jose4j>
