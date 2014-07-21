//
//  Shared.m
//  SignAndVerify
//
//  Created by Ricci Adams on 2014-07-20.
//
//

#import "Shared.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>


NSData *GetSHA1Hash(NSData *inData)
{
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];

    CC_SHA1_CTX ctx;

    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, [inData bytes], (CC_LONG)[inData length]);
    CC_SHA1_Final(digest, &ctx);
    
    return [[NSData alloc] initWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
}


NSData *GetSHA256Hash(NSData *inData)
{
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];

    CC_SHA256_CTX ctx;

    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, [inData bytes], (CC_LONG)[inData length]);
    CC_SHA256_Final(digest, &ctx);
    
    return [[NSData alloc] initWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}


NSString *GetHexStringWithData(NSData *data)
{
    NSUInteger inLength  = [data length];
    unichar *outCharacters = malloc(sizeof(unichar) * (inLength * 2));

    UInt8 *inBytes = (UInt8 *)[data bytes];
    static const char lookup[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
 
    NSUInteger i, o = 0;
    for (i = 0; i < inLength; i++) {
        UInt8 inByte = inBytes[i];
        outCharacters[o++] = lookup[(inByte & 0xF0) >> 4];
        outCharacters[o++] = lookup[(inByte & 0x0F)];
    }

    return [[NSString alloc] initWithCharactersNoCopy:outCharacters length:o freeWhenDone:YES];
}


NSData *GetDataWithHexString(NSString *inputString)
{
    NSUInteger inLength = [inputString length];
    
    unichar *inCharacters = alloca(sizeof(unichar) * inLength);
    [inputString getCharacters:inCharacters range:NSMakeRange(0, inLength)];

    UInt8 *outBytes = malloc(sizeof(UInt8) * ((inLength / 2) + 1));

    NSInteger i, o = 0;
    UInt8 outByte = 0;
    for (i = 0; i < inLength; i++) {
        UInt8 c = inCharacters[i];
        SInt8 value = -1;
        
        if      (c >= '0' && c <= '9') value =      (c - '0');
        else if (c >= 'A' && c <= 'F') value = 10 + (c - 'A');
        else if (c >= 'a' && c <= 'f') value = 10 + (c - 'a');            
        
        if (value >= 0) {
            if (i % 2 == 1) {
                outBytes[o++] = (outByte << 4) | value;
                outByte = 0;
            } else {
                outByte = value;
            }

        } else {
            if (o != 0) break;
        }        
    }

    return [NSData dataWithBytesNoCopy:outBytes length:o freeWhenDone:YES];
}


NSString *DoTest(NSString *privateKeyPath, NSString *publicKeyPath, NSString *textPath, NSString *resultsPath)
{
    NSError  *error;
    NSString *contents = [NSString stringWithContentsOfFile:textPath encoding:NSUTF8StringEncoding error:&error];
    
    NSCharacterSet *ws = [NSCharacterSet whitespaceAndNewlineCharacterSet];

    NSMutableArray *sha1Hashes       = [NSMutableArray array];
    NSMutableArray *sha256Hashes     = [NSMutableArray array];

    NSMutableArray *sha1Signatures   = [NSMutableArray array];
    NSMutableArray *sha256Signatures = [NSMutableArray array];

    // For each line in input.txt, calculate the SHA1 and SHA256 of that line
    for (NSString *line in [contents componentsSeparatedByString:@"\n"]) {
        NSData *lineAsData = [[line stringByTrimmingCharactersInSet:ws] dataUsingEncoding:NSUTF8StringEncoding];
        if (![lineAsData length]) continue;

        [sha1Hashes   addObject:GetSHA1Hash(lineAsData)];
        [sha256Hashes addObject:GetSHA256Hash(lineAsData)];
    }


    // Now sign each hash
    Signer *signer = [[Signer alloc] initWithContentsOfFile:privateKeyPath tag:@"com.iccir.SignAndVerify.private-key"];

    for (NSData *hash in sha1Hashes) {
        [sha1Signatures addObject:[signer signSHA1Hash:hash]];
    }

    for (NSData *hash in sha256Hashes) {
        [sha256Signatures addObject:[signer signSHA256Hash:hash]];
    }

    
    // If we have an existing results.txt, verify the hashes/signatures against it
    if ([[NSFileManager defaultManager] fileExistsAtPath:resultsPath]) {
        NSString *existingResults = [NSString stringWithContentsOfFile:resultsPath encoding:NSUTF8StringEncoding error:&error];

        NSInteger i = 0;
        for (NSString *line in [existingResults componentsSeparatedByString:@"\n"]) {
            NSArray *components = [line componentsSeparatedByString:@"\t"];
            if ([components count] != 4) continue;

            NSData *existingSHA1Hash        = GetDataWithHexString(components[0]);
            NSData *existingSHA1Signature   = GetDataWithHexString(components[1]);
            NSData *existingSHA256Hash      = GetDataWithHexString(components[2]);
            NSData *existingSHA256Signature = GetDataWithHexString(components[3]);

            if (![existingSHA1Hash isEqualToData:sha1Hashes[i]]) {
                NSLog(@"SHA-1 Hash mismatch on line %ld", (long)i);
            }

            if (![existingSHA256Hash isEqualToData:sha256Hashes[i]]) {
                NSLog(@"SHA-256 Hash mismatch on line %ld", (long)i);
            }

            if (![existingSHA1Signature isEqualToData:sha1Signatures[i]]) {
                NSLog(@"SHA-1 Signature mismatch on line %ld", (long)i);
            }

            if (![existingSHA256Signature isEqualToData:sha256Signatures[i]]) {
                NSLog(@"SHA-256 Signature mismatch on line %ld", (long)i);
            }

            i++;
        }
    }


    // Verify the signatures with the Verifier and public key
    {
        Verifier *verifier = [[Verifier alloc] initWithContentsOfFile:publicKeyPath tag:@"com.iccir.SignAndVerify.public-key"];

        for (NSInteger i = 0; i < [sha1Hashes count]; i++) {
            if (![verifier verifySHA1Hash:sha1Hashes[i] withSignature:sha1Signatures[i]]) {
                NSLog(@"OS X Verifier failed to verify line %ld", (long)i);
            }

            if (![verifier verifySHA256Hash:sha256Hashes[i] withSignature:sha256Signatures[i]]) {
                NSLog(@"OS X Verifier failed to verify line %ld", (long)i);
            }
        }
    }

    NSMutableString *results = [NSMutableString string];

    for (NSInteger i = 0; i < [sha1Hashes count]; i++) {
        [results appendFormat:@"%@\t%@\t%@\t%@\n",
            GetHexStringWithData(sha1Hashes[i]),
            GetHexStringWithData(sha1Signatures[i]),
            GetHexStringWithData(sha256Hashes[i]),
            GetHexStringWithData(sha256Signatures[i])];
    }
    
    return results;
}



#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR

#pragma mark - iOS Implementations

// From http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/
static NSData *sGetDataByStrippingHeader(NSData *data)
{
    NSUInteger length = [data length];
    if (!length) return nil;

    UInt8 *bytes = (UInt8 *)[data bytes];
    NSUInteger index = 0;
    
    if (bytes[index++] != 0x30) {
        return nil;
    }

    if (bytes[index] > 0x80) {
        index += bytes[index] - 0x80 + 1;
    } else {
        index++;
    }

    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
    if (memcmp(&bytes[index], seqiod, 15)) return(nil);

    index += 15;

    if (bytes[index++] != 0x03) return nil;

    if (bytes[index] > 0x80) {
        index += bytes[index] - 0x80 + 1;
    } else {
        index++;
    }

    if (bytes[index++] != '\0') return nil;

    // Now make a new NSData from this buffer
    return [NSData dataWithBytes:&bytes[index] length:(length - index)];
}


static NSData *sExtractKey(NSString *inString)
{
    NSArray        *inLines   = [inString componentsSeparatedByString:@"\n"];
    NSMutableArray *outLines  = [NSMutableArray array];
    BOOL            insideKey = NO;

    for (NSString *line in inLines) {
        if ([line rangeOfString:@"KEY-----"].location != NSNotFound) {
            if ([line hasPrefix:@"-----BEGIN"]) {
                insideKey = YES;
            } else if ([line hasPrefix:@"-----END"]) {
                insideKey = NO;
            }

        } else if (insideKey) {
            [outLines addObject:line];
        }
    }

    NSString *outString = [outLines componentsJoinedByString:@"\n"];
    
    return [[NSData alloc] initWithBase64EncodedString:outString options:NSDataBase64DecodingIgnoreUnknownCharacters];
}


@implementation Signer {
    SecKeyRef _privateKey;
}

- (id) initWithContentsOfFile:(NSString *)path tag:(NSString *)tag
{
    if ((self = [super init])) {
        _privateKey = [self _importPrivateKeyAtPath:path tag:tag];

        if (!_privateKey) {
            self = nil;
            return self;
        }
    }

    return self;
}


- (SecKeyRef) _importPrivateKeyAtPath:(NSString *)keyPath tag:(NSString *)tag CF_RETURNS_RETAINED
{
    NSError  *error     = nil;
    NSString *contents  = [NSString stringWithContentsOfFile:keyPath encoding:NSUTF8StringEncoding error:&error];
    
    NSData   *keyData   = sExtractKey(contents);

    NSData   *tagAsData = [tag dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus  err       = 0;

    NSMutableDictionary *dictionary = [[NSMutableDictionary alloc] init];
    [dictionary setObject:(__bridge id)kSecClassKey       forKey:(__bridge id)kSecClass];
    [dictionary setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dictionary setObject:tagAsData                       forKey:(__bridge id)kSecAttrApplicationTag];
    err = SecItemDelete((__bridge CFDictionaryRef)dictionary);

    [dictionary setObject:keyData                              forKey:(__bridge id)kSecValueData];
    [dictionary setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];

    err = SecItemAdd((__bridge CFDictionaryRef)dictionary, NULL);

    if ((err != noErr) && (err != errSecDuplicateItem)) {
        return NULL;
    }

    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;

    [dictionary removeObjectForKey:(__bridge id)kSecValueData];
    [dictionary setObject:@YES forKey:(__bridge id)kSecReturnRef];

    err = SecItemCopyMatching((__bridge CFDictionaryRef)dictionary, (CFTypeRef *)&keyRef);

    return keyRef;
}


- (NSData *) _signHash:(NSData *)hash withPadding:(SecPadding)padding
{
    size_t   signatureLength = SecKeyGetBlockSize(_privateKey);
    uint8_t *signatureBytes  = malloc(signatureLength);

    OSStatus err = SecKeyRawSign(_privateKey, padding, [hash bytes], [hash length], signatureBytes, &signatureLength);
    NSData *result = nil;
    
    if (err == errSecSuccess) {
        result = [NSData dataWithBytes:signatureBytes length:signatureLength];
    }
    
    free(signatureBytes);
    
    return result;

}

- (NSData *) signSHA1Hash:(NSData *)hash
{
    return [self _signHash:hash withPadding:kSecPaddingPKCS1SHA1];
}


- (NSData *) signSHA256Hash:(NSData *)hash
{
    return [self _signHash:hash withPadding:kSecPaddingPKCS1SHA256];
}


@end


@implementation Verifier {
    SecKeyRef _publicKey;
}


- (id) initWithContentsOfFile:(NSString *)path tag:(NSString *)tag
{
    if ((self = [super init])) {
        _publicKey = [self _importPublicKeyAtPath:path tag:tag];

        if (!_publicKey) {
            self = nil;
            return self;
        }
    }

    return self;
}


- (SecKeyRef) _importPublicKeyAtPath:(NSString *)keyPath tag:(NSString *)tag CF_RETURNS_RETAINED
{
    NSError  *error     = nil;
    NSString *contents  = [NSString stringWithContentsOfFile:keyPath encoding:NSUTF8StringEncoding error:&error];
    
    NSData   *keyData   = sGetDataByStrippingHeader(sExtractKey(contents));

    NSData   *tagAsData = [tag dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus  err       = 0;

    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id)kSecClassKey       forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:tagAsData                       forKey:(__bridge id)kSecAttrApplicationTag];
    err = SecItemDelete((__bridge CFDictionaryRef)publicKey);

    [publicKey setObject:keyData                             forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];

    err = SecItemAdd((__bridge CFDictionaryRef)publicKey, NULL);

    if ((err != noErr) && (err != errSecDuplicateItem)) {
        return NULL;
    }

    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;

    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey setObject:@YES forKey:(__bridge id)kSecReturnRef];

    err = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);

    return keyRef;
}


- (BOOL) verifySHA1Hash:(NSData *)hash withSignature:(NSData *)signature
{
    OSStatus err = SecKeyRawVerify(_publicKey, kSecPaddingPKCS1SHA1, [hash bytes], [hash length], [signature bytes], [signature length]);
    return err == errSecSuccess;
}


- (BOOL) verifySHA256Hash:(NSData *)hash withSignature:(NSData *)signature
{
    OSStatus err = SecKeyRawVerify(_publicKey, kSecPaddingPKCS1SHA256, [hash bytes], [hash length], [signature bytes], [signature length]);
    return err == errSecSuccess;
}

@end


#else

#pragma mark - OS X Implementations

@implementation Signer {
    SecKeyRef _privateKey;
}

- (id) initWithContentsOfFile:(NSString *)path tag:(NSString *)tag
{
    if ((self = [super init])) {
        _privateKey = [self _importPrivateKeyAtPath:path tag:tag];

        if (!_privateKey) {
            self = nil;
            return self;
        }
    }
    
    return self;
}


- (SecKeyRef) _importPrivateKeyAtPath:(NSString *)path tag:(NSString *)tag CF_RETURNS_RETAINED
{
    NSData *data = [NSData dataWithContentsOfFile:path];

	SecExternalFormat   format = kSecFormatOpenSSL;
    SecExternalItemType type   = kSecItemTypePrivateKey;
    
    CFArrayRef cfItems = NULL;
    SecItemImport((__bridge CFDataRef)data, NULL, &format, &type, 0, NULL, NULL, &cfItems);

    NSArray *result = cfItems ? CFBridgingRelease(cfItems) : NULL;
    return (SecKeyRef) (result ? CFBridgingRetain([result lastObject]) : nil);
}


- (NSData *) _signHash:(NSData *)hash digestType:(CFStringRef)digestType digestLength:(NSUInteger)digestLength
{
    CFErrorRef error;
    SecTransformRef signer = SecSignTransformCreate(_privateKey, &error);
    CFTypeRef cfResult = NULL;
    
    SecTransformSetAttribute(signer, kSecPaddingKey, kSecPaddingPKCS1Key, &error);
    if (error) goto bail;

    SecTransformSetAttribute(signer, kSecInputIsAttributeName, kSecInputIsDigest, &error);
    if (error) goto bail;

    SecTransformSetAttribute(signer, kSecTransformInputAttributeName, (__bridge CFDataRef)hash, &error);
    if (error) goto bail;

    SecTransformSetAttribute(signer, kSecDigestTypeAttribute, digestType, &error);
    if (error) goto bail;
    
    if (digestLength) {
        SecTransformSetAttribute(signer, kSecDigestLengthAttribute, (__bridge CFNumberRef)@(digestLength), &error);
        if (error) goto bail;
    }

    cfResult = SecTransformExecute(signer, &error);

bail:
    if (error) {
        NSLog(@"Error: %@", error);
    }

    if (signer) {
        CFRelease(signer);
    }

    return CFBridgingRelease(cfResult);
}


- (NSData *) signSHA1Hash:(NSData *)hash
{
    return [self _signHash:hash digestType:kSecDigestSHA1 digestLength:0];
}


- (NSData *) signSHA256Hash:(NSData *)hash
{
    return [self _signHash:hash digestType:kSecDigestSHA2 digestLength:256];
}


@end


@implementation Verifier {
    SecKeyRef _publicKey;
}


- (id) initWithContentsOfFile:(NSString *)path tag:(NSString *)tag
{
    if ((self = [super init])) {
        _publicKey = [self _importPublicKeyAtPath:path tag:tag];

        if (!_publicKey) {
            self = nil;
            return self;
        }
    }

    return self;
}


- (SecKeyRef) _importPublicKeyAtPath:(NSString *)keyPath tag:(NSString *)tag CF_RETURNS_RETAINED
{
    NSData *data = [NSData dataWithContentsOfFile:keyPath];

	SecExternalFormat   format = kSecFormatOpenSSL;
    SecExternalItemType type   = kSecItemTypePublicKey;
    
    CFArrayRef cfItems = NULL;
    SecItemImport((__bridge CFDataRef)data, NULL, &format, &type, 0, NULL, NULL, &cfItems);

    NSArray *result = cfItems ? CFBridgingRelease(cfItems) : NULL;
    return (SecKeyRef) (result ? CFBridgingRetain([result lastObject]) : nil);
}


- (BOOL) _verifyHash:(NSData *)hash withSignature:(NSData *)signature digestType:(CFStringRef)digestType digestLength:(NSUInteger)digestLength
{
    CFErrorRef error;
    id result;

    SecTransformRef verifier = SecVerifyTransformCreate(_publicKey, (__bridge CFDataRef)signature, &error);
    if (error) goto bail;

    SecTransformSetAttribute(verifier, kSecPaddingKey, kSecPaddingPKCS1Key, &error);
    if (error) goto bail;

    SecTransformSetAttribute(verifier, kSecInputIsAttributeName, kSecInputIsDigest, &error);
    if (error) goto bail;

    SecTransformSetAttribute(verifier, kSecTransformInputAttributeName, (__bridge CFDataRef)hash, &error);
    if (error) goto bail;

    SecTransformSetAttribute(verifier, kSecDigestTypeAttribute, digestType, &error);
    if (error) goto bail;
    
    if (digestLength) {
        SecTransformSetAttribute(verifier, kSecDigestLengthAttribute,   (__bridge CFNumberRef)@(digestLength), &error);
        if (error) goto bail;
    }

    result = CFBridgingRelease(SecTransformExecute(verifier, &error));
    
bail:
    if (error) {
        NSLog(@"Error: %@", error);
    }

    if (verifier) {
        CFRelease(verifier);
    }

    if ([result respondsToSelector:@selector(boolValue)]) {
        return [result boolValue];
    }
    
    return NO;
}


- (BOOL) verifySHA1Hash:(NSData *)hash withSignature:(NSData *)signature
{

    return [self _verifyHash:hash withSignature:signature digestType:kSecDigestSHA1 digestLength:0];
}


- (BOOL) verifySHA256Hash:(NSData *)hash withSignature:(NSData *)signature
{
    return [self _verifyHash:hash withSignature:signature digestType:kSecDigestSHA2 digestLength:256];
}


@end

#endif
