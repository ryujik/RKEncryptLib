//
//  RKEncryptLib.m
//  RKEncryptLib
//
//  Created by Ryuji Kawaida on 28/9/16.
//  Copyright © 2016 Ryuji Kawaida. All rights reserved.
//

#import "RKEncryptLib.h"

@implementation RKEncryptLib

#pragma mark -
#pragma mark Methods Public

/*!
 Encrypt (AES256) string with secret key.
 @code
 EncryptSymmetric *crypt = [[EncryptSymmetric alloc] init];
 NSString *word = @"Secret word";
 NSString *key = @"Secret key";
 NSString *result = [crypt encryptAES256:word key:key];
 @endcode
 @param word This is the text that you want to encrypt.
 @param key Secret key for encryption. To make encryption stronger,
 we will not use this key directly.
 We'll first hash the key next step and then use it.
 @returns The autoreleased NSData representation of the encrypt data.
 But, if returned NULL the encrypt is failed.
 @see http://www.imcore.net/ for more information.
 @author Ryuji K.
 
 */
- (NSString *)encryptAES256:(NSString *)word key:(NSString *)key;
{
    NSData *data = [word dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cypherData = [self AES256Encrypt:data key:key];
    return [self base64EncodedStringWithData:cypherData wrap:0];
}


/*!
 Decrypt (AES256) string with secret key.
 @code
 EncryptSymmetric *crypt = [[EncryptSymmetric alloc] init];
 NSString *word = @"XXXXXXXXXX";
 NSString *key = @"Secret key";
 NSString *result = [crypt decryptAES256:word key:key];
 @endcode
 @param encrypted_word This is the text encrypted that you want to decrypt.
 @param key Secret key for decryption. To make dencryption stronger,
 we will not use this key directly.
 We'll first hash the key next step and then use it.
 @returns The autoreleased NSData representation of the decrypt data.
 But, if returned NULL the decrypt is failed.
 @see http://www.imcore.net/ for more information.
 @author Ryuji K.
 
 */
- (NSString *)decryptAES256:(NSString *)encrypted_word key:(NSString *)key;
{
    NSData *cypherData = [self dataWithBase64EncodedString:encrypted_word];
    NSString *strDecrypt = [[NSString alloc] initWithData:[self AES256Decrypt:cypherData key:key]
                                                 encoding:NSUTF8StringEncoding];
    return strDecrypt;
}


#pragma mark -
#pragma mark Methods Private

//********************************************************************************
// Encryption and Decryption (AES 256)
//********************************************************************************
- (NSData *)AES256Encrypt:(NSData *)data key:(NSString *)key {
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    size_t bufferSize     = dataLength + kCCBlockSizeAES128;
    void* buffer          = malloc(bufferSize);
    
    size_t numBytesEncrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess)
        return [NSMutableData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    
    free(buffer);
    return nil;
}


- (NSData *)AES256Decrypt:(NSData *)data key:(NSString *)key {
    char keyPtr[kCCKeySizeAES256 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    size_t bufferSize     = dataLength + kCCBlockSizeAES128;
    void* buffer          = malloc(bufferSize);
    
    size_t numBytesDecrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess)
        return [NSMutableData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    
    free(buffer);
    return nil;
}


//********************************************************************************
// Encode and Decode (Base64)
//********************************************************************************
- (NSString *)base64EncodedStringWithData:(NSData *)data wrap:(NSUInteger)wrapWidth {
    wrapWidth = (wrapWidth / 4) * 4;
    
    const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    long long inputLength = [data length];
    const unsigned char *inputBytes = [data bytes];
    long long maxOutputLength = (inputLength / 3 + 1) * 4;
    
    maxOutputLength += wrapWidth? (maxOutputLength / wrapWidth) * 2: 0;
    unsigned char *outputBytes = (unsigned char *)malloc((u_int32_t)maxOutputLength);
    long long i;
    long long outputLength = 0;
    
    for (i = 0; i < inputLength - 2; i += 3)
    {
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
        outputBytes[outputLength++] = lookup[((inputBytes[i] & 0x03) << 4) | ((inputBytes[i + 1] & 0xF0) >> 4)];
        outputBytes[outputLength++] = lookup[((inputBytes[i + 1] & 0x0F) << 2) | ((inputBytes[i + 2] & 0xC0) >> 6)];
        outputBytes[outputLength++] = lookup[inputBytes[i + 2] & 0x3F];
        
        //add line break
        if (wrapWidth && (outputLength + 2) % (wrapWidth + 2) == 0)
        {
            outputBytes[outputLength++] = '\r';
            outputBytes[outputLength++] = '\n';
        }
    }
    
    //handle left-over data
    if (i == inputLength - 2)
    {
        // = terminator
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
        outputBytes[outputLength++] = lookup[((inputBytes[i] & 0x03) << 4) | ((inputBytes[i + 1] & 0xF0) >> 4)];
        outputBytes[outputLength++] = lookup[(inputBytes[i + 1] & 0x0F) << 2];
        outputBytes[outputLength++] =   '=';
    }
    else if (i == inputLength - 1)
    {
        // == terminator
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0x03) << 4];
        outputBytes[outputLength++] = '=';
        outputBytes[outputLength++] = '=';
    }
    
    //truncate data to match actual output length
    outputBytes = realloc(outputBytes, (u_int32_t)outputLength);
    NSString *result = [[NSString alloc] initWithBytesNoCopy:outputBytes length:(u_int32_t)outputLength encoding:NSASCIIStringEncoding freeWhenDone:YES];
    
#if !__has_feature(objc_arc)
    [result autorelease];
#endif
    
    return (outputLength >= 4)? result: nil;
}

- (NSData *)dataWithBase64EncodedString:(NSString *)string
{
    const char lookup[] =
    {
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 62, 99, 99, 99, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 99, 99, 99, 99, 99, 99,
        99,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 99, 99, 99, 99, 99,
        99, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 99, 99, 99, 99, 99
    };
    
    NSData *inputData = [string dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    long long inputLength = [inputData length];
    const unsigned char *inputBytes = [inputData bytes];
    
    long long maxOutputLength = (inputLength / 4 + 1) * 3;
    NSMutableData *outputData = [NSMutableData dataWithLength:(u_int32_t)maxOutputLength];
    unsigned char *outputBytes = (unsigned char *)[outputData mutableBytes];
    
    int accumulator = 0;
    long long outputLength = 0;
    unsigned char accumulated[] = {0, 0, 0, 0};
    for (long long i = 0; i < inputLength; i++)
    {
        unsigned char decoded = lookup[inputBytes[i] & 0x7F];
        if (decoded != 99)
        {
            accumulated[accumulator] = decoded;
            if (accumulator == 3)
            {
                outputBytes[outputLength++] = (accumulated[0] << 2) | (accumulated[1] >> 4);
                outputBytes[outputLength++] = (accumulated[1] << 4) | (accumulated[2] >> 2);
                outputBytes[outputLength++] = (accumulated[2] << 6) | accumulated[3];
            }
            accumulator = (accumulator + 1) % 4;
        }
    }
    
    //handle left-over data
    if (accumulator > 0) outputBytes[outputLength] = (accumulated[0] << 2) | (accumulated[1] >> 4);
    if (accumulator > 1) outputBytes[++outputLength] = (accumulated[1] << 4) | (accumulated[2] >> 2);
    if (accumulator > 2) outputLength++;
    
    //truncate data to match actual output length
    outputData.length = (u_int32_t)outputLength;
    return outputLength? outputData: nil;
}

@end
