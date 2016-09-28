//
//  RKEncryptLib.h
//  RKEncryptLib
//
//  Created by Ryuji Kawaida on 28/9/16.
//  Copyright © 2016 Ryuji Kawaida. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCrypto.h>

@interface RKEncryptLib : NSObject

- (NSString *)encryptAES256:(NSString *)decrypted_word key:(NSString *)key;
- (NSString *)decryptAES256:(NSString *)encrypted_word key:(NSString *)key;

@end
