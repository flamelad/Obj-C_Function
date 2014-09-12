//
//  BlowFish.m
//  work
//
//  Created by Yi-Shou on 2014/6/27.
//  Copyright (c) 2014年 Yi-Shou. All rights reserved.
//

#import "BlowFish.h"
#import "BitHelper.h"
#import <CommonCrypto/CommonCrypto.h>
@interface BlowFish()
@end

@implementation BlowFish

-(instancetype)init{
    self = [super init];
        return self;
//    _crypt = [[CkoCrypt2 alloc] init];
//    
//    NSString *keyAscii = @"1234567812345678";
//    NSString *ivAscii = @"12345678";
//    
//    NSString *modeString = @"CBC";
//    self.blowFish = [[BlowfishAlgorithm alloc]init];
//    [self.blowFish setMode:[BlowfishAlgorithm buildModeEnum:modeString]];
//    [self.blowFish setKey:keyAscii];
//    [self.blowFish setInitVector:ivAscii];
//    [self.blowFish setupKey];
//    if([_crypt UnlockComponent: @"Anything for 30-day trial"]){
//        _crypt.CryptAlgorithm=@"blowfish2";
//        _crypt.CipherMode = @"cbc";
//        _crypt.EncodingMode = @"hex";
//        _crypt.KeyLength = [NSNumber numberWithInt:256];
//        _crypt.PaddingScheme = [NSNumber numberWithInt:3];
//        [_crypt SetEncodedIV: ivAscii encoding: @"ascii"];
//        [_crypt SetEncodedKey: keyAscii encoding: @"ascii"];
//    }
//    else
//        NSLog(@"trail day is exceeded, what the fuck?");

}

// message is string that want to be encrypt by blowfish, return encrypted string 

-(NSString *) encode:(NSString *)str{
//    NSLog(@"beforeEncode:%@",str);
    NSMutableData *dataStr=[[NSMutableData alloc] initWithData:[str dataUsingEncoding:NSUTF8StringEncoding]];
    if (([dataStr length]%8)!=0) {
        [dataStr increaseLengthBy:(8-[dataStr length]%8)];
    }
    NSData *encryptData=[self crypt:kCCEncrypt cinpherText:dataStr];
    NSString *returnStr=[BitHelper bytesToHex:(unsigned char*)[encryptData bytes] length:(int)[encryptData length]-8];
//    NSLog(@"encryptData:%@",encryptData);
//    NSLog(@"afterEncode:%@",returnStr);
//    NSLog(@"afterdecrypt:%@",[[NSString alloc]initWithData:[self decode:returnStr] encoding:NSUTF8StringEncoding]);
    return returnStr;
}

// message is an encrypt string from php, return decrypt byte data.

-(id) decode:(NSString *)str{
//    NSLog(@"decode:%@",str);
    NSMutableString *decodeStr=[[NSMutableString alloc]initWithData:[self crypt:kCCDecrypt cinpherText:[BitHelper hexToBytes:str]] encoding:NSUTF8StringEncoding];
    //dirty padding in data, for example:[{"m_id":"44"}]@@@, after "]" character exist some bytes and print can't see that, so need to clear they.
    if ([decodeStr length]!=8) {
        NSRange range=[decodeStr rangeOfString:@"]" options:NSBackwardsSearch];
        NSUInteger datalength=range.location+range.length;
        NSMutableData *returnData=[[NSMutableData alloc]initWithData:[self crypt:kCCDecrypt cinpherText:[BitHelper hexToBytes:str]]];
//        NSLog(@"%d",datalength);
        [returnData setLength:datalength];
            return returnData;
    }
    return [self crypt:kCCDecrypt cinpherText:[BitHelper hexToBytes:str]];

}


-(NSData *)crypt:(uint32_t) operation cinpherText:(NSData *) data{
    NSData *keyAscii = [@"1234567812345678" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivAscii = [@"12345678" dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = 2048;
    size_t datalength=[data length]+8;
    if (operation==kCCEncrypt)
        datalength=[data length];
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus destatus = CCCrypt(operation, kCCAlgorithmBlowfish,
                                       kCCOptionPKCS7Padding,
                                       [keyAscii bytes], [keyAscii length],
                                       [ivAscii bytes],
                                       [data bytes], datalength, /* input */
                                       buffer, bufferSize, /* output */
                                       &numBytesDecrypted);
    
//    NSLog(@"get %lu %lu %p %d", bufferSize, numBytesDecrypted, data, destatus);
    if (destatus == kCCSuccess && operation==kCCDecrypt) {
        //the returned NSData takes ownership of buffer and will free it on dealloc
        return [NSMutableData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }else if(destatus == kCCSuccess && operation==kCCEncrypt)
        return [NSMutableData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    
    free(buffer); //free the buffer;
    return nil;
}
@end
