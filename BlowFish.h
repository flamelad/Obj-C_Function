//
//  BlowFish.h
//  work
//
//  Created by Yi-Shou on 2014/6/27.
//  Copyright (c) 2014年 Yi-Shou. All rights reserved.
//
//  與PHP API資料收送時的加解密
//

#import <Foundation/Foundation.h>

@interface BlowFish : NSObject
-(NSString *) encode:(NSString *)str;
-(id) decode:(NSString *)str;
@end
