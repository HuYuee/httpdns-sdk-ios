//
//  MSDKDnsURLSchemeHandler.h
//  MSDKDns
//
//  Created by eric hu on 2024/2/20.
//  Copyright © 2024 Tencent. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface MSDKDnsURLSchemeHandler : NSObject <WKURLSchemeHandler, NSURLSessionDataDelegate>

@end

NS_ASSUME_NONNULL_END
