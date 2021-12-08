//
//  AttaReport.m
//  MSDKDns
//
//  Created by vast on 2021/12/7.
//  Copyright © 2021 Tencent. All rights reserved.
//

#import "AttaReport.h"
#import "MSDKDnsLog.h"
#import "MSDKDnsNetworkManager.h"
#import "MSDKDnsParamsManager.h"
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>

static NSString * const reportUrl = @"https://h.trace.qq.com/kv";

@interface AttaReport ()
@property (strong, nonatomic) NSURLSession * session;
@end


@implementation AttaReport

static AttaReport * _sharedInstance = nil;

+ (instancetype) sharedInstance {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedInstance = [[AttaReport alloc] init];
    });
    return _sharedInstance;
}

- (instancetype) init {
    if (self = [super init]) {
        NSURLSessionConfiguration *defaultSessionConfiguration = [NSURLSessionConfiguration defaultSessionConfiguration];
        self.session = [NSURLSession sessionWithConfiguration:defaultSessionConfiguration delegate:nil delegateQueue:nil];
    }
    return self;
}

- (NSString *)formatReportParams:(NSDictionary *)params {
    /// 客户端ip、运营商、网络类型、hdns加密方式（aes、des、https）、失败时间、请求失败的服务端ip、授权id
    NSString * carrier = [AttaReport getOperatorsType];
    NSString * networkType = [[MSDKDnsNetworkManager shareInstance] networkType];
    int dnsId = [[MSDKDnsParamsManager shareInstance] msdkDnsGetMDnsId];
    int encryptType = [[MSDKDnsParamsManager shareInstance] msdkDnsGetEncryptType];
    NSMutableString *reportData = [NSMutableString stringWithFormat:@"attaid=0f500064192&token=4725229671&carrier=%@&networkType=%@&dnsId=%d&encryptType=%d",
                            carrier,
                            networkType,
                            dnsId,
                            encryptType];
    if (params) {
        for (id key in params) {
            [reportData appendFormat:@"&%@=%@", key, [params objectForKey:key]];
        }
    }
    return reportData;
}

- (void)reportEvent:(NSDictionary *)params {
    NSURL *url = [NSURL URLWithString:reportUrl];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    NSString *postData = [self formatReportParams:params];
    request.HTTPBody = [postData dataUsingEncoding:NSUTF8StringEncoding];
    MSDKDNSLOG(@"ATTAReport data: %@", postData);
    NSURLSessionDataTask *dataTask = [self.session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            MSDKDNSLOG(@"ATTAReport response: %@",json);
        }];

    [dataTask resume];
}

// 获取运营商类型
+ (NSString*)getOperatorsType{
    CTTelephonyNetworkInfo *telephonyInfo = [[CTTelephonyNetworkInfo alloc] init];
    CTCarrier *carrier = [telephonyInfo subscriberCellularProvider];

    NSString *currentCountryCode = [carrier mobileCountryCode];
    NSString *mobileNetWorkCode = [carrier mobileNetworkCode];

    if (![currentCountryCode isEqualToString:@"460"]) {
        return @"其他";
    }

    if ([mobileNetWorkCode isEqualToString:@"00"] ||
        [mobileNetWorkCode isEqualToString:@"02"] ||
        [mobileNetWorkCode isEqualToString:@"07"]) {

        // 中国移动
        return @"中国移动";
    }

    if ([mobileNetWorkCode isEqualToString:@"01"] ||
        [mobileNetWorkCode isEqualToString:@"06"] ||
        [mobileNetWorkCode isEqualToString:@"09"]) {

        // 中国联通
        return @"中国联通";
    }

    if ([mobileNetWorkCode isEqualToString:@"03"] ||
        [mobileNetWorkCode isEqualToString:@"05"] ||
        [mobileNetWorkCode isEqualToString:@"11"]) {

        // 中国电信
        return @"中国电信";
    }

    if ([mobileNetWorkCode isEqualToString:@"20"]) {

        // 中国铁通
        return @"中国铁通";
    }

    return @"其他";
}

@end