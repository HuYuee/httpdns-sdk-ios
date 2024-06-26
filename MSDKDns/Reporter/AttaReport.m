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
#import "MSDKDnsInfoTool.h"
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <UIKit/UIKit.h>
#import "MSDKDns.h"
#if defined(__has_include)
    #if __has_include("httpdnsIps.h")
        #include "httpdnsIps.h"
    #endif
#endif

@interface AttaReport ()
@property (strong, nonatomic) NSURLSession * session;
@property (strong, nonatomic) NSString *attaid;
@property (strong, nonatomic) NSString *token;
@property (strong, nonatomic) NSString *reportUrl;
@property (assign, nonatomic) NSUInteger limit;
@property (assign, nonatomic) NSUInteger interval;
@property (assign, nonatomic) NSUInteger count;
@property (strong, nonatomic) NSDate *lastReportTime;
@end


@implementation AttaReport

static AttaReport * gSharedInstance = nil;

+ (instancetype) sharedInstance {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gSharedInstance = [[AttaReport alloc] init];
    });
    return gSharedInstance;
}

- (instancetype) init {
    if (self = [super init]) {
        NSURLSessionConfiguration *defaultSessionConfiguration = [NSURLSessionConfiguration defaultSessionConfiguration];
        self.session = [NSURLSession sessionWithConfiguration:defaultSessionConfiguration delegate:nil delegateQueue:nil];
#ifdef httpdnsIps_h
    #if IS_INTL
        self.attaid = ATTAID_INTL;
        self.token = ATTAToken_INTL;
    #else
        self.attaid = ATTAID;
        self.token = ATTAToken;
    #endif
        self.reportUrl = ATTAReportUrl;
        self.limit = ATTAReportDnsSpendLimit;
        self.interval = ATTAReportDnsSpendInterval;
        self.count = 0;
        self.lastReportTime = [NSDate date];
#endif
    }
    return self;
}

- (NSString *)formatReportParams:(NSDictionary *)params {
    /// 客户端ip、运营商、网络类型、hdns加密方式（aes、des、https）、失败时间、请求失败的服务端ip、授权id
    NSString * carrier = [AttaReport getOperatorsType];
    NSString * networkType = [[MSDKDnsNetworkManager shareInstance] networkType];
    int dnsId = [[MSDKDnsParamsManager shareInstance] msdkDnsGetMDnsId];
    NSString *appId = @"";
    int encryptType = [[MSDKDnsParamsManager shareInstance] msdkDnsGetEncryptType];
    unsigned long eventTime = [[NSNumber numberWithDouble:[[NSDate date] timeIntervalSince1970] * 1000] unsignedIntegerValue];
    NSString *deviceName = [[UIDevice currentDevice] name];
    NSString *systemName = [[UIDevice currentDevice] systemName];
    NSString *systemVersion = [[UIDevice currentDevice] systemVersion];
    NSMutableDictionary *dic = [NSMutableDictionary dictionaryWithDictionary:params];
    NSString *eventName = [dic objectForKey:@"eventName"];
    
    int _DNSID = 0;
    #ifdef httpdnsIps_h
        #if IS_INTL
            _DNSID = MSDKDnsId_INTL;
        #else
            _DNSID = MSDKDnsId;
        #endif
    #endif
    // 如果是三网解析域名的请求，dnsID就使用指定的dnsID上报
    if ([eventName isEqualToString:MSDKDnsEventHttpDnsGetHTTPDNSDomainIP]){
        dnsId = _DNSID;
    }
    
    if ([[MSDKDnsParamsManager shareInstance] msdkDnsGetMAppId]) {
        appId = [[MSDKDnsParamsManager shareInstance] msdkDnsGetMAppId];
    }
    
    // 排除掉越狱机器的异常数据
    if (!([systemName isEqualToString:@"iOS"] || [systemName isEqualToString:@"iPadOS"])){
        systemName = @"iOS";
    }
    [dic addEntriesFromDictionary:@{
        @"carrier": carrier,
        @"networkType": networkType,
        @"dnsId": [NSNumber numberWithInt:dnsId],
        @"appId": appId,
        @"encryptType": encryptType == 0 ? @"DesHttp" : (encryptType == 1 ? @"AesHttp" : @"Https"),
        @"eventTime": [NSNumber numberWithLong:eventTime],
        @"deviceName": deviceName,
        @"systemName": systemName,
        @"systemVersion": systemVersion,
        @"sdkVersion": MSDKDns_Version,
        @"sessionId": [MSDKDnsInfoTool generateSessionID]
    }];
    return [self paramsToUrlString:dic];
}

- (NSString *)paramsToUrlString:(NSDictionary *)params {
    NSMutableString *res = [NSMutableString stringWithFormat:@"attaid=%@&token=%@",  _attaid, _token];
    if (params) {
        for (id key in params) {
            [res appendFormat:@"&%@=%@", key, [params objectForKey:key]];
        }
    }
    return res;
}

- (void)reportEvent:(NSDictionary *)params {
    NSURL *url = [NSURL URLWithString:_reportUrl];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    NSString *postData = [self formatReportParams:params];
    request.HTTPBody = [postData dataUsingEncoding:NSUTF8StringEncoding];
    MSDKDNSLOG(@"ATTAReport data: %@", postData);
    NSURLSessionDataTask *dataTask = [self.session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (data && (error == nil)) {
            // 网络访问失败
            MSDKDNSLOG(@"success to report");
        } else {
            // 网络访问失败
            MSDKDNSLOG(@"Failed to report，error：%@",error);
        }
    }];
    [dataTask resume];
}

// 获取运营商类型
+ (NSString*)getOperatorsType{
    CTTelephonyNetworkInfo *telephonyInfo = [[CTTelephonyNetworkInfo alloc] init];
    CTCarrier *carrier = [telephonyInfo subscriberCellularProvider];

    NSString *currentCountryCode = [carrier mobileCountryCode];
    NSString *mobileNetWorkCode = [carrier mobileNetworkCode];

    if (currentCountryCode || mobileNetWorkCode) {
        return [NSString stringWithFormat:@"%@%@", currentCountryCode, mobileNetWorkCode];
    }
    return @"-1";
}

- (BOOL)shoulReportDnsSpend {
//    取消上报次数上限，每5分钟上报一次
//    if (self.count >= self.limit) {
//        return NO;
//    }
    NSDate *now = [NSDate date];
    if ([now timeIntervalSinceDate:self.lastReportTime] >= self.interval) {
        self.lastReportTime = now;
        self.count += 1;
        return YES;
    }
    return NO;
}

@end
