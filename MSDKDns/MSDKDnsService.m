/**
 * Copyright (c) Tencent. All rights reserved.
 */

#import "MSDKDnsService.h"
#import "HttpsDnsResolver.h"
#import "LocalDnsResolver.h"
#import "MSDKDnsInfoTool.h"
#import "MSDKDnsLog.h"
#import "MSDKDnsPrivate.h"
#import "MSDKDnsManager.h"
#import "MSDKDnsDB.h"
#import "MSDKDnsNetworkManager.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsTCPSpeedTester.h"
#import "AttaReport.h"

@interface MSDKDnsService () <MSDKDnsResolverDelegate>

@property (strong, nonatomic) NSArray * toCheckDomains;
@property (strong, nonatomic) HttpsDnsResolver * httpDnsResolver_A;
@property (strong, nonatomic) HttpsDnsResolver * httpDnsResolver_4A;
@property (strong, nonatomic) HttpsDnsResolver * httpDnsResolver_BOTH;
@property (strong, nonatomic) LocalDnsResolver * localDnsResolver;
@property (nonatomic, strong) void (^ completionHandler)();
@property (atomic, assign) BOOL isCallBack;
@property (nonatomic) msdkdns::MSDKDNS_TLocalIPStack netStack;
@property (nonatomic, assign) int httpdnsFailCount;
@property (nonatomic, assign) float timeOut;
@property (nonatomic, assign) int dnsId;
@property (nonatomic, strong) NSString* dnsServer;
@property (nonatomic, strong) NSString* dnsRouter;
@property (nonatomic, strong) NSString* dnsKey;
@property (nonatomic, strong) NSString* origin;
@property (nonatomic, strong) NSString* dnsToken;
@property (nonatomic, strong) NSDate * startTime;
@property (nonatomic, assign) NSUInteger encryptType;
@property (nonatomic, assign) BOOL httpOnly;
@property (nonatomic, assign) BOOL enableReport;
@property (nonatomic, assign) BOOL isRetryRequest;
@property (nonatomic, assign) NSUInteger retryCount;
@end

@implementation MSDKDnsService

- (void)dealloc {
    [self setToCheckDomains:nil];
    [self setHttpDnsResolver_A:nil];
    [self setHttpDnsResolver_4A:nil];
    [self setLocalDnsResolver:nil];
    [self setCompletionHandler:nil];
}

- (void)getHostsByNames:(NSArray *)domains timeOut:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey netStack:(msdkdns::MSDKDNS_TLocalIPStack)netStack encryptType:(NSInteger)encryptType returnIps:(void (^)())handler
{
    [self getHostsByNames:domains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:netStack encryptType:encryptType from:MSDKDnsEventHttpDnsNormal returnIps:handler];
}

- (void)getHostsByNames:(NSArray *)domains timeOut:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey netStack:(msdkdns::MSDKDNS_TLocalIPStack)netStack encryptType:(NSInteger)encryptType from:(NSString *)origin returnIps:(void (^)())handler
{
    self.completionHandler = handler;
    self.toCheckDomains = domains;
    self.isCallBack = NO;
    self.netStack = netStack;
    self.origin = origin;
    self.httpdnsFailCount = 0;
    self.startTime = [NSDate date];
    [self startCheck:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
}

- (void)getHttpDNSDomainIPsByNames:(NSArray *)domains
                           timeOut:(float)timeOut
                             dnsId:(int)dnsId
                            dnsKey:(NSString *)dnsKey
                          netStack:(msdkdns::MSDKDNS_TLocalIPStack)netStack
                       encryptType:(NSInteger)encryptType
                          httpOnly:(BOOL)httpOnly
                              from:(NSString *)origin
                         returnIps:(void (^)())handler {
    self.completionHandler = handler;
    self.toCheckDomains = domains;
    self.isCallBack = NO;
    self.netStack = netStack;
    self.origin = origin;
    self.httpdnsFailCount = 0;
    self.startTime = [NSDate date];
    self.timeOut = timeOut;
    self.dnsId = dnsId;
    self.dnsKey = dnsKey;
    self.encryptType = encryptType;
    self.httpOnly = httpOnly;
    
    [self startCheck];
}

#pragma mark - startCheck

- (void)startCheck:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@, MSDKDns startCheck", self.toCheckDomains);
    BOOL expiredIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetExpiredIPEnabled];
    // 当过期缓存expiredIPEnabled未开启的情况下，才清除缓存
    if (!expiredIPEnabled) {
        //查询前清除缓存
        [[MSDKDnsManager shareInstance] clearCacheForDomains:self.toCheckDomains];
    }
    
    //无网络直接返回
    if (![[MSDKDnsNetworkManager shareInstance] networkAvailable]) {
        MSDKDNSLOG(@"No network,please check your network setting!");
        [self callNotify];
        return;
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_None) {
        MSDKDNSLOG(@"No network stack, please check your network setting!");
        [self callNotify];
        return;
    }
    
    self.timeOut = timeOut;
    self.dnsId = dnsId;
    self.dnsKey = dnsKey;
    self.encryptType = encryptType;
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_IPv6) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startHttpDns_4A:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_IPv4) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startHttpDns:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_Dual) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startHttpDnsBoth:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
        });
    }
    
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    // 设置httpOnly为YES，或者开启了expiredIPEnabled过期IP的情况下，就不下发LocalDns请求
    if (!httpOnly && !expiredIPEnabled) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startLocalDns:timeOut dnsId:dnsId dnsKey:dnsKey];
        });
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, timeOut * NSEC_PER_SEC), [MSDKDnsInfoTool msdkdns_queue], ^{
        if(!self.isCallBack) {
            MSDKDNSLOG(@"DnsService timeOut!");
            [self dnsTimeoutAttaUpload:self.origin];
            [self callNotify];
        }
    });
}

- (void)startCheck {
    MSDKDNSLOG(@"%@, MSDKDns startCheck", self.toCheckDomains);
    BOOL expiredIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetExpiredIPEnabled];
    // 当过期缓存expiredIPEnabled未开启的情况下，才清除缓存
    if (!expiredIPEnabled) {
        //查询前清除缓存
        [[MSDKDnsManager shareInstance] clearCacheForDomains:self.toCheckDomains];
    }
    
    //无网络直接返回
    if (![[MSDKDnsNetworkManager shareInstance] networkAvailable]) {
        MSDKDNSLOG(@"No network,please check your network setting!");
        [self callNotify];
        return;
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_None) {
        MSDKDNSLOG(@"No network stack, please check your network setting!");
        [self callNotify];
        return;
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_IPv6) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startHttpDns_4A:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey encryptType:self.encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_IPv4) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startHttpDns:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey encryptType:self.encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_Dual) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startHttpDnsBoth:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey encryptType:self.encryptType];
        });
    }
    
    if (!self.httpOnly) {
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            [self startLocalDns:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey];
        });
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, self.timeOut * NSEC_PER_SEC), [MSDKDnsInfoTool msdkdns_queue], ^{
        if(!self.isCallBack) {
            MSDKDNSLOG(@"DnsService timeOut!");
            [self dnsTimeoutAttaUpload:self.origin];
            [self callNotify];
        }
    });
}

//进行httpdns ipv4和ipv6合并请求
- (void)startHttpDnsBoth:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@ StartHttpDns!", self.toCheckDomains);
    self.httpDnsResolver_BOTH = [[HttpsDnsResolver alloc] init];
    self.httpDnsResolver_BOTH.delegate = self;
    [self.httpDnsResolver_BOTH startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:msdkdns::MSDKDNS_ELocalIPStack_Dual encryptType:encryptType];
}

//进行httpdns ipv4请求
- (void)startHttpDns:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@ StartHttpDns!", self.toCheckDomains);
    self.httpDnsResolver_A = [[HttpsDnsResolver alloc] init];
    self.httpDnsResolver_A.delegate = self;
    [self.httpDnsResolver_A startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4 encryptType:encryptType];
}

//进行httpdns ipv6请求
- (void)startHttpDns_4A:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@ StartHttpDns!", self.toCheckDomains);
    self.httpDnsResolver_4A = [[HttpsDnsResolver alloc] init];
    self.httpDnsResolver_4A.delegate = self;
    [self.httpDnsResolver_4A startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv6 encryptType:encryptType];
}

//进行localdns请求
- (void)startLocalDns:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey {
    MSDKDNSLOG(@"%@ startLocalDns!", self.toCheckDomains);
    self.localDnsResolver = [[LocalDnsResolver alloc] init];
    self.localDnsResolver.delegate = self;
    [self.localDnsResolver startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:_netStack];
}

#pragma mark - MSDKDnsResolverDelegate

- (void)resolver:(MSDKDnsResolver *)resolver didGetDomainInfo:(NSDictionary *)domainInfo {
    MSDKDNSLOG(@"%@ %@ domainInfo = %@", self.toCheckDomains, [resolver class], domainInfo);
    // 结果存缓存
    dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
        [self cacheDomainInfo:resolver];
        NSDictionary * info = @{
            kDnsErrCode:MSDKDns_Success,
            kDnsErrMsg:@"",
            kDnsRetry: @(self.httpdnsFailCount)
        };
        [self callBack:resolver Info:info];
        if (resolver == self.httpDnsResolver_A || resolver == self.httpDnsResolver_4A || resolver == self.httpDnsResolver_BOTH) {
            NSArray *keepAliveDomains = [[MSDKDnsParamsManager shareInstance] msdkDnsGetKeepAliveDomains];
            BOOL enableKeepDomainsAlive = [[MSDKDnsParamsManager shareInstance] msdkDnsGetEnableKeepDomainsAlive];
            // 获取延迟记录字典
            NSMutableDictionary *domainISOpenDelayDispatch = [[MSDKDnsManager shareInstance] msdkDnsGetDomainISOpenDelayDispatch];
            [domainInfo enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull domain, id  _Nonnull obj, BOOL * _Nonnull stop) {
                // NSLog(@"domain = %@", domain);
                // NSLog(@"domainInfo = %@", domainInfo);
                // 判断此次请求的域名中有多少属于保活域名，是则开启延时解析请求，自动刷新缓存
                if (enableKeepDomainsAlive && keepAliveDomains && domain && [keepAliveDomains containsObject:domain]) {
                    NSMutableString * afterTime = [[NSMutableString alloc] init];
                    if(resolver == self.httpDnsResolver_BOTH){
                        NSDictionary *domainResult = domainInfo[domain];
                        if (domainResult) {
                            NSDictionary *ipv4Value = [domainResult objectForKey:@"ipv4"];
                            NSDictionary *ipv6Value = [domainResult objectForKey:@"ipv6"];
                            if (ipv6Value) {
                                NSString *ttl = [ipv6Value objectForKey:kTTL];
                                afterTime = [[NSMutableString alloc]initWithString:ttl];
                            }
                            if (ipv4Value) {
                                NSString *ttl = [ipv4Value objectForKey:kTTL];
                                afterTime = [[NSMutableString alloc]initWithString:ttl];
                            }
                        }
                    }else{
                        NSDictionary *domainResult = domainInfo[domain];
                        if (domainResult) {
                            NSString *ttl = [domainResult objectForKey:kTTL];
                            afterTime = [[NSMutableString alloc]initWithString:ttl];
                        }
                    }
                    //  NSLog(@"4444444延时更新请求等待，预计在%f秒后开始!请求域名为%@",afterTime.floatValue,domain);
                    if (!domainISOpenDelayDispatch[domain] && afterTime.floatValue > 0) {
                        // NSLog(@"获取缓存延时更新after，初始值为%f秒。", afterTime.floatValue);
                        afterTime = [NSMutableString stringWithFormat:@"%f", afterTime.floatValue * 0.75];
                        if (afterTime.floatValue < 60) {
                            afterTime = [[NSMutableString alloc]initWithString:@"60"];
                        }
                        // 使用静态字典来记录该域名是否开启了一个延迟解析请求，如果已经开启则忽略，没有则立马开启一个
                        [[MSDKDnsManager shareInstance] msdkDnsAddDomainOpenDelayDispatch:domain];
                        MSDKDNSLOG(@"Start the delayed execution task, it is expected to start requesting the domain name %@ after %f seconds", domain, afterTime.floatValue);
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, afterTime.floatValue * NSEC_PER_SEC), [MSDKDnsInfoTool msdkdns_queue], ^{
                            // NSLog(@"缓存延时更新请求开始!请求域名为%@", domain);
                            BOOL enableKeepDomainsAlive = [[MSDKDnsParamsManager shareInstance] msdkDnsGetEnableKeepDomainsAlive];
                            if (enableKeepDomainsAlive) {
                                MSDKDNSLOG(@"The cache update request start! request domain:%@",domain);
                                [[MSDKDnsManager shareInstance] refreshCacheDelay:@[domain] clearDispatchTag:YES];
                            }else {
                                [[MSDKDnsManager shareInstance] msdkDnsClearDomainsOpenDelayDispatch:@[domain]];
                            }
                        });
                    }
                }
            }];
        }
        // 处理IP优选逻辑
        [self excuteIPRank:resolver didGetDomainInfo:domainInfo];
    });
}

- (void)excuteIPRank:(MSDKDnsResolver *)resolver didGetDomainInfo:(NSDictionary *)domainInfo {
    if (resolver == self.httpDnsResolver_A || resolver == self.httpDnsResolver_BOTH) {
        NSDictionary *IPRankData = [[MSDKDnsParamsManager shareInstance] msdkDnsGetIPRankData];
        if (IPRankData) {
            [domainInfo enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull domain, id  _Nonnull obj, BOOL * _Nonnull stop) {
                if (!domain) {
                    return;
                }
                NSArray *allHost = [IPRankData allKeys];
                
                if (!allHost || allHost.count == 0) {
                    return;
                }
                if (![allHost containsObject:domain]) {
                    return;
                }
                @try {
                    if(resolver == self.httpDnsResolver_BOTH){
                        NSDictionary *domainResult = domainInfo[domain];
                        if (domainResult) {
                            NSDictionary *ipv4Value = [domainResult objectForKey:@"ipv4"];
                            if (ipv4Value) {
                                NSArray *ips = [ipv4Value objectForKey:kIP];
                                if(ips){
                                    [self aysncUpdateIPRankingWithResult:ips forHost:domain];
                                }
                            }
                        }
                    }else{
                        NSDictionary *domainResult = domainInfo[domain];
                        if (domainResult) {
                            NSArray *ips = [domainResult objectForKey:kIP];
                            if(ips){
                                [self aysncUpdateIPRankingWithResult:ips forHost:domain];
                            }
                        }
                    }
                } @catch (NSException *exception) {}
            }];
        }
    }
}

- (NSDictionary *)getDomainsDNSFromCache:(NSArray *)domains {
    NSDictionary * cacheDict = [[MSDKDnsManager shareInstance] domainDict];
    NSString * localDnsIPs = @"";
    NSString * httpDnsIP_A = @"";
    NSString * httpDnsIP_4A = @"";
    if (cacheDict) {
        for (NSString *domain in domains) {
            NSDictionary * cacheInfo = cacheDict[domain];
            if (cacheInfo) {
                NSDictionary * localDnsCache = cacheInfo[kMSDKLocalDnsCache];
                if (localDnsCache) {
                    NSArray * ipsArray = localDnsCache[kIP];
                    if (ipsArray && [ipsArray count] == 2) {
                        if ([localDnsIPs length] > 0) {
                            localDnsIPs = [NSString stringWithFormat:@"%@,%@", localDnsIPs, [MSDKDnsInfoTool getIPsStringFromIPsArray:ipsArray]];
                        } else {
                            localDnsIPs = [NSString stringWithFormat:@"%@", [MSDKDnsInfoTool getIPsStringFromIPsArray:ipsArray]];
                        }
                        
                    }
                }
                NSDictionary * httpDnsCache_A = cacheInfo[kMSDKHttpDnsCache_A];
                if (httpDnsCache_A) {
                    NSArray * ipsArray = httpDnsCache_A[kIP];
                    if (ipsArray && [ipsArray isKindOfClass:[NSArray class]] && ipsArray.count > 0) {
                        if ([httpDnsIP_A length] > 0) {
                            httpDnsIP_A = [NSString stringWithFormat:@"%@,%@", httpDnsIP_A, [MSDKDnsInfoTool getIPsStringFromIPsArray:ipsArray]];
                        } else {
                            httpDnsIP_A = [NSString stringWithFormat:@"%@", [MSDKDnsInfoTool getIPsStringFromIPsArray:ipsArray]];
                        }
                    }
                }
                NSDictionary * httpDnsCache_4A = cacheInfo[kMSDKHttpDnsCache_4A];
                if (httpDnsCache_4A) {
                    NSArray * ipsArray = httpDnsCache_4A[kIP];
                    if (ipsArray && [ipsArray isKindOfClass:[NSArray class]] && ipsArray.count > 0) {
                        if ([httpDnsIP_4A length] > 0) {
                            httpDnsIP_4A = [NSString stringWithFormat:@"%@,%@", httpDnsIP_4A, [MSDKDnsInfoTool getIPsStringFromIPsArray:ipsArray]];
                        } else {
                            httpDnsIP_4A = [NSString stringWithFormat:@"%@", [MSDKDnsInfoTool getIPsStringFromIPsArray:ipsArray]];
                        }
                    }
                }
            }
        }
    }
    return @{
        kMSDKDns_A_IP:httpDnsIP_A,
        kMSDKDns_4A_IP:httpDnsIP_4A,
        kMSDKDnsLDNS_IP: localDnsIPs
    };
}

- (void)aysncUpdateIPRankingWithResult:(NSArray *)IPStrings forHost:(NSString *)host {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
        [self syncUpdateIPRankingWithResult:IPStrings forHost:host];
    });
}

- (void)syncUpdateIPRankingWithResult:(NSArray *)IPStrings forHost:(NSString *)host {
    NSArray *sortedIps = [[MSDKDnsTCPSpeedTester new] ipRankingWithIPs:IPStrings host:host];
    [self updateHostManagerDictWithIPs:sortedIps host:host];
}

- (void)updateHostManagerDictWithIPs:(NSArray *)ips host:(NSString *)host {
    if(!ips){
        return;
    }
    dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
        NSDictionary * tempDict = [[[MSDKDnsManager shareInstance] domainDict] objectForKey:host];
        NSMutableDictionary *cacheDict;
        
        if (tempDict) {
            cacheDict = [NSMutableDictionary dictionaryWithDictionary:tempDict];
            
            if (self.httpDnsResolver_A && self.httpDnsResolver_A.domainInfo) {
                
                NSDictionary *cacheValue = [self.httpDnsResolver_A.domainInfo objectForKey:host];
                if (cacheValue) {
                    NSMutableDictionary *newCacheValue = [NSMutableDictionary dictionaryWithDictionary:cacheValue];
                    [newCacheValue setValue:ips forKey:kIP];
                    [cacheDict setObject:newCacheValue forKey:kMSDKHttpDnsCache_A];
                }
                
            } else if (self.httpDnsResolver_BOTH && self.httpDnsResolver_BOTH.domainInfo) {
                NSDictionary *cacheValue = [self.httpDnsResolver_BOTH.domainInfo objectForKey:host];
                if (cacheValue) {
                    NSDictionary *ipv4CacheValue = [cacheValue objectForKey:@"ipv4"];
                    if (ipv4CacheValue) {
                        NSMutableDictionary *newCacheValue = [NSMutableDictionary dictionaryWithDictionary:ipv4CacheValue];
                        [newCacheValue setValue:ips forKey:kIP];
                        [cacheDict setObject:newCacheValue forKey:kMSDKHttpDnsCache_A];
                    }
                }
            }
            
            if (cacheDict && host) {
                [[MSDKDnsManager shareInstance] cacheDomainInfo:cacheDict domain:host];
            }
        }
    });
}

- (void)resolver:(MSDKDnsResolver *)resolver getDomainError:(NSString *)error retry:(BOOL)retry {
    MSDKDNSLOG(@"%@ %@ error = %@",self.toCheckDomains, [resolver class], error);
    if (retry) {
        [self retryHttpDns:resolver];
    } else {
        dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
            NSDictionary * info = @{
                kDnsErrCode:MSDKDns_Fail,
                kDnsErrMsg:error ? error : @"",
                kDnsRetry:@(self.httpdnsFailCount)
            };
            [self callBack:resolver Info:info];
        });
    }
    
}

- (void)dnsTimeoutAttaUpload:(NSString *)eventName {
    if ([[MSDKDnsParamsManager shareInstance] msdkDnsGetEnableReport]) {
        NSString* routeip = [[MSDKDnsParamsManager shareInstance] msdkDnsGetRouteIp];
        NSNumber *status = @0;
        NSString *timeConsuming = @"";
        NSString *serviceIp = @"";
        NSString *expiredTime = @"";
        
        if (!routeip) {
            routeip = @"";
        }
        NSString *req_type = @"a";
        HttpsDnsResolver *httpResolver = self.httpDnsResolver_A;
        if (self.httpDnsResolver_4A) {
            req_type = @"aaaa";
            httpResolver = self.httpDnsResolver_4A;
        }else if (self.httpDnsResolver_BOTH) {
            req_type = @"addrs";
            httpResolver = self.httpDnsResolver_BOTH;
        }
        if (httpResolver && httpResolver.statusCode) {
            status = @(httpResolver.statusCode);
        }
        if (httpResolver && httpResolver.serviceIp) {
            serviceIp = httpResolver.serviceIp;
        }
        if (httpResolver && httpResolver.expiredTime) {
            expiredTime = httpResolver.expiredTime;
        }
        
        
        NSDictionary * dnsIPs = [self getDomainsDNSFromCache:self.toCheckDomains];
        NSString *localDnsIPs = [dnsIPs valueForKey:kMSDKDnsLDNS_IP];
        NSString *httpDnsIP_A = [dnsIPs valueForKey:kMSDKDns_A_IP];
        NSString *httpDnsIP_4A = [dnsIPs valueForKey:kMSDKDns_4A_IP];
        NSString *httpdnsIPs = @"";
        
        if ([httpDnsIP_A length] > 0 && [httpDnsIP_4A length] > 0) {
            httpdnsIPs = [NSString stringWithFormat:@"%@,%@", httpDnsIP_A, httpDnsIP_4A];
        } else if ([httpDnsIP_A length] > 0) {
            httpdnsIPs = [NSString stringWithFormat:@"%@", httpDnsIP_A];
        } else if ([httpDnsIP_4A length] > 0) {
            httpdnsIPs = [NSString stringWithFormat:@"%@", httpDnsIP_4A];
        }
        
        if (self.startTime && [timeConsuming isEqualToString:@""]){
            // 优先使用缓存中的耗时，如果没有则使用实时计算的耗时，因为上报的时间点不一定是api方法结束的时间点。会等待LocalDNS返回才会去上报
            NSDate *currentTime = [NSDate date];
            NSLog(@"====timeConsuming= %@=====", timeConsuming);
            NSTimeInterval timeInterval = [currentTime timeIntervalSinceDate:self.startTime] * 1000;
            timeConsuming = [NSString stringWithFormat: @"%d", (int)timeInterval];
            NSLog(@"====timeConsuming= %@=====", timeConsuming);
        }
        
        [[AttaReport sharedInstance] reportEvent:@{
            MSDKDns_ErrorCode: MSDKDns_Timeout,
            @"eventName": eventName,
            @"dnsIp": serviceIp,
            @"req_dn": [self.toCheckDomains componentsJoinedByString:@","],
            @"req_type": req_type,
            @"req_timeout": @(self.timeOut * 1000),
            @"exp": expiredTime,
            @"req_ttl": @1,
            @"req_query": @1,
            @"req_ip": routeip,
            @"spend": timeConsuming,
            @"statusCode": status,
            @"count": @1,
            @"isCache": @0,
            @"ldns": localDnsIPs,
            @"hdns": httpdnsIPs,
        }];
    }
}

#pragma mark - retry
- (void) retryHttpDns:(MSDKDnsResolver *)resolver {
    self.httpdnsFailCount += 1;
    self.isRetryRequest = @YES;
    NSLog(@"======%@======", self.origin);
    [self changeRetryEventName:self.origin];
    if (self.httpdnsFailCount < [[MSDKDnsParamsManager shareInstance] msdkDnsGetRetryTimesBeforeSwitchServer]) {
        if (resolver == self.httpDnsResolver_A) {
            dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
                [self startHttpDns:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey encryptType:self.encryptType];
            });
        } else if (resolver == self.httpDnsResolver_4A) {
            dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
                [self startHttpDns_4A:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey encryptType:self.encryptType];
            });
        } else if (resolver == self.httpDnsResolver_BOTH) {
            dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
                [self startHttpDnsBoth:self.timeOut dnsId:self.dnsId dnsKey:self.dnsKey encryptType:self.encryptType];
            });
        }
    } else {
        MSDKDNSLOG(@"fail %lu times, switch server!", (unsigned long)[[MSDKDnsParamsManager shareInstance] msdkDnsGetRetryTimesBeforeSwitchServer]);
        // 失败超过三次，返回错误结果并切换备份ip
        dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
            NSDictionary * info = @{
                kDnsErrCode:MSDKDns_UnResolve,
                kDnsErrMsg:[NSString stringWithFormat:@"request fail %lu times", (unsigned long)[[MSDKDnsParamsManager shareInstance] msdkDnsGetRetryTimesBeforeSwitchServer]],
                kDnsRetry:@(self.httpdnsFailCount)
            };
            [self callBack:resolver Info:info];
        });
        // 重试解析失败情况上报
        [self dnsTimeoutAttaUpload:MSDKDnsEventHttpDnsNormalRetry];
        [[MSDKDnsManager shareInstance] switchDnsServer];
    }
}

- (void) changeRetryEventName:(NSString *)eventName {
    if ([eventName isEqualToString:MSDKDnsEventHttpDnsNormal]) {
        self.origin = MSDKDnsEventHttpDnsNormalRetry;
    } else if ([eventName isEqualToString:MSDKDnsEventHttpDnsPreResolved]) {
        self.origin = MSDKDnsEventHttpDnsPreResolvedRetry;
    } else if ([eventName isEqualToString:MSDKDnsEventHttpDnsAutoRefresh]) {
        self.origin = MSDKDnsEventHttpDnsAutoRefreshRetry;
    } else if ([eventName isEqualToString:MSDKDnsEventHttpDnsExpiredAsync]) {
        self.origin = MSDKDnsEventHttpDnsExpiredAsyncRetry;
    }
}

#pragma mark - CallBack

- (void)callBack:(MSDKDnsResolver *)resolver Info:(NSDictionary *)info {
    if (self.isRetryRequest) {
        if (self.httpDnsResolver_A && [self.httpDnsResolver_A.errorCode isEqualToString:MSDKDns_Success]) {
            [self reportDataTransform];
        } else if (self.httpDnsResolver_4A && [self.httpDnsResolver_4A.errorCode isEqualToString:MSDKDns_Success]) {
            [self reportDataTransform];
        } else if (self.httpDnsResolver_BOTH && [self.httpDnsResolver_BOTH.errorCode isEqualToString:MSDKDns_Success]) {
            [self reportDataTransform];
        }
    }
    if (self.isCallBack) {
        return;
    }
    // 解析请求返回状态缓存
    for(int i = 0; i < [self.toCheckDomains count]; i++) {
        NSString *domain = [self.toCheckDomains objectAtIndex:i];
        NSDictionary * tempDict = [[[MSDKDnsManager shareInstance] domainDict] objectForKey:domain];
        NSMutableDictionary *cacheDict = [[NSMutableDictionary alloc] init];
        if (tempDict) {
            cacheDict = [NSMutableDictionary dictionaryWithDictionary:tempDict];
        }
        if (resolver) {
            if (resolver == self.httpDnsResolver_A) {
                [cacheDict setObject:info forKey:kMSDKHttpDnsInfo_A];
            } else if (resolver == self.httpDnsResolver_4A) {
                [cacheDict setObject:info forKey:kMSDKHttpDnsInfo_4A];
            } else if (resolver == self.httpDnsResolver_BOTH) {
                [cacheDict setObject:info forKey:kMSDKHttpDnsInfo_BOTH];
            }
        }
        if (cacheDict && domain) {
            [[MSDKDnsManager shareInstance] cacheDomainInfo:cacheDict domain:domain];
        }
    }
    MSDKDNSLOG(@"callBack! :%@", self.toCheckDomains);
    [self excuteCallNotify];
    [self excuteReport];
}

- (void)excuteCallNotify {
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    BOOL expiredIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetExpiredIPEnabled];
    if (self.httpDnsResolver_A && (httpOnly || expiredIPEnabled || [self.httpDnsResolver_A.errorCode isEqualToString:MSDKDns_Success] || self.localDnsResolver.isFinished)) {
        if (self.httpDnsResolver_A.isFinished) {
            [self callNotify];
        }
    } else if (self.httpDnsResolver_4A && (httpOnly || expiredIPEnabled || [self.httpDnsResolver_4A.errorCode isEqualToString:MSDKDns_Success] || self.localDnsResolver.isFinished)) {
        if (self.httpDnsResolver_4A.isFinished) {
            [self callNotify];
        }
    } else if (self.httpDnsResolver_BOTH && (httpOnly || expiredIPEnabled || [self.httpDnsResolver_BOTH.errorCode isEqualToString:MSDKDns_Success] || self.localDnsResolver.isFinished)) {
        if (self.httpDnsResolver_BOTH.isFinished) {
            [self callNotify];
        }
    }
}

- (void)excuteReport {
    //LocalHttp 和 HttpDns均完成，则返回结果，如果开启了httpOnly或者使用过期缓存IP则只等待HttpDns完成就立即返回
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    BOOL expiredIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetExpiredIPEnabled];
    if (httpOnly || expiredIPEnabled || self.localDnsResolver.isFinished) {
        if (self.httpDnsResolver_A && self.httpDnsResolver_A.isFinished) {
            [self reportDataTransform];
        } else if (self.httpDnsResolver_4A && self.httpDnsResolver_4A.isFinished) {
            [self reportDataTransform];
        } else if (self.httpDnsResolver_BOTH && self.httpDnsResolver_BOTH.isFinished) {
            [self reportDataTransform];
        }
    }
}

- (void)reportDataTransform {
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    NSDictionary *tempDict = [[MSDKDnsManager shareInstance] domainDict];
    
    // 当开启上报服务时
    if ([[MSDKDnsParamsManager shareInstance] msdkDnsGetEnableReport]) {
        NSString *routeip = [[MSDKDnsParamsManager shareInstance] msdkDnsGetRouteIp] ?: @"";
        NSDictionary *reportParams = [self getReportParamsWithRouteIP:routeip andTempDict:tempDict andHttpOnly:httpOnly];
        [[AttaReport sharedInstance] reportEvent:reportParams];
    }
}

- (NSDictionary *)getReportParamsWithRouteIP:(NSString *)routeip andTempDict:(NSDictionary *)tempDict andHttpOnly:(BOOL)httpOnly {
    NSString *req_type = @"a";
    NSString *serviceIp = @"";
    NSNumber *status = @0;
    NSDictionary *dnsIPs = [self getDomainsDNSFromCache:self.toCheckDomains];
    NSString *localDnsIPs = [dnsIPs valueForKey:kMSDKDnsLDNS_IP];
    NSString *httpDnsIP_A = [dnsIPs valueForKey:kMSDKDns_A_IP];
    NSString *httpDnsIP_4A = [dnsIPs valueForKey:kMSDKDns_4A_IP];
    NSString *httpdnsIPs = [self getHttpDnsIPsWithA:httpDnsIP_A and4A:httpDnsIP_4A];
    NSNumber *localDNSSpend = [NSNumber numberWithInt:-1];
    NSString *timeConsuming = @"";
    NSString *errorCode = MSDKDns_Success;
    NSString *expiredTime = @"";

    for (int i = 0; i < [self.toCheckDomains count]; i++) {
        NSString *domain = [self.toCheckDomains objectAtIndex:i];
        NSDictionary *domainDic = [tempDict objectForKey:domain];
        if (domainDic) {
            timeConsuming = [self getTimeConsumingFromDomainDic:domainDic];
            if (!httpOnly) {
                localDNSSpend = [self getLocalDnsSpendFromDomainDic:domainDic andLocalDNSSpend:localDNSSpend];
            } else if (![timeConsuming isEqualToString:@""]) {
                break;
            }
        }
    }
    
    if (self.startTime && [timeConsuming isEqualToString:@""]){
        // 优先使用缓存中的耗时，如果没有则使用实时计算的耗时，因为上报的时间点不一定是api方法结束的时间点。会等待LocalDNS返回才会去上报
        NSDate *currentTime = [NSDate date];
        NSLog(@"====timeConsuming= %@=====", timeConsuming);
        NSTimeInterval timeInterval = [currentTime timeIntervalSinceDate:self.startTime] * 1000;
        timeConsuming = [NSString stringWithFormat: @"%d", (int)timeInterval];
        NSLog(@"====timeConsuming= %@=====", timeConsuming);
    }
  
    if (self.httpDnsResolver_A) {
        status = @(self.httpDnsResolver_A.statusCode);
        errorCode = self.httpDnsResolver_A.errorCode;
        serviceIp = self.httpDnsResolver_A.serviceIp;
        expiredTime = self.httpDnsResolver_A.expiredTime;
    } else if (self.httpDnsResolver_4A) {
        req_type = @"aaaa";
        status = @(self.httpDnsResolver_4A.statusCode);
        errorCode = self.httpDnsResolver_4A.errorCode;
        serviceIp = self.httpDnsResolver_4A.serviceIp;
        expiredTime = self.httpDnsResolver_4A.expiredTime;
    } else if (self.httpDnsResolver_BOTH) {
        req_type = @"addrs";
        status = @(self.httpDnsResolver_BOTH.statusCode);
        errorCode = self.httpDnsResolver_BOTH.errorCode;
        serviceIp = self.httpDnsResolver_BOTH.serviceIp;
        expiredTime = self.httpDnsResolver_BOTH.expiredTime;
    }

    return @{
        MSDKDns_ErrorCode: errorCode ? errorCode : MSDKDns_Success,
        @"eventName": self.origin,
        @"dnsIp": serviceIp,
        @"req_dn": [self.toCheckDomains componentsJoinedByString:@","],
        @"req_type": req_type,
        @"req_timeout": @(self.timeOut * 1000),
        @"exp": expiredTime,
        @"req_ttl": @1,
        @"req_query": @1,
        @"req_ip": routeip,
        @"spend": timeConsuming,
        @"ldns_spend": localDNSSpend,
        @"statusCode": status,
        @"count": @1,
        @"isCache": @0,
        @"ldns": localDnsIPs,
        @"hdns": httpdnsIPs,
    };
}

- (NSString *)getHttpDnsIPsWithA:(NSString *)httpDnsIP_A and4A:(NSString *)httpDnsIP_4A {
    NSString *httpdnsIPs = @"";
    if ([httpDnsIP_A length] > 0 && [httpDnsIP_4A length] > 0) {
        httpdnsIPs = [NSString stringWithFormat:@"%@,%@", httpDnsIP_A, httpDnsIP_4A];
    } else if ([httpDnsIP_A length] > 0) {
        httpdnsIPs = [NSString stringWithFormat:@"%@", httpDnsIP_A];
    } else if ([httpDnsIP_4A length] > 0) {
        httpdnsIPs = [NSString stringWithFormat:@"%@", httpDnsIP_4A];
    }
    return httpdnsIPs;
}

- (NSString *)getTimeConsumingFromDomainDic:(NSDictionary *)domainDic {
    NSString *timeConsuming = @"";
    NSDictionary *ipv4CacheValue = [domainDic objectForKey:kMSDKHttpDnsCache_A];
    NSDictionary *ipv6CacheValue = [domainDic objectForKey:kMSDKHttpDnsCache_4A];
    
    if (ipv4CacheValue && [ipv4CacheValue objectForKey:kDnsTimeConsuming]) {
        timeConsuming = [ipv4CacheValue objectForKey:kDnsTimeConsuming];
    }
    if (ipv6CacheValue && [ipv6CacheValue objectForKey:kDnsTimeConsuming]) {
        timeConsuming = [ipv6CacheValue objectForKey:kDnsTimeConsuming];
    }
    
    return timeConsuming;
}

- (NSNumber *)getLocalDnsSpendFromDomainDic:(NSDictionary *)domainDic andLocalDNSSpend:(NSNumber *)localDNSSpend {
    NSDictionary *localDNSData = [domainDic objectForKey:kMSDKLocalDnsCache];
    if (localDNSData) {
        int spend = [[localDNSData objectForKey:kDnsTimeConsuming] intValue];
        if (spend > 0 && [localDNSSpend intValue] < spend) {
            localDNSSpend = @(spend);
        }
    }
    return localDNSSpend;
}

- (void)callNotify {
    MSDKDNSLOG(@"callNotify! :%@", self.toCheckDomains);
    self.isCallBack = YES;
    if (self.completionHandler) {
        self.completionHandler();
        self.completionHandler = nil;
    }
}

#pragma mark - cacheDomainInfo

// 解析结果存缓存
- (void)cacheDomainInfo:(MSDKDnsResolver *)resolver {
    MSDKDNSLOG(@"cacheDomainInfo: %@", self.toCheckDomains);
    for(int i = 0; i < [self.toCheckDomains count]; i++) {
        NSString *domain = [self.toCheckDomains objectAtIndex:i];
        NSDictionary * tempDict = [[[MSDKDnsManager shareInstance] domainDict] objectForKey:domain];
        NSMutableDictionary *cacheDict = [[NSMutableDictionary alloc] init];
        if (tempDict) {
            cacheDict = [NSMutableDictionary dictionaryWithDictionary:tempDict];
        }
        if (resolver) {
            if ((resolver == self.httpDnsResolver_A) && self.httpDnsResolver_A.domainInfo) {
                NSDictionary *cacheValue = [self.httpDnsResolver_A.domainInfo objectForKey:domain];
                if (cacheValue) {
                    [cacheDict setObject:cacheValue forKey:kMSDKHttpDnsCache_A];
                    [cacheDict removeObjectForKey:kMSDKHttpDnsCache_4A];
                }
            } else if ((resolver == self.httpDnsResolver_4A) && self.httpDnsResolver_4A.domainInfo) {
                NSDictionary *cacheValue = [self.httpDnsResolver_4A.domainInfo objectForKey:domain];
                if (cacheValue) {
                    [cacheDict setObject:cacheValue forKey:kMSDKHttpDnsCache_4A];
                    [cacheDict removeObjectForKey:kMSDKHttpDnsCache_A];
                }
            } else if ((resolver == self.localDnsResolver) && self.localDnsResolver.domainInfo) {
                NSDictionary *cacheValue = [self.localDnsResolver.domainInfo objectForKey:domain];
                if (cacheValue) {
                    [cacheDict setObject:cacheValue forKey:kMSDKLocalDnsCache];
                }
            } else if ((resolver == self.httpDnsResolver_BOTH) && self.httpDnsResolver_BOTH.domainInfo) {
                NSDictionary *cacheValue = [self.httpDnsResolver_BOTH.domainInfo objectForKey:domain];
                if (cacheValue) {
                    NSDictionary *ipv4CacheValue = [cacheValue objectForKey:@"ipv4"];
                    NSDictionary *ipv6CacheValue = [cacheValue objectForKey:@"ipv6"];
                    if (ipv4CacheValue) {
                        [cacheDict setObject:ipv4CacheValue forKey:kMSDKHttpDnsCache_A];
                    }
                    if (ipv6CacheValue) {
                        [cacheDict setObject:ipv6CacheValue forKey:kMSDKHttpDnsCache_4A];
                    }
                }
            }
        }
        [self updateCacheAndPersistIfNeeded:cacheDict withDomain:domain andResolver:resolver];
    }
}

- (void)updateCacheAndPersistIfNeeded:(NSMutableDictionary *)cacheDict withDomain:(NSString *)domain andResolver:(MSDKDnsResolver *)resolver {
    if (cacheDict && domain) {
        [[MSDKDnsManager shareInstance] cacheDomainInfo:cacheDict domain:domain];
        BOOL persistCacheIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetPersistCacheIPEnabled];
        BOOL isHttpAndOpenPersist = resolver && resolver != self.localDnsResolver && persistCacheIPEnabled;
        if (isHttpAndOpenPersist){
            [[MSDKDnsDB shareInstance] insertOrReplaceDomainInfo:cacheDict domain:domain];
        }
    }
}

@end
