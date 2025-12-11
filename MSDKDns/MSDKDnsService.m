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

@property (atomic, strong) NSArray * toCheckDomains;
@property (atomic, strong) HttpsDnsResolver * httpDnsResolver_A;
@property (atomic, strong) HttpsDnsResolver * httpDnsResolver_4A;
@property (atomic, strong) HttpsDnsResolver * httpDnsResolver_BOTH;
@property (atomic, strong) LocalDnsResolver * localDnsResolver;
@property (atomic, copy) void (^ completionHandler)();
@property (atomic, assign) BOOL isCallBack;
@property (atomic, assign) msdkdns::MSDKDNS_TLocalIPStack netStack;
@property (atomic, assign) int httpdnsFailCount;
@property (atomic, assign) float timeOut;
@property (atomic, assign) int dnsId;
@property (atomic, strong) NSString* dnsServer;
@property (atomic, strong) NSString* dnsRouter;
@property (atomic, strong) NSString* dnsKey;
@property (atomic, strong) NSString* origin;
@property (atomic, strong) NSString* dnsToken;
@property (atomic, strong) NSDate * startTime;
@property (atomic, assign) NSUInteger encryptType;
@property (atomic, assign) BOOL httpOnly;
@property (atomic, assign) BOOL enableReport;
@property (atomic, assign) BOOL isRetryRequest;
@property (atomic, assign) NSUInteger retryCount;
@end

@implementation MSDKDnsService

- (void)dealloc {
    // 清理所有 resolver 的 delegate，防止悬空指针回调
    if (_httpDnsResolver_A) {
        _httpDnsResolver_A.delegate = nil;
    }
    if (_httpDnsResolver_4A) {
        _httpDnsResolver_4A.delegate = nil;
    }
    if (_httpDnsResolver_BOTH) {
        _httpDnsResolver_BOTH.delegate = nil;
    }
    if (_localDnsResolver) {
        _localDnsResolver.delegate = nil;
    }
    
    // 清理属性
    [self setToCheckDomains:nil];
    [self setHttpDnsResolver_A:nil];
    [self setHttpDnsResolver_4A:nil];
    [self setHttpDnsResolver_BOTH:nil];
    [self setLocalDnsResolver:nil];
    [self setCompletionHandler:nil];
    
    MSDKDNSLOG(@"MSDKDnsService dealloc");
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
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startHttpDns_4A:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_IPv4) {
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startHttpDns:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_Dual) {
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startHttpDnsBoth:timeOut dnsId:dnsId dnsKey:dnsKey encryptType:encryptType];
        });
    }
    
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    // 设置httpOnly为YES，或者开启了expiredIPEnabled过期IP的情况下，就不下发LocalDns请求
    if (!httpOnly && !expiredIPEnabled) {
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startLocalDns:timeOut dnsId:dnsId dnsKey:dnsKey];
        });
    }
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, timeOut * NSEC_PER_SEC), [MSDKDnsInfoTool msdkdns_queue], ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            MSDKDNSLOG(@"MSDKDnsService has been deallocated in timeout callback");
            return;
        }
        if(!strongSelf.isCallBack) {
            MSDKDNSLOG(@"DnsService timeOut!");
            [strongSelf dnsTimeoutAttaUpload:strongSelf.origin];
            [strongSelf callNotify];
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
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startHttpDns_4A:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey encryptType:strongSelf.encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_IPv4) {
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startHttpDns:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey encryptType:strongSelf.encryptType];
        });
    }
    
    if (_netStack == msdkdns::MSDKDNS_ELocalIPStack_Dual) {
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startHttpDnsBoth:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey encryptType:strongSelf.encryptType];
        });
    }
    
    if (!self.httpOnly) {
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            [strongSelf startLocalDns:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey];
        });
    }
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, self.timeOut * NSEC_PER_SEC), [MSDKDnsInfoTool msdkdns_queue], ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            MSDKDNSLOG(@"MSDKDnsService has been deallocated in timeout callback");
            return;
        }
        if(!strongSelf.isCallBack) {
            MSDKDNSLOG(@"DnsService timeOut!");
            [strongSelf dnsTimeoutAttaUpload:strongSelf.origin];
            [strongSelf callNotify];
        }
    });
}

//进行httpdns ipv4和ipv6合并请求
- (void)startHttpDnsBoth:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@ StartHttpDns!", self.toCheckDomains);
    // 先清理旧resolver的delegate，防止悬空指针回调
    if (self.httpDnsResolver_BOTH) {
        self.httpDnsResolver_BOTH.delegate = nil;
    }
    self.httpDnsResolver_BOTH = [[HttpsDnsResolver alloc] init];
    self.httpDnsResolver_BOTH.delegate = self;
    [self.httpDnsResolver_BOTH startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:msdkdns::MSDKDNS_ELocalIPStack_Dual encryptType:encryptType];
}

//进行httpdns ipv4请求
- (void)startHttpDns:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@ StartHttpDns!", self.toCheckDomains);
    // 先清理旧resolver的delegate，防止悬空指针回调
    if (self.httpDnsResolver_A) {
        self.httpDnsResolver_A.delegate = nil;
    }
    self.httpDnsResolver_A = [[HttpsDnsResolver alloc] init];
    self.httpDnsResolver_A.delegate = self;
    [self.httpDnsResolver_A startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4 encryptType:encryptType];
}

//进行httpdns ipv6请求
- (void)startHttpDns_4A:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey encryptType:(NSInteger)encryptType
{
    MSDKDNSLOG(@"%@ StartHttpDns!", self.toCheckDomains);
    // 先清理旧resolver的delegate，防止悬空指针回调
    if (self.httpDnsResolver_4A) {
        self.httpDnsResolver_4A.delegate = nil;
    }
    self.httpDnsResolver_4A = [[HttpsDnsResolver alloc] init];
    self.httpDnsResolver_4A.delegate = self;
    [self.httpDnsResolver_4A startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv6 encryptType:encryptType];
}

//进行localdns请求
- (void)startLocalDns:(float)timeOut dnsId:(int)dnsId dnsKey:(NSString *)dnsKey {
    MSDKDNSLOG(@"%@ startLocalDns!", self.toCheckDomains);
    // 先清理旧resolver的delegate，防止悬空指针回调
    if (self.localDnsResolver) {
        self.localDnsResolver.delegate = nil;
    }
    self.localDnsResolver = [[LocalDnsResolver alloc] init];
    self.localDnsResolver.delegate = self;
    [self.localDnsResolver startWithDomains:self.toCheckDomains timeOut:timeOut dnsId:dnsId dnsKey:dnsKey netStack:_netStack];
}

#pragma mark - MSDKDnsResolverDelegate

- (void)resolver:(MSDKDnsResolver *)resolver didGetDomainInfo:(NSDictionary *)domainInfo {
    MSDKDNSLOG(@"%@ %@ domainInfo = %@", self.toCheckDomains, [resolver class], domainInfo);
    // 结果存缓存
    // 使用 weak-strong dance 防止 block 中 self 被提前释放导致的野指针访问
    __weak typeof(self) weakSelf = self;
    dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            MSDKDNSLOG(@"MSDKDnsService has been deallocated, skip callback");
            return;
        }
        [strongSelf cacheDomainInfo:resolver];
        NSDictionary * info = @{
            kDnsErrCode:MSDKDns_Success,
            kDnsErrMsg:@"",
            kDnsRetry: @(strongSelf.httpdnsFailCount)
        };
        [strongSelf callBack:resolver Info:info];
        if (resolver == strongSelf.httpDnsResolver_A || resolver == strongSelf.httpDnsResolver_4A || resolver == strongSelf.httpDnsResolver_BOTH) {
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
                    if(resolver == strongSelf.httpDnsResolver_BOTH){
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
                        __weak typeof(strongSelf) weakSelf2 = strongSelf;
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, afterTime.floatValue * NSEC_PER_SEC), [MSDKDnsInfoTool msdkdns_queue], ^{
                            __strong typeof(weakSelf2) strongSelf2 = weakSelf2;
                            if (!strongSelf2) {
                                MSDKDNSLOG(@"MSDKDnsService has been deallocated in delayed cache update");
                                return;
                            }
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
        [strongSelf excuteIPRank:resolver didGetDomainInfo:domainInfo];
    });
}

- (void)excuteIPRank:(MSDKDnsResolver *)resolver didGetDomainInfo:(NSDictionary *)domainInfo {
    // 缓存 resolver 引用，防止竞态条件
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    
    if (resolver == resolverA || resolver == resolverBoth) {
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
                    if(resolver == resolverBoth){
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
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        [strongSelf syncUpdateIPRankingWithResult:IPStrings forHost:host];
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
    __weak typeof(self) weakSelf = self;
    dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) return;
        
        NSDictionary * tempDict = [[[MSDKDnsManager shareInstance] domainDict] objectForKey:host];
        NSMutableDictionary *cacheDict;
        
        if (tempDict) {
            cacheDict = [NSMutableDictionary dictionaryWithDictionary:tempDict];
            
            if (strongSelf.httpDnsResolver_A && strongSelf.httpDnsResolver_A.domainInfo) {
                
                NSDictionary *cacheValue = [strongSelf.httpDnsResolver_A.domainInfo objectForKey:host];
                if (cacheValue) {
                    NSMutableDictionary *newCacheValue = [NSMutableDictionary dictionaryWithDictionary:cacheValue];
                    [newCacheValue setValue:ips forKey:kIP];
                    [cacheDict setObject:newCacheValue forKey:kMSDKHttpDnsCache_A];
                }
                
            } else if (strongSelf.httpDnsResolver_BOTH && strongSelf.httpDnsResolver_BOTH.domainInfo) {
                NSDictionary *cacheValue = [strongSelf.httpDnsResolver_BOTH.domainInfo objectForKey:host];
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
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            NSDictionary * info = @{
                kDnsErrCode:MSDKDns_Fail,
                kDnsErrMsg:error ? error : @"",
                kDnsRetry:@(strongSelf.httpdnsFailCount)
            };
            [strongSelf callBack:resolver Info:info];
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
        
        // 缓存属性到局部变量，防止多线程竞态条件
        NSArray *domains = self.toCheckDomains;
        NSDate *startTime = self.startTime;
        HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
        HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
        HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
        
        if (!routeip) {
            routeip = @"";
        }
        NSString *req_type = @"a";
        HttpsDnsResolver *httpResolver = resolverA;
        if (resolver4A) {
            req_type = @"aaaa";
            httpResolver = resolver4A;
        }else if (resolverBoth) {
            req_type = @"addrs";
            httpResolver = resolverBoth;
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
        
        
        NSDictionary * dnsIPs = [self getDomainsDNSFromCache:domains];
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
        
        if (startTime && [timeConsuming isEqualToString:@""]){
            // 优先使用缓存中的耗时，如果没有则使用实时计算的耗时，因为上报的时间点不一定是api方法结束的时间点。会等待LocalDNS返回才会去上报
            NSDate *currentTime = [NSDate date];
            // NSLog(@"====timeConsuming= %@=====", timeConsuming);
            NSTimeInterval timeInterval = [currentTime timeIntervalSinceDate:startTime] * 1000;
            timeConsuming = [NSString stringWithFormat: @"%d", (int)timeInterval];
            // NSLog(@"====timeConsuming= %@=====", timeConsuming);
        }
        
        [[AttaReport sharedInstance] reportEvent:@{
            MSDKDns_ErrorCode: MSDKDns_Timeout,
            @"eventName": eventName,
            @"dnsIp": serviceIp,
            @"req_dn": [domains componentsJoinedByString:@","],
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
    // NSLog(@"======%@======", self.origin);
    [self changeRetryEventName:self.origin];
    
    // 缓存 resolver 引用，防止在判断时被其他线程修改
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    
    if (self.httpdnsFailCount < [[MSDKDnsParamsManager shareInstance] msdkDnsGetRetryTimesBeforeSwitchServer]) {
        __weak typeof(self) weakSelf = self;
        if (resolver == resolverA) {
            dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
                __strong typeof(weakSelf) strongSelf = weakSelf;
                if (!strongSelf) return;
                [strongSelf startHttpDns:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey encryptType:strongSelf.encryptType];
            });
        } else if (resolver == resolver4A) {
            dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
                __strong typeof(weakSelf) strongSelf = weakSelf;
                if (!strongSelf) return;
                [strongSelf startHttpDns_4A:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey encryptType:strongSelf.encryptType];
            });
        } else if (resolver == resolverBoth) {
            dispatch_async([MSDKDnsInfoTool msdkdns_resolver_queue], ^{
                __strong typeof(weakSelf) strongSelf = weakSelf;
                if (!strongSelf) return;
                [strongSelf startHttpDnsBoth:strongSelf.timeOut dnsId:strongSelf.dnsId dnsKey:strongSelf.dnsKey encryptType:strongSelf.encryptType];
            });
        }
    } else {
        MSDKDNSLOG(@"fail %lu times, switch server!", (unsigned long)[[MSDKDnsParamsManager shareInstance] msdkDnsGetRetryTimesBeforeSwitchServer]);
        // 失败超过三次，返回错误结果并切换备份ip
        __weak typeof(self) weakSelf = self;
        dispatch_async([MSDKDnsInfoTool msdkdns_queue], ^{
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            NSDictionary * info = @{
                kDnsErrCode:MSDKDns_UnResolve,
                kDnsErrMsg:[NSString stringWithFormat:@"request fail %lu times", (unsigned long)[[MSDKDnsParamsManager shareInstance] msdkDnsGetRetryTimesBeforeSwitchServer]],
                kDnsRetry:@(strongSelf.httpdnsFailCount)
            };
            [strongSelf callBack:resolver Info:info];
        });
        // 重试解析失败情况上报
        [self dnsTimeoutAttaUpload:self.origin];
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
    // 使用局部变量缓存 resolver 引用，防止竞态条件
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    
    if (self.isRetryRequest) {
        if (resolverA && [resolverA.errorCode isEqualToString:MSDKDns_Success]) {
            [self reportDataTransform];
        } else if (resolver4A && [resolver4A.errorCode isEqualToString:MSDKDns_Success]) {
            [self reportDataTransform];
        } else if (resolverBoth && [resolverBoth.errorCode isEqualToString:MSDKDns_Success]) {
            [self reportDataTransform];
        }
    }
    if (self.isCallBack) {
        return;
    }
    // 解析请求返回状态缓存
    NSArray *domains = self.toCheckDomains;
    for(int i = 0; i < [domains count]; i++) {
        NSString *domain = [domains objectAtIndex:i];
        NSDictionary * tempDict = [[[MSDKDnsManager shareInstance] domainDict] objectForKey:domain];
        NSMutableDictionary *cacheDict = [[NSMutableDictionary alloc] init];
        if (tempDict) {
            cacheDict = [NSMutableDictionary dictionaryWithDictionary:tempDict];
        }
        if (resolver) {
            if (resolver == resolverA) {
                [cacheDict setObject:info forKey:kMSDKHttpDnsInfo_A];
            } else if (resolver == resolver4A) {
                [cacheDict setObject:info forKey:kMSDKHttpDnsInfo_4A];
            } else if (resolver == resolverBoth) {
                [cacheDict setObject:info forKey:kMSDKHttpDnsInfo_BOTH];
            }
        }
        if (cacheDict && domain) {
            [[MSDKDnsManager shareInstance] cacheDomainInfo:cacheDict domain:domain];
        }
    }
    MSDKDNSLOG(@"callBack! :%@", domains);
    [self excuteCallNotify];
    [self excuteReport];
}

- (void)excuteCallNotify {
    // 使用局部变量缓存属性，防止多线程竞态条件导致的野指针访问
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    BOOL expiredIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetExpiredIPEnabled];
    
    // 先取出 resolver 引用，避免重复访问属性时被其他线程修改
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    LocalDnsResolver *localResolver = self.localDnsResolver;
    
    if (resolverA && (httpOnly || expiredIPEnabled || [resolverA.errorCode isEqualToString:MSDKDns_Success] || (localResolver && localResolver.isFinished))) {
        if (resolverA.isFinished) {
            [self callNotify];
        }
    } else if (resolver4A && (httpOnly || expiredIPEnabled || [resolver4A.errorCode isEqualToString:MSDKDns_Success] || (localResolver && localResolver.isFinished))) {
        if (resolver4A.isFinished) {
            [self callNotify];
        }
    } else if (resolverBoth && (httpOnly || expiredIPEnabled || [resolverBoth.errorCode isEqualToString:MSDKDns_Success] || (localResolver && localResolver.isFinished))) {
        if (resolverBoth.isFinished) {
            [self callNotify];
        }
    }
}

- (void)excuteReport {
    //LocalHttp 和 HttpDns均完成，则返回结果，如果开启了httpOnly或者使用过期缓存IP则只等待HttpDns完成就立即返回
    BOOL httpOnly = [[MSDKDnsParamsManager shareInstance] msdkDnsGetHttpOnly];
    BOOL expiredIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetExpiredIPEnabled];
    
    // 使用局部变量缓存 resolver 引用，防止竞态条件
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    LocalDnsResolver *localResolver = self.localDnsResolver;
    
    if (httpOnly || expiredIPEnabled || (localResolver && localResolver.isFinished)) {
        if (resolverA && resolverA.isFinished) {
            [self reportDataTransform];
        } else if (resolver4A && resolver4A.isFinished) {
            [self reportDataTransform];
        } else if (resolverBoth && resolverBoth.isFinished) {
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
    
    // 缓存属性到局部变量，防止多线程竞态条件
    NSArray *domains = self.toCheckDomains;
    NSDate *startTime = self.startTime;
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    
    NSDictionary *dnsIPs = [self getDomainsDNSFromCache:domains];
    NSString *localDnsIPs = [dnsIPs valueForKey:kMSDKDnsLDNS_IP];
    NSString *httpDnsIP_A = [dnsIPs valueForKey:kMSDKDns_A_IP];
    NSString *httpDnsIP_4A = [dnsIPs valueForKey:kMSDKDns_4A_IP];
    NSString *httpdnsIPs = [self getHttpDnsIPsWithA:httpDnsIP_A and4A:httpDnsIP_4A];
    NSNumber *localDNSSpend = [NSNumber numberWithInt:-1];
    NSString *timeConsuming = @"";
    NSString *errorCode = MSDKDns_Success;
    NSString *expiredTime = @"";

    for (int i = 0; i < [domains count]; i++) {
        NSString *domain = [domains objectAtIndex:i];
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
    
    if (startTime && [timeConsuming isEqualToString:@""]){
        // 优先使用缓存中的耗时，如果没有则使用实时计算的耗时，因为上报的时间点不一定是api方法结束的时间点。会等待LocalDNS返回才会去上报
        NSDate *currentTime = [NSDate date];
        // NSLog(@"====timeConsuming= %@=====", timeConsuming);
        NSTimeInterval timeInterval = [currentTime timeIntervalSinceDate:startTime] * 1000;
        timeConsuming = [NSString stringWithFormat: @"%d", (int)timeInterval];
        // NSLog(@"====timeConsuming= %@=====", timeConsuming);
    }
  
    if (resolverA) {
        status = @(resolverA.statusCode);
        errorCode = resolverA.errorCode;
        serviceIp = resolverA.serviceIp;
        expiredTime = resolverA.expiredTime;
    } else if (resolver4A) {
        req_type = @"aaaa";
        status = @(resolver4A.statusCode);
        errorCode = resolver4A.errorCode;
        serviceIp = resolver4A.serviceIp;
        expiredTime = resolver4A.expiredTime;
    } else if (resolverBoth) {
        req_type = @"addrs";
        status = @(resolverBoth.statusCode);
        errorCode = resolverBoth.errorCode;
        serviceIp = resolverBoth.serviceIp;
        expiredTime = resolverBoth.expiredTime;
    }

    return @{
        MSDKDns_ErrorCode: errorCode ? errorCode : MSDKDns_Success,
        @"eventName": self.origin,
        @"dnsIp": serviceIp,
        @"req_dn": [domains componentsJoinedByString:@","],
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
    
    void (^handler)() = nil;
    
    @synchronized (self) {
        // Double-check防止重复回调
        if (self.isCallBack) {
            return;
        }
        self.isCallBack = YES;
        
        // 在同步块内安全地取出并清空handler
        handler = self.completionHandler;
        self.completionHandler = nil;
    }
    
    // 在同步块外执行回调，避免死锁风险
    if (handler) {
        handler();
    }
}

#pragma mark - cacheDomainInfo

// 解析结果存缓存
- (void)cacheDomainInfo:(MSDKDnsResolver *)resolver {
    NSArray *domains = self.toCheckDomains;
    MSDKDNSLOG(@"cacheDomainInfo: %@", domains);
    
    // 缓存 resolver 引用，防止竞态条件
    HttpsDnsResolver *resolverA = self.httpDnsResolver_A;
    HttpsDnsResolver *resolver4A = self.httpDnsResolver_4A;
    HttpsDnsResolver *resolverBoth = self.httpDnsResolver_BOTH;
    LocalDnsResolver *localResolver = self.localDnsResolver;
    
    for(int i = 0; i < [domains count]; i++) {
        NSString *domain = [domains objectAtIndex:i];
        NSDictionary * tempDict = [[[MSDKDnsManager shareInstance] domainDict] objectForKey:domain];
        NSMutableDictionary *cacheDict = [[NSMutableDictionary alloc] init];
        if (tempDict) {
            cacheDict = [NSMutableDictionary dictionaryWithDictionary:tempDict];
        }
        if (resolver) {
            if ((resolver == resolverA) && resolverA.domainInfo) {
                NSDictionary *cacheValue = [resolverA.domainInfo objectForKey:domain];
                if (cacheValue) {
                    [cacheDict setObject:cacheValue forKey:kMSDKHttpDnsCache_A];
                    [cacheDict removeObjectForKey:kMSDKHttpDnsCache_4A];
                }
            } else if ((resolver == resolver4A) && resolver4A.domainInfo) {
                NSDictionary *cacheValue = [resolver4A.domainInfo objectForKey:domain];
                if (cacheValue) {
                    [cacheDict setObject:cacheValue forKey:kMSDKHttpDnsCache_4A];
                    [cacheDict removeObjectForKey:kMSDKHttpDnsCache_A];
                }
            } else if ((resolver == localResolver) && localResolver.domainInfo) {
                NSDictionary *cacheValue = [localResolver.domainInfo objectForKey:domain];
                if (cacheValue) {
                    [cacheDict setObject:cacheValue forKey:kMSDKLocalDnsCache];
                }
            } else if ((resolver == resolverBoth) && resolverBoth.domainInfo) {
                NSDictionary *cacheValue = [resolverBoth.domainInfo objectForKey:domain];
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
        [self updateCacheAndPersistIfNeeded:cacheDict withDomain:domain andResolver:resolver localResolver:localResolver];
    }
}

- (void)updateCacheAndPersistIfNeeded:(NSMutableDictionary *)cacheDict withDomain:(NSString *)domain andResolver:(MSDKDnsResolver *)resolver localResolver:(LocalDnsResolver *)localResolver {
    if (cacheDict && domain) {
        [[MSDKDnsManager shareInstance] cacheDomainInfo:cacheDict domain:domain];
        BOOL persistCacheIPEnabled = [[MSDKDnsParamsManager shareInstance] msdkDnsGetPersistCacheIPEnabled];
        BOOL isHttpAndOpenPersist = resolver && resolver != localResolver && persistCacheIPEnabled;
        if (isHttpAndOpenPersist){
            [[MSDKDnsDB shareInstance] insertOrReplaceDomainInfo:cacheDict domain:domain];
        }
    }
}

@end
