#import <XCTest/XCTest.h>
#import "MSDKDnsManager.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"
#import "MSDKDnsPrivate.h"

@interface MSDKDnsManager (Testing)
- (BOOL)domainsResultUseOnlyLocalDNS:(NSArray *)domains fromCache:(NSDictionary *)domainDict;
- (NSArray *)resultArray:(NSString *)domain fromCache:(NSDictionary *)domainDict;
@end

@interface MSDKDnsManagerTests : XCTestCase
@property (nonatomic, strong) MSDKDnsManager *manager;
@end

@implementation MSDKDnsManagerTests

- (void)setUp {
    [super setUp];
    self.manager = [MSDKDnsManager shareInstance];
    [self.manager clearAllCache];
    [self flushQueue];
}

- (void)tearDown {
    [self.manager clearAllCache];
    [self flushQueue];
    [super tearDown];
}

- (void)flushQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

- (NSDictionary *)domainInfoWithHttpIPv4:(NSArray<NSString *> *)ipv4 ipv6:(NSArray<NSString *> *)ipv6 local:(NSArray<NSString *> *)local {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    if (ipv4) {
        info[kMSDKHttpDnsCache_A] = @{kIP: ipv4, kTTL: @"60", kClientIP: @"10.0.0.1"};
    }
    if (ipv6) {
        info[kMSDKHttpDnsCache_4A] = @{kIP: ipv6, kTTL: @"120", kClientIP: @"2001::1"};
    }
    if (local) {
        info[kMSDKLocalDnsCache] = @{kIP: local};
    }
    return info;
}

- (void)testCacheDomainInfoAndGetDnsDetail {
    NSDictionary *domainInfo = [self domainInfoWithHttpIPv4:@[@"1.1.1.1", @"2.2.2.2"]
                                                    ipv6:@[@"2001::1"]
                                                   local:@[@"9.9.9.9", @"8.8.8.8"]];
    [self.manager cacheDomainInfo:domainInfo domain:@"example.com"];
    [self flushQueue];

    NSDictionary *detail = [self.manager getDnsDetail:@"example.com"];
    XCTAssertEqualObjects(detail[@"v4_ips"], @"1.1.1.1,2.2.2.2");
    XCTAssertEqualObjects(detail[@"v6_ips"], @"2001::1");
    XCTAssertEqualObjects(detail[@"v4_client_ip"], @"10.0.0.1");

    [self.manager clearCacheForDomain:@"example.com"];
    [self flushQueue];
    NSDictionary *cleared = [self.manager getDnsDetail:@"example.com"];
    XCTAssertEqualObjects(cleared[@"v4_ips"], @"");
}

- (void)testDomainsResultUseOnlyLocalDNS {
    NSDictionary *localOnlyCache = @{
        @"only-local.com": @{
            kMSDKLocalDnsCache: @{kIP: @[@"9.9.9.9"]},
            kMSDKHttpDnsCache_A: @{kIP: @[]}
        }
    };
    XCTAssertTrue([self.manager domainsResultUseOnlyLocalDNS:@[@"only-local.com"] fromCache:localOnlyCache]);

    NSDictionary *httpCache = @{
        @"with-http.com": @{
            kMSDKHttpDnsCache_A: @{kIP: @[@"1.1.1.1"]}
        }
    };
    XCTAssertFalse([self.manager domainsResultUseOnlyLocalDNS:@[@"with-http.com"] fromCache:httpCache]);
}

- (void)testResultArrayRespectsHttpOnlyFlag {
    NSDictionary *domainCache = @{
        @"demo.com": @{
            kMSDKLocalDnsCache: @{kIP: @[@"9.9.9.9", @"8.8.8.8"]}
        }
    };
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetHttpOnly:NO];
    [self flushQueue];
    NSArray *result = [self.manager resultArray:@"demo.com" fromCache:domainCache];
    XCTAssertEqualObjects(result[0], @"9.9.9.9");

    [params msdkDnsSetHttpOnly:YES];
    [self flushQueue];
    NSArray *httpOnlyResult = [self.manager resultArray:@"demo.com" fromCache:domainCache];
    XCTAssertEqualObjects(httpOnlyResult[0], @"0");
}

- (void)testIsOpenOptimismCacheRequiresBothSwitches {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetPersistCacheIPEnabled:YES];
    [params msdkDnsSetExpiredIPEnabled:YES];
    [self flushQueue];
    XCTAssertTrue([self.manager isOpenOptimismCache]);

    [params msdkDnsSetExpiredIPEnabled:NO];
    [self flushQueue];
    XCTAssertFalse([self.manager isOpenOptimismCache]);
}

- (void)testDelayDispatchDictionaryLifecycle {
    [self.manager msdkDnsAddDomainOpenDelayDispatch:@"demo.com"];
    [self flushQueue];
    NSDictionary *delayDict = [self.manager msdkDnsGetDomainISOpenDelayDispatch];
    XCTAssertEqualObjects(delayDict[@"demo.com"], @YES);

    [self.manager msdkDnsClearDomainOpenDelayDispatch:@"demo.com"];
    [self flushQueue];
    NSDictionary *cleared = [self.manager msdkDnsGetDomainISOpenDelayDispatch];
    XCTAssertFalse([cleared.allKeys containsObject:@"demo.com"]);
}

@end
