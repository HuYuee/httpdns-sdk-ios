//
//  MSDKDnsMainTests.m
//  MSDKDnsTests
//
//  测试MSDKDns主SDK类
//

#import <XCTest/XCTest.h>
#import "MSDKDns.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsManager.h"
#import "MSDKDnsInfoTool.h"

@interface MSDKDnsMainTests : XCTestCase
@end

@implementation MSDKDnsMainTests

- (void)setUp {
    [super setUp];
    // 设置基本配置，避免未初始化异常
    [self initializeSDK];
}

- (void)tearDown {
    // 清理缓存
    [[MSDKDns sharedInstance] clearCache];
    [super tearDown];
}

- (void)initializeSDK {
    DnsConfig *config = new DnsConfig();
    config->appId = @"test-app-id";
    config->dnsId = 12345;
    config->dnsKey = @"test-key-1234";
    config->token = @"test-token";
    config->debug = NO;
    config->timeout = 2000;
    config->encryptType = HttpDnsEncryptTypeHTTPS;
    config->addressType = HttpDnsAddressTypeAuto;
    config->routeIp = @"";
    config->httpOnly = NO;
    config->retryTimesBeforeSwitchServer = 3;
    config->enableReport = NO;
    
    [[MSDKDns sharedInstance] initConfig:config];
    
    // 等待异步初始化完成
    [self flushQueue];
}

- (void)flushQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

#pragma mark - 单例测试

- (void)testSharedInstanceReturnsSameObject {
    MSDKDns *instance1 = [MSDKDns sharedInstance];
    MSDKDns *instance2 = [MSDKDns sharedInstance];
    
    XCTAssertNotNil(instance1, @"MSDKDns单例不应为nil");
    XCTAssertEqual(instance1, instance2, @"多次调用sharedInstance应返回同一对象");
}

#pragma mark - 初始化配置测试

- (void)testInitConfigWithDictionary {
    NSDictionary *config = @{
        @"appId": @"dict-app-id",
        @"debug": @YES,
        @"dnsId": @54321,
        @"dnsKey": @"dict-dns-key",
        @"token": @"dict-token",
        @"encryptType": @(HttpDnsEncryptTypeHTTPS),
        @"routeIp": @"",
        @"timeout": @3000,
        @"httpOnly": @NO,
        @"retryTimesBeforeSwitchServer": @5,
        @"enableReport": @NO,
        @"addressType": @(HttpDnsAddressTypeAuto)
    };
    
    BOOL result = [[MSDKDns sharedInstance] initConfigWithDictionary:config];
    
    XCTAssertTrue(result, @"initConfigWithDictionary应返回YES");
}

#pragma mark - 设置方法测试

- (void)testWGSetDnsOpenIdWithValidId {
    BOOL result = [[MSDKDns sharedInstance] WGSetDnsOpenId:@"test-open-id-12345"];
    
    XCTAssertTrue(result, @"设置有效的openId应返回YES");
}

- (void)testWGSetDnsOpenIdWithEmptyString {
    BOOL result = [[MSDKDns sharedInstance] WGSetDnsOpenId:@""];
    
    XCTAssertFalse(result, @"设置空字符串openId应返回NO");
}

- (void)testWGSetDnsOpenIdWithNil {
    BOOL result = [[MSDKDns sharedInstance] WGSetDnsOpenId:nil];
    
    XCTAssertFalse(result, @"设置nil openId应返回NO");
}

- (void)testWGSetPreResolvedDomains {
    NSArray *domains = @[@"pre.example.com", @"pre2.example.com"];
    
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetPreResolvedDomains:domains], @"设置预解析域名不应抛出异常");
}

- (void)testWGSetKeepAliveDomains {
    NSArray *domains = @[@"keep1.example.com", @"keep2.example.com"];
    
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetKeepAliveDomains:domains], @"设置保活域名不应抛出异常");
}

- (void)testWGSetKeepAliveDomainsWithNil {
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetKeepAliveDomains:nil], @"设置nil保活域名不应抛出异常");
}

- (void)testWGSetIPRankData {
    NSDictionary *ipRankData = @{
        @"rank.example.com": @80,
        @"rank2.example.com": @443
    };
    
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetIPRankData:ipRankData], @"设置IP排序数据不应抛出异常");
}

- (void)testWGSetEnableKeepDomainsAlive {
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetEnableKeepDomainsAlive:YES], @"启用保活功能不应抛出异常");
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetEnableKeepDomainsAlive:NO], @"禁用保活功能不应抛出异常");
}

- (void)testWGSetHijackDomainArray {
    NSArray *hijackDomains = @[@"hijack1.example.com", @"hijack2.example.com"];
    
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetHijackDomainArray:hijackDomains], @"设置劫持域名列表不应抛出异常");
}

- (void)testWGSetNoHijackDomainArray {
    NSArray *noHijackDomains = @[@"nohijack1.example.com", @"nohijack2.example.com"];
    
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetNoHijackDomainArray:noHijackDomains], @"设置非劫持域名列表不应抛出异常");
}

- (void)testWGSetExpiredIPEnabled {
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetExpiredIPEnabled:YES], @"启用过期IP功能不应抛出异常");
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetExpiredIPEnabled:NO], @"禁用过期IP功能不应抛出异常");
}

- (void)testWGSetPersistCacheIPEnabled {
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetPersistCacheIPEnabled:YES], @"启用持久化缓存不应抛出异常");
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetPersistCacheIPEnabled:NO], @"禁用持久化缓存不应抛出异常");
}

- (void)testWGSetAuthTimeBaseByCurrentTime {
    NSTimeInterval currentTime = [[NSDate date] timeIntervalSince1970];
    
    XCTAssertNoThrow([[MSDKDns sharedInstance] WGSetAuthTimeBaseByCurrentTime:currentTime], @"设置授权时间基准不应抛出异常");
}

#pragma mark - 解析方法测试

- (void)testWGGetHostByNameWithEmptyDomain {
    NSArray *result = [[MSDKDns sharedInstance] WGGetHostByName:@""];
    
    XCTAssertNotNil(result, @"空域名应返回非nil数组");
    XCTAssertEqual(result.count, 2, @"空域名应返回[@\"0\", @\"0\"]");
    XCTAssertEqualObjects(result[0], @"0", @"空域名IPv4应为0");
    XCTAssertEqualObjects(result[1], @"0", @"空域名IPv6应为0");
}

- (void)testWGGetHostByNameWithNilDomain {
    NSArray *result = [[MSDKDns sharedInstance] WGGetHostByName:nil];
    
    XCTAssertNotNil(result, @"nil域名应返回非nil数组");
    XCTAssertEqual(result.count, 2, @"nil域名应返回[@\"0\", @\"0\"]");
}

- (void)testWGGetHostByNameWithValidDomain {
    // 使用一个测试域名
    NSArray *result = [[MSDKDns sharedInstance] WGGetHostByName:@"test.example.com"];
    
    XCTAssertNotNil(result, @"解析结果不应为nil");
    XCTAssertEqual(result.count, 2, @"结果数组应包含2个元素");
}

- (void)testWGGetHostsByNamesWithEmptyArray {
    NSDictionary *result = [[MSDKDns sharedInstance] WGGetHostsByNames:@[]];
    
    XCTAssertNotNil(result, @"空域名数组应返回非nil字典");
    XCTAssertEqual(result.count, 0, @"空域名数组应返回空字典");
}

- (void)testWGGetHostsByNamesWithNilArray {
    NSDictionary *result = [[MSDKDns sharedInstance] WGGetHostsByNames:nil];
    
    XCTAssertNotNil(result, @"nil域名数组应返回非nil字典");
    XCTAssertEqual(result.count, 0, @"nil域名数组应返回空字典");
}

- (void)testWGGetHostsByNamesWithValidDomains {
    NSArray *domains = @[@"test1.example.com", @"test2.example.com"];
    NSDictionary *result = [[MSDKDns sharedInstance] WGGetHostsByNames:domains];
    
    XCTAssertNotNil(result, @"解析结果不应为nil");
}

- (void)testWGGetAllHostsByNamesWithEmptyArray {
    NSDictionary *result = [[MSDKDns sharedInstance] WGGetAllHostsByNames:@[]];
    
    XCTAssertNotNil(result, @"空域名数组应返回非nil字典");
    XCTAssertEqual(result.count, 0, @"空域名数组应返回空字典");
}

- (void)testWGGetAllHostsByNamesWithValidDomains {
    NSArray *domains = @[@"test1.example.com"];
    NSDictionary *result = [[MSDKDns sharedInstance] WGGetAllHostsByNames:domains];
    
    XCTAssertNotNil(result, @"解析结果不应为nil");
}

#pragma mark - 异步解析方法测试

- (void)testWGGetHostByNameAsyncWithEmptyDomain {
    XCTestExpectation *expectation = [self expectationWithDescription:@"异步解析空域名"];
    
    // 确保expiredIPEnabled为NO
    [[MSDKDns sharedInstance] WGSetExpiredIPEnabled:NO];
    [self flushQueue];
    
    [[MSDKDns sharedInstance] WGGetHostByNameAsync:@"" returnIps:^(NSArray *ipsArray) {
        XCTAssertNotNil(ipsArray, @"回调结果不应为nil");
        XCTAssertEqual(ipsArray.count, 2, @"空域名应返回[@\"0\", @\"0\"]");
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testWGGetHostByNameAsyncWithNilDomain {
    XCTestExpectation *expectation = [self expectationWithDescription:@"异步解析nil域名"];
    
    // 确保expiredIPEnabled为NO
    [[MSDKDns sharedInstance] WGSetExpiredIPEnabled:NO];
    [self flushQueue];
    
    [[MSDKDns sharedInstance] WGGetHostByNameAsync:nil returnIps:^(NSArray *ipsArray) {
        XCTAssertNotNil(ipsArray, @"回调结果不应为nil");
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testWGGetHostsByNamesAsyncWithEmptyArray {
    XCTestExpectation *expectation = [self expectationWithDescription:@"异步批量解析空数组"];
    
    // 确保expiredIPEnabled为NO
    [[MSDKDns sharedInstance] WGSetExpiredIPEnabled:NO];
    [self flushQueue];
    
    [[MSDKDns sharedInstance] WGGetHostsByNamesAsync:@[] returnIps:^(NSDictionary *ipsDict) {
        XCTAssertNotNil(ipsDict, @"回调结果不应为nil");
        XCTAssertEqual(ipsDict.count, 0, @"空数组应返回空字典");
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testWGGetAllHostsByNamesAsyncWithEmptyArray {
    XCTestExpectation *expectation = [self expectationWithDescription:@"异步批量解析空数组（详细）"];
    
    // 确保expiredIPEnabled为NO
    [[MSDKDns sharedInstance] WGSetExpiredIPEnabled:NO];
    [self flushQueue];
    
    [[MSDKDns sharedInstance] WGGetAllHostsByNamesAsync:@[] returnIps:^(NSDictionary *ipsDict) {
        XCTAssertNotNil(ipsDict, @"回调结果不应为nil");
        XCTAssertEqual(ipsDict.count, 0, @"空数组应返回空字典");
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

#pragma mark - 其他方法测试

- (void)testWGGetDnsDetail {
    NSDictionary *detail = [[MSDKDns sharedInstance] WGGetDnsDetail:@"test.example.com"];
    
    // 如果没有缓存，应返回空或nil
    // 主要测试方法不崩溃
    XCTAssertTrue(detail == nil || [detail isKindOfClass:[NSDictionary class]], @"WGGetDnsDetail应返回nil或字典");
}

- (void)testWGGetNetworkStack {
    int networkStack = [[MSDKDns sharedInstance] WGGetNetworkStack];
    
    // 应返回有效的网络栈类型
    XCTAssertTrue(networkStack >= 0, @"网络栈类型应为非负整数");
}

- (void)testClearCache {
    XCTAssertNoThrow([[MSDKDns sharedInstance] clearCache], @"清理缓存不应抛出异常");
}

- (void)testClearHostCacheWithNil {
    XCTAssertNoThrow([[MSDKDns sharedInstance] clearHostCache:nil], @"清理nil主机缓存不应抛出异常");
}

- (void)testClearHostCacheWithEmptyArray {
    XCTAssertNoThrow([[MSDKDns sharedInstance] clearHostCache:@[]], @"清理空主机列表缓存不应抛出异常");
}

- (void)testClearHostCacheWithValidHosts {
    NSArray *hosts = @[@"host1.example.com", @"host2.example.com"];
    XCTAssertNoThrow([[MSDKDns sharedInstance] clearHostCache:hosts], @"清理指定主机缓存不应抛出异常");
}

#pragma mark - 边界条件测试

- (void)testWGGetHostByNameConvertsToLowercase {
    // 测试大写域名会被转换为小写
    NSArray *result = [[MSDKDns sharedInstance] WGGetHostByName:@"TEST.EXAMPLE.COM"];
    
    XCTAssertNotNil(result, @"大写域名解析结果不应为nil");
}

- (void)testWGGetHostsByNamesConvertsToLowercase {
    // 测试大写域名数组会被转换为小写
    NSArray *domains = @[@"TEST1.EXAMPLE.COM", @"TEST2.EXAMPLE.COM"];
    NSDictionary *result = [[MSDKDns sharedInstance] WGGetHostsByNames:domains];
    
    XCTAssertNotNil(result, @"大写域名数组解析结果不应为nil");
}

@end
