#import <XCTest/XCTest.h>
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"
#import "MSDKDnsPrivate.h"

@interface MSDKDnsParamsManagerTests : XCTestCase
@property (nonatomic, strong) MSDKDnsParamsManager *params;
@end

@implementation MSDKDnsParamsManagerTests

- (void)setUp {
    [super setUp];
    self.params = [MSDKDnsParamsManager shareInstance];
    [self resetAllFlags];
}

- (void)tearDown {
    [self resetAllFlags];
    [super tearDown];
}

- (void)resetAllFlags {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetPreResolvedDomains:nil];
    [params msdkDnsSetHttpOnly:NO];
    [params msdkDnsSetPersistCacheIPEnabled:NO];
    [params msdkDnsSetExpiredIPEnabled:NO];
    [params msdkDnsSetKeepAliveDomains:nil];
    [params msdkDnsUpdateSceneUseLdns:NO];
    [params msdkDnsUpdateSceneIsRetry:NO];
    [self flushParamQueue];
}

- (void)flushParamQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

#pragma mark - 单例测试

- (void)testShareInstanceReturnsSameObject {
    MSDKDnsParamsManager *instance1 = [MSDKDnsParamsManager shareInstance];
    MSDKDnsParamsManager *instance2 = [MSDKDnsParamsManager shareInstance];
    
    XCTAssertNotNil(instance1, @"MSDKDnsParamsManager单例不应为nil");
    XCTAssertEqual(instance1, instance2, @"多次调用shareInstance应返回同一对象");
}

#pragma mark - 基本参数设置测试

- (void)testSetAndGetMDnsId {
    [self.params msdkDnsSetMDnsId:12345 dnsKey:@"test-key" token:@"test-token"];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetMDnsId], 12345, @"DnsId应正确设置");
    XCTAssertEqualObjects([self.params msdkDnsGetMDnsKey], @"test-key", @"DnsKey应正确设置");
    XCTAssertEqualObjects([self.params msdkDnsGetMToken], @"test-token", @"Token应正确设置");
}

- (void)testSetAndGetMAppId {
    [self.params msdkDnsSetMAppId:@"test-app" timeOut:3000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushParamQueue];
    
    XCTAssertEqualObjects([self.params msdkDnsGetMAppId], @"test-app", @"AppId应正确设置");
    XCTAssertEqual([self.params msdkDnsGetEncryptType], HttpDnsEncryptTypeHTTPS, @"加密类型应正确设置");
    XCTAssertEqualWithAccuracy([self.params msdkDnsGetMTimeOut], 3.0, 0.0001, @"超时应正确转换");
}

- (void)testSetAndGetMOpenId {
    [self.params msdkDnsSetMOpenId:@"test-open-id"];
    [self flushParamQueue];
    
    XCTAssertEqualObjects([self.params msdkDnsGetMOpenId], @"test-open-id", @"OpenId应正确设置");
}

#pragma mark - 功能标志测试

- (void)testFeatureFlagsToggleBasedOnConfiguration {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetPreResolvedDomains:@[@"pre.example.com"]];
    [params msdkDnsSetHttpOnly:YES];
    [params msdkDnsSetPersistCacheIPEnabled:YES];
    [params msdkDnsSetExpiredIPEnabled:YES];
    [params msdkDnsSetKeepAliveDomains:@[@"keep.example.com"]];
    [self flushParamQueue];

    uint32_t expected = MSDKDNS_FEATURE_PRE_RESOLVE_DOMAINS |
                        MSDKDNS_FEATURE_HTTP_ONLY |
                        MSDKDNS_FEATURE_PERSIST_CACHE_IP |
                        MSDKDNS_FEATURE_EXPIRED_IP_ENABLED |
                        MSDKDNS_FEATURE_KEEP_ALIVE_DOMAINS;
    XCTAssertEqual([params msdkDnsGetFeatureFlags], expected);

    [params msdkDnsSetPreResolvedDomains:nil];
    [params msdkDnsSetHttpOnly:NO];
    [params msdkDnsSetPersistCacheIPEnabled:NO];
    [params msdkDnsSetExpiredIPEnabled:NO];
    [params msdkDnsSetKeepAliveDomains:nil];
    [self flushParamQueue];
    XCTAssertEqual([params msdkDnsGetFeatureFlags], 0);
}

- (void)testSceneFlagsToggle {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsUpdateSceneUseLdns:YES];
    [params msdkDnsUpdateSceneIsRetry:YES];
    [self flushParamQueue];
    XCTAssertEqual([params msdkDnsGetSceneFlags], MSDKDNS_SCENE_USE_LDNS | MSDKDNS_SCENE_HTTPDNS_RETRY);

    [params msdkDnsUpdateSceneUseLdns:NO];
    [params msdkDnsUpdateSceneIsRetry:NO];
    [self flushParamQueue];
    XCTAssertEqual([params msdkDnsGetSceneFlags], 0);
}

#pragma mark - 超时设置测试

- (void)testTimeoutConversionFallbacks {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetMAppId:@"app" timeOut:1500 encryptType:HttpDnsEncryptTypeDES];
    XCTAssertEqualWithAccuracy([params msdkDnsGetMTimeOut], 1.5, 0.0001);

    [params msdkDnsSetMAppId:@"app" timeOut:0 encryptType:HttpDnsEncryptTypeDES];
    XCTAssertEqualWithAccuracy([params msdkDnsGetMTimeOut], 2.0, 0.0001);
}

- (void)testTimeoutWithNegativeValue {
    [self.params msdkDnsSetMAppId:@"app" timeOut:-1000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushParamQueue];
    
    // 负值应被视为无效，使用默认值
    XCTAssertEqualWithAccuracy([self.params msdkDnsGetMTimeOut], 2.0, 0.0001, @"负值应使用默认超时");
}

- (void)testTimeoutWithVeryLargeValue {
    [self.params msdkDnsSetMAppId:@"app" timeOut:30000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushParamQueue];
    
    XCTAssertEqualWithAccuracy([self.params msdkDnsGetMTimeOut], 30.0, 0.0001, @"大值应正确转换");
}

#pragma mark - 加密类型测试

- (void)testEncryptTypeDES {
    [self.params msdkDnsSetMAppId:@"app" timeOut:2000 encryptType:HttpDnsEncryptTypeDES];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetEncryptType], HttpDnsEncryptTypeDES, @"DES加密类型应正确设置");
}

- (void)testEncryptTypeAES {
    [self.params msdkDnsSetMAppId:@"app" timeOut:2000 encryptType:HttpDnsEncryptTypeAES];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetEncryptType], HttpDnsEncryptTypeAES, @"AES加密类型应正确设置");
}

- (void)testEncryptTypeHTTPS {
    [self.params msdkDnsSetMAppId:@"app" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetEncryptType], HttpDnsEncryptTypeHTTPS, @"HTTPS加密类型应正确设置");
}

#pragma mark - 地址类型测试

- (void)testAddressTypeIPv4 {
    [self.params msdkDnsSetAddressType:HttpDnsAddressTypeIPv4];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetAddressType], HttpDnsAddressTypeIPv4, @"IPv4地址类型应正确设置");
}

- (void)testAddressTypeIPv6 {
    [self.params msdkDnsSetAddressType:HttpDnsAddressTypeIPv6];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetAddressType], HttpDnsAddressTypeIPv6, @"IPv6地址类型应正确设置");
}

- (void)testAddressTypeDual {
    [self.params msdkDnsSetAddressType:HttpDnsAddressTypeDual];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetAddressType], HttpDnsAddressTypeDual, @"双栈地址类型应正确设置");
}

- (void)testAddressTypeAuto {
    [self.params msdkDnsSetAddressType:HttpDnsAddressTypeAuto];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetAddressType], HttpDnsAddressTypeAuto, @"自动地址类型应正确设置");
}

#pragma mark - HttpOnly测试

- (void)testHttpOnlyEnabled {
    [self.params msdkDnsSetHttpOnly:YES];
    [self flushParamQueue];
    
    XCTAssertTrue([self.params msdkDnsGetHttpOnly], @"HttpOnly应为YES");
}

- (void)testHttpOnlyDisabled {
    [self.params msdkDnsSetHttpOnly:NO];
    [self flushParamQueue];
    
    XCTAssertFalse([self.params msdkDnsGetHttpOnly], @"HttpOnly应为NO");
}

#pragma mark - 预解析域名测试

- (void)testPreResolvedDomainsWithValidArray {
    NSArray *domains = @[@"pre1.example.com", @"pre2.example.com"];
    [self.params msdkDnsSetPreResolvedDomains:domains];
    [self flushParamQueue];
    
    NSArray *result = [self.params msdkDnsGetPreResolvedDomains];
    XCTAssertEqualObjects(result, domains, @"预解析域名应正确设置");
}

- (void)testPreResolvedDomainsWithNil {
    [self.params msdkDnsSetPreResolvedDomains:nil];
    [self flushParamQueue];
    
    NSArray *result = [self.params msdkDnsGetPreResolvedDomains];
    XCTAssertNil(result, @"nil应清除预解析域名");
}

- (void)testPreResolvedDomainsWithEmptyArray {
    [self.params msdkDnsSetPreResolvedDomains:@[]];
    [self flushParamQueue];
    
    NSArray *result = [self.params msdkDnsGetPreResolvedDomains];
    XCTAssertEqual(result.count, 0, @"空数组应设置为空");
}

#pragma mark - 保活域名测试

- (void)testKeepAliveDomainsWithValidArray {
    NSArray *domains = @[@"keep1.example.com", @"keep2.example.com"];
    [self.params msdkDnsSetKeepAliveDomains:domains];
    [self flushParamQueue];
    
    NSArray *result = [self.params msdkDnsGetKeepAliveDomains];
    XCTAssertEqualObjects(result, domains, @"保活域名应正确设置");
}

- (void)testKeepAliveDomainsWithNil {
    [self.params msdkDnsSetKeepAliveDomains:nil];
    [self flushParamQueue];
    
    NSArray *result = [self.params msdkDnsGetKeepAliveDomains];
    XCTAssertNil(result, @"nil应清除保活域名");
}

#pragma mark - 持久化缓存测试

- (void)testPersistCacheIPEnabled {
    [self.params msdkDnsSetPersistCacheIPEnabled:YES];
    [self flushParamQueue];
    
    XCTAssertTrue([self.params msdkDnsGetPersistCacheIPEnabled], @"持久化缓存应为YES");
}

- (void)testPersistCacheIPDisabled {
    [self.params msdkDnsSetPersistCacheIPEnabled:NO];
    [self flushParamQueue];
    
    XCTAssertFalse([self.params msdkDnsGetPersistCacheIPEnabled], @"持久化缓存应为NO");
}

#pragma mark - 过期IP测试

- (void)testExpiredIPEnabled {
    [self.params msdkDnsSetExpiredIPEnabled:YES];
    [self flushParamQueue];
    
    XCTAssertTrue([self.params msdkDnsGetExpiredIPEnabled], @"过期IP应为YES");
}

- (void)testExpiredIPDisabled {
    [self.params msdkDnsSetExpiredIPEnabled:NO];
    [self flushParamQueue];
    
    XCTAssertFalse([self.params msdkDnsGetExpiredIPEnabled], @"过期IP应为NO");
}

#pragma mark - IP排序配置测试

- (void)testIPRankDataWithValidDictionary {
    NSDictionary *ipRankData = @{
        @"rank.example.com": @80,
        @"rank2.example.com": @443
    };
    [self.params msdkDnsSetIPRankData:ipRankData];
    [self flushParamQueue];
    
    NSDictionary *result = [self.params msdkDnsGetIPRankData];
    XCTAssertNotNil(result, @"IP排序数据不应为nil");
}

- (void)testIPRankDataWithNil {
    [self.params msdkDnsSetIPRankData:nil];
    [self flushParamQueue];
    
    NSDictionary *result = [self.params msdkDnsGetIPRankData];
    XCTAssertNil(result, @"nil应清除IP排序数据");
}

#pragma mark - 劫持域名列表测试

- (void)testHijackDomainArray {
    NSArray *hijackDomains = @[@"hijack1.example.com", @"hijack2.example.com"];
    [self.params msdkDnsSetHijackDomainArray:hijackDomains];
    [self flushParamQueue];
    
    // 验证设置不崩溃
    XCTAssertNoThrow([self.params msdkDnsSetHijackDomainArray:hijackDomains], @"设置劫持域名不应崩溃");
}

- (void)testNoHijackDomainArray {
    NSArray *noHijackDomains = @[@"nohijack1.example.com", @"nohijack2.example.com"];
    [self.params msdkDnsSetNoHijackDomainArray:noHijackDomains];
    [self flushParamQueue];
    
    // 验证设置不崩溃
    XCTAssertNoThrow([self.params msdkDnsSetNoHijackDomainArray:noHijackDomains], @"设置非劫持域名不应崩溃");
}

#pragma mark - 路由IP测试

- (void)testRouteIP {
    [self.params msdkDnsSetRouteIp:@"192.168.1.1"];
    [self flushParamQueue];
    
    XCTAssertEqualObjects([self.params msdkDnsGetRouteIp], @"192.168.1.1", @"路由IP应正确设置");
}

- (void)testRouteIPWithNil {
    [self.params msdkDnsSetRouteIp:nil];
    [self flushParamQueue];
    
    NSString *result = [self.params msdkDnsGetRouteIp];
    XCTAssertNil(result, @"nil路由IP应正确处理");
}

#pragma mark - 上报开关测试

- (void)testEnableReportEnabled {
    [self.params msdkDnsSetEnableReport:YES];
    [self flushParamQueue];
    
    XCTAssertTrue([self.params msdkDnsGetEnableReport], @"上报开关应为YES");
}

- (void)testEnableReportDisabled {
    [self.params msdkDnsSetEnableReport:NO];
    [self flushParamQueue];
    
    XCTAssertFalse([self.params msdkDnsGetEnableReport], @"上报开关应为NO");
}

#pragma mark - 重试次数测试

- (void)testRetryTimesBeforeSwitchServer {
    [self.params msdkDnsSetRetryTimesBeforeSwitchServer:5];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetRetryTimesBeforeSwitchServer], 5, @"重试次数应为5");
}

- (void)testRetryTimesBeforeSwitchServerDefault {
    // 默认值测试
    int defaultValue = [self.params msdkDnsGetRetryTimesBeforeSwitchServer];
    XCTAssertGreaterThanOrEqual(defaultValue, 0, @"默认重试次数应为非负数");
}

#pragma mark - 域名服务探测开关测试

- (void)testEnableDetectHostServer {
    [self.params msdkDnsSetEnableDetectHostServer:YES];
    [self flushParamQueue];
    
    XCTAssertTrue([self.params msdkDnsGetEnableDetectHostServer], @"域名服务探测应为YES");
}

#pragma mark - 保活开关测试

- (void)testEnableKeepDomainsAlive {
    [self.params msdkDnsSetEnableKeepDomainsAlive:YES];
    [self flushParamQueue];
    
    XCTAssertTrue([self.params msdkDnsGetEnableKeepDomainsAlive], @"保活开关应为YES");
}

#pragma mark - 边界条件测试

- (void)testSetMDnsIdWithZero {
    [self.params msdkDnsSetMDnsId:0 dnsKey:@"key" token:@"token"];
    [self flushParamQueue];
    
    XCTAssertEqual([self.params msdkDnsGetMDnsId], 0, @"DnsId为0应正确设置");
}

- (void)testSetMDnsIdWithEmptyKey {
    [self.params msdkDnsSetMDnsId:12345 dnsKey:@"" token:@"token"];
    [self flushParamQueue];
    
    XCTAssertEqualObjects([self.params msdkDnsGetMDnsKey], @"", @"空DnsKey应正确设置");
}

- (void)testSetMAppIdWithEmptyString {
    [self.params msdkDnsSetMAppId:@"" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushParamQueue];
    
    XCTAssertEqualObjects([self.params msdkDnsGetMAppId], @"", @"空AppId应正确设置");
}

@end
