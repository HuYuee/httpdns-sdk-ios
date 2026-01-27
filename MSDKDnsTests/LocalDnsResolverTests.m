//
//  LocalDnsResolverTests.m
//  MSDKDnsTests
//
//  测试LocalDnsResolver本地DNS解析器
//

#import <XCTest/XCTest.h>
#import "LocalDnsResolver.h"
#import "MSDKDnsPrivate.h"
#import "msdkdns_local_ip_stack.h"

@interface LocalDnsResolverTests : XCTestCase <MSDKDnsResolverDelegate>
@property (nonatomic, strong) LocalDnsResolver *resolver;
@property (nonatomic, strong) XCTestExpectation *expectation;
@property (nonatomic, strong) NSDictionary *receivedDomainInfo;
@property (nonatomic, strong) NSString *receivedErrorInfo;
@end

@implementation LocalDnsResolverTests

- (void)setUp {
    [super setUp];
    self.resolver = [[LocalDnsResolver alloc] init];
    self.resolver.delegate = self;
    self.receivedDomainInfo = nil;
    self.receivedErrorInfo = nil;
}

- (void)tearDown {
    self.resolver.delegate = nil;
    self.resolver = nil;
    self.expectation = nil;
    [super tearDown];
}

#pragma mark - MSDKDnsResolverDelegate

- (void)resolver:(MSDKDnsResolver *)resolver didGetDomainInfo:(NSDictionary *)domainInfo {
    self.receivedDomainInfo = domainInfo;
    if (self.expectation) {
        [self.expectation fulfill];
    }
}

- (void)resolver:(MSDKDnsResolver *)resolver getDomainError:(NSString *)errorInfo retry:(BOOL)retry {
    self.receivedErrorInfo = errorInfo;
    if (self.expectation) {
        [self.expectation fulfill];
    }
}

#pragma mark - 初始化测试

- (void)testResolverCanBeInitialized {
    XCTAssertNotNil(self.resolver, @"LocalDnsResolver应能正常初始化");
}

- (void)testResolverInitialState {
    XCTAssertFalse(self.resolver.isFinished, @"初始状态isFinished应为NO");
    XCTAssertFalse(self.resolver.isSucceed, @"初始状态isSucceed应为NO");
}

#pragma mark - 解析测试

- (void)testResolveValidDomain {
    self.expectation = [self expectationWithDescription:@"解析有效域名"];
    
    // 解析一个肯定存在的域名
    [self.resolver startWithDomains:@[@"localhost"]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    XCTAssertTrue(self.resolver.isFinished, @"解析完成后isFinished应为YES");
    XCTAssertNotNil(self.receivedDomainInfo, @"应收到域名信息");
}

- (void)testResolveIPv4Only {
    self.expectation = [self expectationWithDescription:@"仅IPv4解析"];
    
    [self.resolver startWithDomains:@[@"localhost"]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    XCTAssertNotNil(self.receivedDomainInfo, @"应收到域名信息");
    
    NSDictionary *localhostInfo = self.receivedDomainInfo[@"localhost"];
    if (localhostInfo) {
        NSArray *ips = localhostInfo[kIP];
        XCTAssertNotNil(ips, @"应包含IP数组");
    }
}

- (void)testResolveIPv6Only {
    self.expectation = [self expectationWithDescription:@"仅IPv6解析"];
    
    [self.resolver startWithDomains:@[@"localhost"]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv6];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    XCTAssertTrue(self.resolver.isFinished, @"解析完成后isFinished应为YES");
}

- (void)testResolveDualStack {
    self.expectation = [self expectationWithDescription:@"双栈解析"];
    
    [self.resolver startWithDomains:@[@"localhost"]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_Dual];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    XCTAssertTrue(self.resolver.isFinished, @"解析完成后isFinished应为YES");
}

#pragma mark - 批量解析测试

- (void)testResolveMultipleDomains {
    self.expectation = [self expectationWithDescription:@"批量解析多个域名"];
    
    [self.resolver startWithDomains:@[@"localhost", @"localhost"]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    XCTAssertNotNil(self.receivedDomainInfo, @"应收到域名信息");
}

#pragma mark - 超时测试

- (void)testResolveWithShortTimeout {
    self.expectation = [self expectationWithDescription:@"短超时解析"];
    
    // 使用非常短的超时时间
    [self.resolver startWithDomains:@[@"nonexistent.invalid.domain.test"]
                            timeOut:0.001  // 1毫秒
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
    
    // 应该完成（可能成功或超时）
    XCTAssertTrue(self.resolver.isFinished, @"解析应完成");
}

#pragma mark - dnsTimeConsuming测试

- (void)testDnsTimeConsumingReturnsValidValue {
    self.expectation = [self expectationWithDescription:@"获取DNS耗时"];
    
    [self.resolver startWithDomains:@[@"localhost"]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    int timeConsuming = [self.resolver dnsTimeConsuming];
    
    // 耗时应该是非负数
    XCTAssertGreaterThanOrEqual(timeConsuming, 0, @"DNS耗时应为非负数");
}

#pragma mark - isIPLegal测试

- (void)testIsIPLegalWithValidIPv4 {
    // use4A=NO时，检查所有IP是否都是有效的IPv4
    NSArray *ips = @[@"192.168.1.1"];
    BOOL isLegal = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertTrue(isLegal, @"有效IPv4应返回YES");
}

- (void)testIsIPLegalWithInvalidIPv4 {
    // "0"不是有效的IPv4地址
    NSArray *ips = @[@"0"];
    BOOL isLegal = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertFalse(isLegal, @"无效IP应返回NO");
}

- (void)testIsIPLegalWithValidIPv6 {
    // use4A=YES时，检查所有IP是否都是有效的IPv6
    NSArray *ips = @[@"2001:db8::1"];
    BOOL isLegal = [self.resolver isIPLegal:ips use4A:YES];
    
    XCTAssertTrue(isLegal, @"有效IPv6应返回YES");
}

- (void)testIsIPLegalWithNilArray {
    BOOL isLegal = [self.resolver isIPLegal:nil use4A:NO];
    
    XCTAssertFalse(isLegal, @"nil数组应返回NO");
}

- (void)testIsIPLegalWithEmptyArray {
    NSArray *ips = @[];
    BOOL isLegal = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertFalse(isLegal, @"空数组应返回NO");
}

- (void)testIsIPLegalWithMixedValidInvalid {
    // 数组中有一个无效IP时应返回NO
    NSArray *ips = @[@"192.168.1.1", @"invalid"];
    BOOL isLegal = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertFalse(isLegal, @"包含无效IP的数组应返回NO");
}

#pragma mark - 边界情况测试

- (void)testResolveWithEmptyDomainArray {
    // 传入空域名数组
    self.expectation = [self expectationWithDescription:@"空域名数组解析"];
    
    [self.resolver startWithDomains:@[]
                            timeOut:5.0
                              dnsId:0
                             dnsKey:nil
                           netStack:msdkdns::MSDKDNS_ELocalIPStack_IPv4];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
    
    // 应该完成（返回空结果）
    XCTAssertTrue(self.resolver.isFinished, @"解析应完成");
}

@end
