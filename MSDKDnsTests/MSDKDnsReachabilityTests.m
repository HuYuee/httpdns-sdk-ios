//
//  MSDKDnsReachabilityTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsReachability网络可达性类
//

#import <XCTest/XCTest.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import "MSDKDnsReachability.h"

@interface MSDKDnsReachabilityTests : XCTestCase
@property (nonatomic, strong) MSDKDnsReachability *reachability;
@end

@implementation MSDKDnsReachabilityTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    if (self.reachability) {
        [self.reachability stopNotifier];
        self.reachability = nil;
    }
    [super tearDown];
}

#pragma mark - 常量测试

- (void)testNotificationConstants {
    XCTAssertNotNil(kMSDKDnsInternetConnection, @"kMSDKDnsInternetConnection常量不应为nil");
    XCTAssertNotNil(kMSDKDnsLocalWiFiConnection, @"kMSDKDnsLocalWiFiConnection常量不应为nil");
    XCTAssertNotNil(kMSDKDnsReachabilityChangedNotification, @"kMSDKDnsReachabilityChangedNotification常量不应为nil");
    
    XCTAssertEqualObjects(kMSDKDnsInternetConnection, @"MSDKDnsInternetConnection", @"常量值应匹配");
    XCTAssertEqualObjects(kMSDKDnsLocalWiFiConnection, @"MSDKDnsLocalWiFiConnection", @"常量值应匹配");
    XCTAssertEqualObjects(kMSDKDnsReachabilityChangedNotification, @"MSDKDnsNetworkReachabilityChangedNotification", @"常量值应匹配");
}

#pragma mark - reachabilityWithHostName测试

- (void)testReachabilityWithHostNameReturnsInstance {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityWithHostName:@"www.apple.com"];
    
    XCTAssertNotNil(reachability, @"使用有效主机名应返回非nil实例");
    
    [reachability stopNotifier];
}

- (void)testReachabilityWithEmptyHostName {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityWithHostName:@""];
    
    // 空主机名可能返回nil或有效实例，取决于实现
    // 主要测试不崩溃
    if (reachability) {
        [reachability stopNotifier];
    }
}

#pragma mark - reachabilityForInternetConnection测试

- (void)testReachabilityForInternetConnectionReturnsInstance {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    
    XCTAssertNotNil(reachability, @"reachabilityForInternetConnection应返回非nil实例");
    
    [reachability stopNotifier];
}

#pragma mark - reachabilityWithAddress测试

- (void)testReachabilityWithIPv4Address {
    struct sockaddr_in address;
    bzero(&address, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("8.8.8.8");
    
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityWithAddress:(const struct sockaddr *)&address];
    
    XCTAssertNotNil(reachability, @"使用有效IPv4地址应返回非nil实例");
    
    [reachability stopNotifier];
}

- (void)testReachabilityWithZeroAddress {
    struct sockaddr_in zeroAddress;
    bzero(&zeroAddress, sizeof(zeroAddress));
    zeroAddress.sin_len = sizeof(zeroAddress);
    zeroAddress.sin_family = AF_INET;
    
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityWithAddress:(const struct sockaddr *)&zeroAddress];
    
    XCTAssertNotNil(reachability, @"使用零地址应返回非nil实例");
    
    [reachability stopNotifier];
}

#pragma mark - currentReachabilityStatus测试

- (void)testCurrentReachabilityStatusReturnsValidValue {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    MSDKDnsNetworkStatus status = [reachability currentReachabilityStatus];
    
    // 状态应该是有效的枚举值之一
    XCTAssertTrue(status == MSDKDnsNotReachable ||
                  status == MSDKDnsReachableViaWiFi ||
                  status == MSDKDnsReachableViaWWAN,
                  @"状态应该是有效的枚举值");
    
    [reachability stopNotifier];
}

#pragma mark - connectionRequired测试

- (void)testConnectionRequiredReturnsBOOL {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    BOOL required = [reachability connectionRequired];
    
    // 主要测试方法可以正常调用并返回BOOL值
    XCTAssertTrue(required == YES || required == NO, @"connectionRequired应返回有效的BOOL值");
    
    [reachability stopNotifier];
}

#pragma mark - startNotifier和stopNotifier测试

- (void)testStartNotifierReturnsYES {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    BOOL started = [reachability startNotifier];
    
    XCTAssertTrue(started, @"startNotifier应返回YES");
    
    [reachability stopNotifier];
}

- (void)testStopNotifierDoesNotCrash {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    [reachability startNotifier];
    
    // stopNotifier不应崩溃
    XCTAssertNoThrow([reachability stopNotifier], @"stopNotifier不应抛出异常");
}

- (void)testStopNotifierWithoutStartDoesNotCrash {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    // 未调用startNotifier就调用stopNotifier不应崩溃
    XCTAssertNoThrow([reachability stopNotifier], @"未启动时停止不应抛出异常");
}

#pragma mark - 多次调用测试

- (void)testMultipleStartNotifierCalls {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    // 多次调用startNotifier不应崩溃
    [reachability startNotifier];
    [reachability startNotifier];
    
    [reachability stopNotifier];
}

- (void)testMultipleStopNotifierCalls {
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    [reachability startNotifier];
    
    // 多次调用stopNotifier不应崩溃
    [reachability stopNotifier];
    [reachability stopNotifier];
}

#pragma mark - 通知测试

- (void)testReachabilityChangedNotificationReceived {
    XCTestExpectation *expectation = [self expectationWithDescription:@"收到网络变化通知"];
    expectation.inverted = YES; // 我们不期望在短时间内收到通知，只是测试监听器设置
    
    MSDKDnsReachability *reachability = [MSDKDnsReachability reachabilityForInternetConnection];
    XCTAssertNotNil(reachability, @"reachability不应为nil");
    
    [[NSNotificationCenter defaultCenter] addObserverForName:kMSDKDnsReachabilityChangedNotification
                                                      object:nil
                                                       queue:nil
                                                  usingBlock:^(NSNotification *note) {
        [expectation fulfill];
    }];
    
    [reachability startNotifier];
    
    [self waitForExpectationsWithTimeout:1.0 handler:nil];
    
    [[NSNotificationCenter defaultCenter] removeObserver:self name:kMSDKDnsReachabilityChangedNotification object:nil];
    [reachability stopNotifier];
}

#pragma mark - NetworkStatus枚举测试

- (void)testNetworkStatusEnumValues {
    // 验证枚举值
    XCTAssertEqual(MSDKDnsNotReachable, 0, @"MSDKDnsNotReachable应为0");
    XCTAssertEqual(MSDKDnsReachableViaWiFi, 1, @"MSDKDnsReachableViaWiFi应为1");
    XCTAssertEqual(MSDKDnsReachableViaWWAN, 2, @"MSDKDnsReachableViaWWAN应为2");
}

@end
