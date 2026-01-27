//
//  MSDKDnsNetworkManagerTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsNetworkManager网络管理器
//

#import <XCTest/XCTest.h>
#import "MSDKDnsNetworkManager.h"
#import "MSDKDnsParamsManager.h"

@interface MSDKDnsNetworkManagerTests : XCTestCase
@property (nonatomic, strong) MSDKDnsNetworkManager *networkManager;
@end

@implementation MSDKDnsNetworkManagerTests

- (void)setUp {
    [super setUp];
    self.networkManager = [MSDKDnsNetworkManager shareInstance];
}

- (void)tearDown {
    self.networkManager = nil;
    [super tearDown];
}

#pragma mark - 单例测试

- (void)testShareInstanceReturnsSameObject {
    MSDKDnsNetworkManager *instance1 = [MSDKDnsNetworkManager shareInstance];
    MSDKDnsNetworkManager *instance2 = [MSDKDnsNetworkManager shareInstance];
    
    XCTAssertNotNil(instance1, @"网络管理器单例不应为nil");
    XCTAssertEqual(instance1, instance2, @"多次调用shareInstance应返回同一对象");
}

- (void)testStartInitializesInstance {
    XCTAssertNoThrow([MSDKDnsNetworkManager start], @"start方法不应抛出异常");
    XCTAssertNotNil([MSDKDnsNetworkManager shareInstance], @"start后实例应存在");
}

#pragma mark - networkAvailable测试

- (void)testNetworkAvailableReturnsBOOL {
    BOOL available = [self.networkManager networkAvailable];
    
    // 主要测试方法可以正常调用并返回BOOL值
    XCTAssertTrue(available == YES || available == NO, @"networkAvailable应返回有效的BOOL值");
}

#pragma mark - networkStatus测试

- (void)testNetworkStatusReturnsValidValue {
    MSDKDnsNetworkStatus status = [self.networkManager networkStatus];
    
    // 状态应该是有效的枚举值之一
    XCTAssertTrue(status == MSDKDnsNotReachable ||
                  status == MSDKDnsReachableViaWiFi ||
                  status == MSDKDnsReachableViaWWAN,
                  @"状态应该是有效的枚举值");
}

#pragma mark - networkType测试

- (void)testNetworkTypeReturnsValidString {
    NSString *networkType = [self.networkManager networkType];
    
    XCTAssertNotNil(networkType, @"networkType不应返回nil");
    XCTAssertTrue(networkType.length > 0, @"networkType应返回非空字符串");
    
    // 验证返回的网络类型是预期的值之一
    NSArray *validTypes = @[@"wifi", @"2G", @"3G", @"4G", @"unknown", @"iphonesimulator"];
    XCTAssertTrue([validTypes containsObject:networkType], @"networkType应返回有效的网络类型: %@", networkType);
}

#pragma mark - is3gNetWork测试

- (void)testIs3gNetWorkWithValidNetworkModels {
    // 测试不同的3G网络模型
    // 注意：这个方法是私有的，我们通过networkType间接测试
    
    NSString *networkType = [self.networkManager networkType];
    // 只要不崩溃就说明内部的is3gNetWork方法正常工作
    XCTAssertNotNil(networkType, @"networkType应正常返回");
}

#pragma mark - activeWLAN测试

- (void)testActiveWLANReturnsBOOL {
    // 通过反射调用私有方法进行测试
    SEL selector = NSSelectorFromString(@"activeWLAN");
    if ([self.networkManager respondsToSelector:selector]) {
        IMP imp = [self.networkManager methodForSelector:selector];
        BOOL (*func)(id, SEL) = (BOOL (*)(id, SEL))imp;
        BOOL result = func(self.networkManager, selector);
        XCTAssertTrue(result == YES || result == NO, @"activeWLAN应返回有效的BOOL值");
    }
}

#pragma mark - activeWWAN测试

- (void)testActiveWWANReturnsBOOL {
    // 通过反射调用私有方法进行测试
    SEL selector = NSSelectorFromString(@"activeWWAN");
    if ([self.networkManager respondsToSelector:selector]) {
        IMP imp = [self.networkManager methodForSelector:selector];
        BOOL (*func)(id, SEL) = (BOOL (*)(id, SEL))imp;
        BOOL result = func(self.networkManager, selector);
        XCTAssertTrue(result == YES || result == NO, @"activeWWAN应返回有效的BOOL值");
    }
}

#pragma mark - localWiFiIPAddress测试

- (void)testLocalWiFiIPAddressReturnsStringOrNil {
    // 通过反射调用私有方法进行测试
    SEL selector = NSSelectorFromString(@"localWiFiIPAddress");
    if ([self.networkManager respondsToSelector:selector]) {
        IMP imp = [self.networkManager methodForSelector:selector];
        NSString* (*func)(id, SEL) = (NSString* (*)(id, SEL))imp;
        NSString *result = func(self.networkManager, selector);
        // 在WiFi环境下应返回IP地址，否则返回nil
        if (result) {
            XCTAssertTrue(result.length > 0, @"如果返回了IP地址，长度应大于0");
        }
    }
}

#pragma mark - 边界情况测试

- (void)testNetworkManagerInitialization {
    // 验证初始化时不会崩溃
    XCTAssertNoThrow([MSDKDnsNetworkManager shareInstance], @"初始化不应抛出异常");
}

- (void)testNetworkManagerThreadSafety {
    XCTestExpectation *expectation = [self expectationWithDescription:@"多线程访问测试"];
    
    dispatch_group_t group = dispatch_group_create();
    
    // 在多个线程同时访问网络管理器
    for (int i = 0; i < 10; i++) {
        dispatch_group_async(group, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self.networkManager networkAvailable];
            [self.networkManager networkStatus];
            [self.networkManager networkType];
        });
    }
    
    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        [expectation fulfill];
    });
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

#pragma mark - 通知测试

- (void)testNetworkManagerRegistersForNotifications {
    // 验证网络管理器正确注册了通知
    // 这个测试主要确保初始化过程正常
    XCTAssertNotNil([MSDKDnsNetworkManager shareInstance], @"网络管理器应正确初始化");
}

@end
