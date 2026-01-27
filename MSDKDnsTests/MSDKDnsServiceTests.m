//
//  MSDKDnsServiceTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsService服务类
//  注意：此测试文件只包含快速的单元测试，不会触发真实网络请求
//  涉及网络请求的测试应放在集成测试中单独执行
//

#import <XCTest/XCTest.h>
#import "MSDKDnsService.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"
#import "msdkdns_local_ip_stack.h"

@interface MSDKDnsServiceTests : XCTestCase
@property (nonatomic, strong) MSDKDnsService *service;
@end

@implementation MSDKDnsServiceTests

- (void)setUp {
    [super setUp];
    self.service = [[MSDKDnsService alloc] init];
}

- (void)tearDown {
    self.service = nil;
    [super tearDown];
}

#pragma mark - 初始化测试

- (void)testServiceCanBeInitialized {
    XCTAssertNotNil(self.service, @"MSDKDnsService应能正常初始化");
}

- (void)testServiceCanBeReinitialized {
    MSDKDnsService *service1 = [[MSDKDnsService alloc] init];
    MSDKDnsService *service2 = [[MSDKDnsService alloc] init];
    
    XCTAssertNotNil(service1, @"service1应能正常初始化");
    XCTAssertNotNil(service2, @"service2应能正常初始化");
    XCTAssertNotEqual(service1, service2, @"两个实例不应相同");
}

- (void)testMultipleServiceInstancesAreIndependent {
    MSDKDnsService *service1 = [[MSDKDnsService alloc] init];
    MSDKDnsService *service2 = [[MSDKDnsService alloc] init];
    MSDKDnsService *service3 = [[MSDKDnsService alloc] init];
    
    XCTAssertNotNil(service1, @"service1应能正常初始化");
    XCTAssertNotNil(service2, @"service2应能正常初始化");
    XCTAssertNotNil(service3, @"service3应能正常初始化");
    
    // 验证三个实例都是独立的
    XCTAssertNotEqual(service1, service2, @"service1和service2应是不同实例");
    XCTAssertNotEqual(service2, service3, @"service2和service3应是不同实例");
    XCTAssertNotEqual(service1, service3, @"service1和service3应是不同实例");
}

#pragma mark - 服务实例类型测试

- (void)testServiceIsCorrectClass {
    XCTAssertTrue([self.service isKindOfClass:[MSDKDnsService class]], @"service应是MSDKDnsService类型");
}

- (void)testServiceRespondsToGetHostsByNames {
    // 验证服务响应基本方法（不实际调用）
    SEL selector = @selector(getHostsByNames:timeOut:dnsId:dnsKey:netStack:encryptType:returnIps:);
    XCTAssertTrue([self.service respondsToSelector:selector], @"service应响应getHostsByNames:方法");
}

- (void)testServiceRespondsToGetHttpDNSDomainIPsByNames {
    SEL selector = @selector(getHttpDNSDomainIPsByNames:timeOut:dnsId:dnsKey:netStack:encryptType:httpOnly:from:returnIps:);
    XCTAssertTrue([self.service respondsToSelector:selector], @"service应响应getHttpDNSDomainIPsByNames:方法");
}

- (void)testServiceRespondsToGetHostsByNamesFrom {
    SEL selector = @selector(getHostsByNames:timeOut:dnsId:dnsKey:netStack:encryptType:from:returnIps:);
    XCTAssertTrue([self.service respondsToSelector:selector], @"service应响应getHostsByNames:from:方法");
}

#pragma mark - 网络栈枚举值测试

- (void)testNetStackEnumValues {
    // 验证网络栈枚举值定义正确
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_None, 0, @"MSDKDNS_ELocalIPStack_None应为0");
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_IPv4, 1, @"MSDKDNS_ELocalIPStack_IPv4应为1");
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_IPv6, 2, @"MSDKDNS_ELocalIPStack_IPv6应为2");
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_Dual, 3, @"MSDKDNS_ELocalIPStack_Dual应为3");
}

#pragma mark - 加密类型枚举值测试

- (void)testEncryptTypeEnumValues {
    // 验证加密类型枚举值定义正确
    XCTAssertEqual(HttpDnsEncryptTypeDES, 0, @"HttpDnsEncryptTypeDES应为0");
    XCTAssertEqual(HttpDnsEncryptTypeAES, 1, @"HttpDnsEncryptTypeAES应为1");
    XCTAssertEqual(HttpDnsEncryptTypeHTTPS, 2, @"HttpDnsEncryptTypeHTTPS应为2");
}

@end
