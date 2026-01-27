//
//  MSDKDnsTCPSpeedTesterTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsTCPSpeedTester测速类
//  注意：此测试文件只包含快速的单元测试，不包含实际网络测速测试
//  实际网络测速测试应放在性能测试中单独执行
//

#import <XCTest/XCTest.h>
#import "MSDKDnsTCPSpeedTester.h"
#import "MSDKDnsParamsManager.h"

@interface MSDKDnsTCPSpeedTesterTests : XCTestCase
@property (nonatomic, strong) MSDKDnsTCPSpeedTester *speedTester;
@end

@implementation MSDKDnsTCPSpeedTesterTests

- (void)setUp {
    [super setUp];
    self.speedTester = [[MSDKDnsTCPSpeedTester alloc] init];
}

- (void)tearDown {
    self.speedTester = nil;
    [super tearDown];
}

#pragma mark - 初始化测试

- (void)testSpeedTesterCanBeInitialized {
    XCTAssertNotNil(self.speedTester, @"MSDKDnsTCPSpeedTester应能正常初始化");
}

- (void)testSpeedTesterCanBeReinitialized {
    MSDKDnsTCPSpeedTester *tester1 = [[MSDKDnsTCPSpeedTester alloc] init];
    MSDKDnsTCPSpeedTester *tester2 = [[MSDKDnsTCPSpeedTester alloc] init];
    
    XCTAssertNotNil(tester1, @"tester1应能正常初始化");
    XCTAssertNotNil(tester2, @"tester2应能正常初始化");
    XCTAssertNotEqual(tester1, tester2, @"两个实例不应相同");
}

#pragma mark - ipRankingWithIPs参数验证测试（快速，不涉及网络）

- (void)testIpRankingWithNilIPs {
    NSArray *result = [self.speedTester ipRankingWithIPs:nil host:@"test.example.com"];
    
    XCTAssertNil(result, @"传入nil IPs应返回nil");
}

- (void)testIpRankingWithNilHost {
    NSArray *ips = @[@"10.0.0.1", @"20.0.0.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:nil];
    
    XCTAssertNil(result, @"传入nil host应返回nil");
}

- (void)testIpRankingWithEmptyIPs {
    NSArray *result = [self.speedTester ipRankingWithIPs:@[] host:@"test.example.com"];
    
    XCTAssertNil(result, @"传入空IPs数组应返回nil");
}

- (void)testIpRankingWithSingleIP {
    // IP池小于2个应返回nil
    NSArray *ips = @[@"10.0.0.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"test.example.com"];
    
    XCTAssertNil(result, @"单个IP应返回nil");
}

- (void)testIpRankingWithTooManyIPs {
    // IP池大于9个应返回nil
    NSArray *ips = @[@"10.0.0.1", @"20.0.0.1", @"250.108.128.100", @"10.0.0.1", @"10.0.0.2", 
                     @"10.0.0.3", @"10.0.0.4", @"10.0.0.5", @"10.0.0.6", @"10.0.0.7"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"test.example.com"];
    
    XCTAssertNil(result, @"超过9个IP应返回nil");
}

- (void)testIpRankingWithHostNotInConfig {
    // 当host不在IPRankData配置中时应返回nil
    NSArray *ips = @[@"10.0.0.1", @"20.0.0.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"notconfigured.example.com"];
    
    XCTAssertNil(result, @"未配置的host应返回nil");
}

- (void)testIpRankingWithEmptyIPRankData {
    // 清空IPRankData
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:@{}];
    
    NSArray *ips = @[@"10.0.0.1", @"20.0.0.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"test.example.com"];
    
    XCTAssertNil(result, @"空IPRankData应返回nil");
}

- (void)testIpRankingWithNilIPRankData {
    // 设置nil IPRankData
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:nil];
    
    NSArray *ips = @[@"10.0.0.1", @"20.0.0.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"test.example.com"];
    
    XCTAssertNil(result, @"nil IPRankData应返回nil");
}

#pragma mark - 边界条件测试（快速，不涉及网络）

- (void)testIpRankingWithExactlyTenIPs {
    // IP池正好10个（超过最大值9）
    NSArray *ips = @[@"10.0.0.1", @"10.0.0.2", @"10.0.0.3", @"10.0.0.4", @"10.0.0.5",
                     @"10.0.0.6", @"10.0.0.7", @"10.0.0.8", @"10.0.0.9", @"192.168.1.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"test.example.com"];
    
    XCTAssertNil(result, @"10个IP应返回nil");
}

- (void)testIpRankingWithDuplicateIPs {
    // 测试重复IP
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:@{@"dup.example.com": @80}];
    
    NSArray *ips = @[@"10.0.0.1", @"10.0.0.1", @"10.0.0.1"];
    NSArray *result = [self.speedTester ipRankingWithIPs:ips host:@"dup.example.com"];
    
    // 重复IP的情况，主要测试不崩溃
    // 结果可能是nil（测速失败）或重复的数组
    XCTAssertTrue(result == nil || [result isKindOfClass:[NSArray class]], @"重复IP结果应为nil或数组");
    
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:nil];
}

#pragma mark - IPRankData配置测试

- (void)testSetIPRankDataWithValidConfig {
    NSDictionary *config = @{@"example.com": @80, @"example2.com": @443};
    
    XCTAssertNoThrow([[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:config], @"设置有效配置不应崩溃");
}

- (void)testSetIPRankDataWithZeroPort {
    NSDictionary *config = @{@"example.com": @0};
    
    XCTAssertNoThrow([[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:config], @"设置0端口不应崩溃");
}

- (void)testSetIPRankDataWithNegativePort {
    NSDictionary *config = @{@"example.com": @(-1)};
    
    XCTAssertNoThrow([[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:config], @"设置负端口不应崩溃");
}

- (void)testSetIPRankDataWithLargePort {
    NSDictionary *config = @{@"example.com": @65535};
    
    XCTAssertNoThrow([[MSDKDnsParamsManager shareInstance] msdkDnsSetIPRankData:config], @"设置大端口不应崩溃");
}

#pragma mark - 超时常量测试

- (void)testTimeoutConstants {
    // 验证超时常量定义
    XCTAssertEqual(MSDKDNS_SOCKET_CONNECT_TIMEOUT, 10, @"连接超时应为10秒");
    XCTAssertEqual(MSDKDNS_SOCKET_CONNECT_TIMEOUT_RTT, 600000, @"RTT超时应为600000毫秒");
}

@end
