//
//  MSDKDnsDBTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsDB数据库类
//

#import <XCTest/XCTest.h>
#import "MSDKDnsDB.h"
#import "MSDKDnsPrivate.h"

@interface MSDKDnsDBTests : XCTestCase
@end

@implementation MSDKDnsDBTests

- (void)setUp {
    [super setUp];
    // 每个测试前清空数据库
    [[MSDKDnsDB shareInstance] deleteAllData];
}

- (void)tearDown {
    // 清理测试数据
    [[MSDKDnsDB shareInstance] deleteAllData];
    [super tearDown];
}

#pragma mark - 单例测试

- (void)testShareInstanceReturnsSameObject {
    MSDKDnsDB *instance1 = [MSDKDnsDB shareInstance];
    MSDKDnsDB *instance2 = [MSDKDnsDB shareInstance];
    
    XCTAssertNotNil(instance1, @"数据库单例不应为nil");
    XCTAssertEqual(instance1, instance2, @"多次调用shareInstance应返回同一对象");
}

#pragma mark - 插入和查询测试

- (void)testInsertAndRetrieveDomainInfo {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 创建测试数据
    NSDictionary *ipv4Info = @{
        kChannel: @"httpdns",
        kClientIP: @"1.2.3.4",
        kIP: @[@"10.0.0.1", @"10.0.0.2"],
        kDnsTimeConsuming: @"50",
        kTTL: @"300",
        kTTLExpired: @"1700000000"
    };
    
    NSDictionary *ipv6Info = @{
        kChannel: @"httpdns",
        kClientIP: @"::1",
        kIP: @[@"2001:db8::1"],
        kDnsTimeConsuming: @"60",
        kTTL: @"300",
        kTTLExpired: @"1700000000"
    };
    
    NSDictionary *domainInfo = @{
        kMSDKHttpDnsCache_A: ipv4Info,
        kMSDKHttpDnsCache_4A: ipv6Info
    };
    
    // 插入数据
    [db insertOrReplaceDomainInfo:domainInfo domain:@"test.example.com"];
    
    // 查询数据
    NSDictionary *result = [db getDataFromDB];
    
    XCTAssertNotNil(result, @"查询结果不应为nil");
    XCTAssertNotNil(result[@"test.example.com"], @"应能查询到插入的域名");
    
    NSDictionary *retrievedInfo = result[@"test.example.com"];
    NSDictionary *retrievedIPv4 = retrievedInfo[kMSDKHttpDnsCache_A];
    
    XCTAssertNotNil(retrievedIPv4, @"IPv4信息不应为nil");
    XCTAssertEqualObjects(retrievedIPv4[kChannel], @"httpdns", @"Channel应匹配");
    XCTAssertEqualObjects(retrievedIPv4[kClientIP], @"1.2.3.4", @"ClientIP应匹配");
}

- (void)testInsertOrReplaceUpdatesExistingRecord {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 第一次插入
    NSDictionary *ipv4Info1 = @{
        kChannel: @"httpdns",
        kClientIP: @"1.2.3.4",
        kIP: @[@"10.0.0.1"],
        kDnsTimeConsuming: @"50",
        kTTL: @"300",
        kTTLExpired: @"1700000000"
    };
    
    NSDictionary *domainInfo1 = @{
        kMSDKHttpDnsCache_A: ipv4Info1,
        kMSDKHttpDnsCache_4A: @{}
    };
    
    [db insertOrReplaceDomainInfo:domainInfo1 domain:@"replace.example.com"];
    
    // 第二次插入（相同域名，不同数据）
    NSDictionary *ipv4Info2 = @{
        kChannel: @"httpdns",
        kClientIP: @"5.6.7.8",
        kIP: @[@"20.0.0.1"],
        kDnsTimeConsuming: @"100",
        kTTL: @"600",
        kTTLExpired: @"1800000000"
    };
    
    NSDictionary *domainInfo2 = @{
        kMSDKHttpDnsCache_A: ipv4Info2,
        kMSDKHttpDnsCache_4A: @{}
    };
    
    [db insertOrReplaceDomainInfo:domainInfo2 domain:@"replace.example.com"];
    
    // 查询验证数据已更新
    NSDictionary *result = [db getDataFromDB];
    NSDictionary *retrievedInfo = result[@"replace.example.com"];
    NSDictionary *retrievedIPv4 = retrievedInfo[kMSDKHttpDnsCache_A];
    
    XCTAssertEqualObjects(retrievedIPv4[kClientIP], @"5.6.7.8", @"数据应被更新为新值");
    XCTAssertEqualObjects(retrievedIPv4[kTTL], @"600", @"TTL应被更新为新值");
}

#pragma mark - 删除测试

- (void)testDeleteDBDataRemovesSpecificDomains {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 插入多条测试数据
    NSDictionary *domainInfo = @{
        kMSDKHttpDnsCache_A: @{
            kChannel: @"httpdns",
            kIP: @[@"10.0.0.1"]
        },
        kMSDKHttpDnsCache_4A: @{}
    };
    
    [db insertOrReplaceDomainInfo:domainInfo domain:@"delete1.example.com"];
    [db insertOrReplaceDomainInfo:domainInfo domain:@"delete2.example.com"];
    [db insertOrReplaceDomainInfo:domainInfo domain:@"keep.example.com"];
    
    // 删除部分数据
    [db deleteDBData:@[@"delete1.example.com", @"delete2.example.com"]];
    
    // 验证删除结果
    NSDictionary *result = [db getDataFromDB];
    
    XCTAssertNil(result[@"delete1.example.com"], @"delete1应被删除");
    XCTAssertNil(result[@"delete2.example.com"], @"delete2应被删除");
    XCTAssertNotNil(result[@"keep.example.com"], @"keep应保留");
}

- (void)testDeleteAllDataClearsDatabase {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 插入测试数据
    NSDictionary *domainInfo = @{
        kMSDKHttpDnsCache_A: @{
            kChannel: @"httpdns",
            kIP: @[@"10.0.0.1"]
        },
        kMSDKHttpDnsCache_4A: @{}
    };
    
    [db insertOrReplaceDomainInfo:domainInfo domain:@"all1.example.com"];
    [db insertOrReplaceDomainInfo:domainInfo domain:@"all2.example.com"];
    
    // 删除所有数据
    [db deleteAllData];
    
    // 验证数据库为空
    NSDictionary *result = [db getDataFromDB];
    
    XCTAssertEqual(result.count, 0, @"删除所有数据后数据库应为空");
}

#pragma mark - 边界情况测试

- (void)testInsertWithEmptyDomainInfo {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 插入空的域名信息
    NSDictionary *emptyInfo = @{
        kMSDKHttpDnsCache_A: @{},
        kMSDKHttpDnsCache_4A: @{}
    };
    
    // 不应崩溃
    XCTAssertNoThrow([db insertOrReplaceDomainInfo:emptyInfo domain:@"empty.example.com"], @"插入空信息不应崩溃");
}

- (void)testInsertWithNilValues {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 创建包含部分数据的信息（不包含所有key）
    NSDictionary *partialInfo = @{
        kMSDKHttpDnsCache_A: @{
            kIP: @[@"10.0.0.1"]
        },
        kMSDKHttpDnsCache_4A: @{}
    };
    
    // 不应崩溃
    XCTAssertNoThrow([db insertOrReplaceDomainInfo:partialInfo domain:@"partial.example.com"], @"插入部分信息不应崩溃");
}

- (void)testGetDataFromDBWhenEmpty {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 确保数据库为空
    [db deleteAllData];
    
    // 查询空数据库
    NSDictionary *result = [db getDataFromDB];
    
    XCTAssertNotNil(result, @"空数据库查询结果不应为nil");
    XCTAssertEqual(result.count, 0, @"空数据库查询结果应为空字典");
}

- (void)testDeleteDBDataWithEmptyArray {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    // 插入测试数据
    NSDictionary *domainInfo = @{
        kMSDKHttpDnsCache_A: @{kIP: @[@"10.0.0.1"]},
        kMSDKHttpDnsCache_4A: @{}
    };
    [db insertOrReplaceDomainInfo:domainInfo domain:@"nodelete.example.com"];
    
    // 删除空数组不应崩溃
    XCTAssertNoThrow([db deleteDBData:@[]], @"删除空数组不应崩溃");
    
    // 数据应该还在
    NSDictionary *result = [db getDataFromDB];
    XCTAssertNotNil(result[@"nodelete.example.com"], @"数据不应被删除");
}

#pragma mark - IPv6数据测试

- (void)testInsertAndRetrieveIPv6Info {
    MSDKDnsDB *db = [MSDKDnsDB shareInstance];
    
    NSDictionary *ipv6Info = @{
        kChannel: @"httpdns",
        kClientIP: @"2001:db8::1",
        kIP: @[@"2001:db8::100", @"2001:db8::200"],
        kDnsTimeConsuming: @"80",
        kTTL: @"600",
        kTTLExpired: @"1700000000"
    };
    
    NSDictionary *domainInfo = @{
        kMSDKHttpDnsCache_A: @{},
        kMSDKHttpDnsCache_4A: ipv6Info
    };
    
    [db insertOrReplaceDomainInfo:domainInfo domain:@"ipv6.example.com"];
    
    NSDictionary *result = [db getDataFromDB];
    NSDictionary *retrievedInfo = result[@"ipv6.example.com"];
    NSDictionary *retrievedIPv6 = retrievedInfo[kMSDKHttpDnsCache_4A];
    
    XCTAssertNotNil(retrievedIPv6, @"IPv6信息不应为nil");
    XCTAssertEqualObjects(retrievedIPv6[kClientIP], @"2001:db8::1", @"IPv6 ClientIP应匹配");
}

@end
