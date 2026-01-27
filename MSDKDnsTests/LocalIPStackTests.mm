//
//  LocalIPStackTests.m
//  MSDKDnsTests
//
//  测试msdkdns_local_ip_stack网络栈检测
//

#import <XCTest/XCTest.h>
#import "msdkdns_local_ip_stack.h"

@interface LocalIPStackTests : XCTestCase
@end

@implementation LocalIPStackTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

#pragma mark - 枚举值测试

- (void)testIPStackEnumValues {
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_None, 0, @"None应为0");
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_IPv4, 1, @"IPv4应为1");
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_IPv6, 2, @"IPv6应为2");
    XCTAssertEqual(msdkdns::MSDKDNS_ELocalIPStack_Dual, 3, @"Dual应为3 (IPv4 | IPv6)");
}

#pragma mark - msdkdns_detect_local_ip_stack测试

- (void)testDetectLocalIPStackReturnsValidValue {
    msdkdns::MSDKDNS_TLocalIPStack stack = msdkdns::msdkdns_detect_local_ip_stack();
    
    // 返回值应该是有效的枚举值
    XCTAssertTrue(stack >= msdkdns::MSDKDNS_ELocalIPStack_None &&
                  stack <= msdkdns::MSDKDNS_ELocalIPStack_Dual,
                  @"返回值应在有效范围内: %d", stack);
}

- (void)testDetectLocalIPStackIsConsistent {
    // 多次调用应返回一致的结果（短时间内网络状态不变）
    msdkdns::MSDKDNS_TLocalIPStack stack1 = msdkdns::msdkdns_detect_local_ip_stack();
    msdkdns::MSDKDNS_TLocalIPStack stack2 = msdkdns::msdkdns_detect_local_ip_stack();
    
    XCTAssertEqual(stack1, stack2, @"短时间内多次检测应返回相同结果");
}

- (void)testDetectLocalIPStackHasIPv4OrIPv6 {
    msdkdns::MSDKDNS_TLocalIPStack stack = msdkdns::msdkdns_detect_local_ip_stack();
    
    // 在模拟器环境下，至少应该有IPv4
    // 但在某些网络环境下可能没有网络，所以只验证返回值有效
    if (stack != msdkdns::MSDKDNS_ELocalIPStack_None) {
        BOOL hasIPv4 = (stack & msdkdns::MSDKDNS_ELocalIPStack_IPv4) != 0;
        BOOL hasIPv6 = (stack & msdkdns::MSDKDNS_ELocalIPStack_IPv6) != 0;
        
        XCTAssertTrue(hasIPv4 || hasIPv6, @"有网络时应至少有IPv4或IPv6");
    }
}

#pragma mark - 位运算测试

- (void)testIPStackBitOperations {
    // 测试双栈是IPv4和IPv6的组合
    msdkdns::MSDKDNS_TLocalIPStack dual = msdkdns::MSDKDNS_ELocalIPStack_Dual;
    
    XCTAssertTrue((dual & msdkdns::MSDKDNS_ELocalIPStack_IPv4) != 0, @"双栈应包含IPv4");
    XCTAssertTrue((dual & msdkdns::MSDKDNS_ELocalIPStack_IPv6) != 0, @"双栈应包含IPv6");
    
    // 验证IPv4 | IPv6 = Dual
    msdkdns::MSDKDNS_TLocalIPStack combined = (msdkdns::MSDKDNS_TLocalIPStack)(msdkdns::MSDKDNS_ELocalIPStack_IPv4 | msdkdns::MSDKDNS_ELocalIPStack_IPv6);
    XCTAssertEqual(combined, msdkdns::MSDKDNS_ELocalIPStack_Dual, @"IPv4 | IPv6 应等于 Dual");
}

- (void)testIPStackNoneHasNoNetwork {
    msdkdns::MSDKDNS_TLocalIPStack none = msdkdns::MSDKDNS_ELocalIPStack_None;
    
    XCTAssertEqual((none & msdkdns::MSDKDNS_ELocalIPStack_IPv4), 0, @"None不应包含IPv4");
    XCTAssertEqual((none & msdkdns::MSDKDNS_ELocalIPStack_IPv6), 0, @"None不应包含IPv6");
}

#pragma mark - sockaddr_union测试

- (void)testSockaddrUnionSize {
    // 验证联合体大小足够容纳所有类型
    XCTAssertTrue(sizeof(msdkdns::msdkdns_sockaddr_union) >= sizeof(struct sockaddr_in), @"联合体应能容纳sockaddr_in");
    XCTAssertTrue(sizeof(msdkdns::msdkdns_sockaddr_union) >= sizeof(struct sockaddr_in6), @"联合体应能容纳sockaddr_in6");
}

#pragma mark - 性能测试

- (void)testDetectLocalIPStackPerformance {
    // 测试检测性能
    [self measureBlock:^{
        for (int i = 0; i < 10; i++) {
            msdkdns::msdkdns_detect_local_ip_stack();
        }
    }];
}

@end
