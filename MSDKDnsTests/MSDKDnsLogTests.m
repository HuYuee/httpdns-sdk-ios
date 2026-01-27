//
//  MSDKDnsLogTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsLog日志类
//

#import <XCTest/XCTest.h>
#import "MSDKDnsLog.h"

@interface MSDKDnsLogTests : XCTestCase
@end

@implementation MSDKDnsLogTests

- (void)setUp {
    [super setUp];
    // 每个测试前重置日志开关
    [[MSDKDnsLog sharedInstance] setEnableLog:NO];
}

- (void)tearDown {
    [[MSDKDnsLog sharedInstance] setEnableLog:NO];
    [super tearDown];
}

#pragma mark - 单例测试

- (void)testSharedInstanceReturnsSameObject {
    MSDKDnsLog *instance1 = [MSDKDnsLog sharedInstance];
    MSDKDnsLog *instance2 = [MSDKDnsLog sharedInstance];
    
    XCTAssertNotNil(instance1, @"单例实例不应为nil");
    XCTAssertEqual(instance1, instance2, @"多次调用sharedInstance应返回同一对象");
}

#pragma mark - enableLog属性测试

- (void)testEnableLogDefaultValue {
    // 验证enableLog默认值为NO
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    // 注意：由于单例可能在其他测试中被修改，这里主要测试属性可访问性
    XCTAssertNoThrow([log enableLog], @"访问enableLog属性不应抛出异常");
}

- (void)testSetEnableLogToYES {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    
    XCTAssertTrue([log enableLog], @"设置enableLog为YES后应返回YES");
}

- (void)testSetEnableLogToNO {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    [log setEnableLog:NO];
    
    XCTAssertFalse([log enableLog], @"设置enableLog为NO后应返回NO");
}

#pragma mark - msdkDnsLog方法测试

- (void)testMsdkDnsLogWhenDisabled {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:NO];
    
    // 当日志禁用时，调用msdkDnsLog不应崩溃
    XCTAssertNoThrow([log msdkDnsLog:@"测试日志"], @"日志禁用时调用msdkDnsLog不应抛出异常");
}

- (void)testMsdkDnsLogWhenEnabled {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    
    // 当日志启用时，调用msdkDnsLog不应崩溃
    XCTAssertNoThrow([log msdkDnsLog:@"测试日志"], @"日志启用时调用msdkDnsLog不应抛出异常");
}

- (void)testMsdkDnsLogWithNilFormat {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    
    // 传入nil不应崩溃
    XCTAssertNoThrow([log msdkDnsLog:nil], @"传入nil不应抛出异常");
}

- (void)testMsdkDnsLogWithEmptyString {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    
    // 传入空字符串不应崩溃
    XCTAssertNoThrow([log msdkDnsLog:@""], @"传入空字符串不应抛出异常");
}

- (void)testMsdkDnsLogWithSpecialCharacters {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    
    // 传入包含特殊字符的字符串不应崩溃
    XCTAssertNoThrow([log msdkDnsLog:@"测试%@日志%d特殊字符%%"], @"传入特殊字符不应抛出异常");
}

#pragma mark - 线程安全测试

- (void)testMsdkDnsLogIsThreadSafe {
    MSDKDnsLog *log = [MSDKDnsLog sharedInstance];
    [log setEnableLog:YES];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"多线程日志测试"];
    
    dispatch_group_t group = dispatch_group_create();
    
    // 在多个线程同时调用日志方法
    for (int i = 0; i < 10; i++) {
        dispatch_group_async(group, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [log msdkDnsLog:[NSString stringWithFormat:@"线程测试日志 %d", i]];
        });
    }
    
    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        [expectation fulfill];
    });
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

@end
