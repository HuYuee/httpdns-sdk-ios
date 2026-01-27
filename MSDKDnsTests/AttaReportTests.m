#import <XCTest/XCTest.h>
#import "AttaReport.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"
#import "MSDKDnsNetworkManager.h"

@interface AttaReport ()
- (NSString *)formatReportParams:(NSDictionary *)params;
- (NSString *)paramsToUrlString:(NSDictionary *)params;
+ (NSString *)getOperatorsType;
@end

@interface AttaReportTests : XCTestCase
@property (nonatomic, strong) AttaReport *report;
@end

@implementation AttaReportTests

- (void)setUp {
    [super setUp];
    self.report = [AttaReport sharedInstance];
    
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [params msdkDnsSetMDnsId:4321 dnsKey:@"dummy" token:@"token"];
    [params msdkDnsSetMOpenId:@"open-id"];
    [self flushParamQueue];
}

- (void)tearDown {
    self.report = nil;
    [super tearDown];
}

- (void)flushParamQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

#pragma mark - 单例测试

- (void)testSharedInstanceReturnsSameObject {
    AttaReport *instance1 = [AttaReport sharedInstance];
    AttaReport *instance2 = [AttaReport sharedInstance];
    
    XCTAssertNotNil(instance1, @"AttaReport单例不应为nil");
    XCTAssertEqual(instance1, instance2, @"多次调用sharedInstance应返回同一对象");
}

#pragma mark - paramsToUrlString测试

- (void)testParamsToUrlStringContainsRequiredKeys {
    NSString *query = [self.report paramsToUrlString:@{ @"eventName": @"UnitTest" }];
    XCTAssertTrue([query containsString:@"attaid="]);
    XCTAssertTrue([query containsString:@"token="]);
    XCTAssertTrue([query containsString:@"eventName=UnitTest"]);
}

- (void)testParamsToUrlStringWithNilParams {
    NSString *query = [self.report paramsToUrlString:nil];
    
    XCTAssertNotNil(query, @"nil参数应返回非nil字符串");
    XCTAssertTrue([query containsString:@"attaid="], @"应包含attaid");
    XCTAssertTrue([query containsString:@"token="], @"应包含token");
}

- (void)testParamsToUrlStringWithEmptyParams {
    NSString *query = [self.report paramsToUrlString:@{}];
    
    XCTAssertNotNil(query, @"空参数应返回非nil字符串");
    XCTAssertTrue([query containsString:@"attaid="], @"应包含attaid");
}

- (void)testParamsToUrlStringWithMultipleParams {
    NSDictionary *params = @{
        @"param1": @"value1",
        @"param2": @"value2",
        @"param3": @123
    };
    NSString *query = [self.report paramsToUrlString:params];
    
    XCTAssertTrue([query containsString:@"param1=value1"], @"应包含param1");
    XCTAssertTrue([query containsString:@"param2=value2"], @"应包含param2");
    XCTAssertTrue([query containsString:@"param3=123"], @"应包含param3");
}

#pragma mark - formatReportParams测试

- (void)testFormatReportParamsInjectsMetadata {
    NSString *payload = [self.report formatReportParams:@{ @"eventName": @"UnitTest" }];
    XCTAssertTrue([payload containsString:@"eventName=UnitTest"]);
    XCTAssertTrue([payload containsString:@"appId=test-app"]);
    XCTAssertTrue([payload containsString:@"dnsId=4321"]);
}

- (void)testFormatReportParamsContainsAllRequiredFields {
    NSString *payload = [self.report formatReportParams:@{ @"eventName": @"TestEvent" }];
    
    // 验证必要字段
    XCTAssertTrue([payload containsString:@"carrier="], @"应包含运营商信息");
    XCTAssertTrue([payload containsString:@"networkType="], @"应包含网络类型");
    XCTAssertTrue([payload containsString:@"dnsId="], @"应包含dnsId");
    XCTAssertTrue([payload containsString:@"appId="], @"应包含appId");
    XCTAssertTrue([payload containsString:@"encryptType="], @"应包含加密类型");
    XCTAssertTrue([payload containsString:@"eventTime="], @"应包含事件时间");
    XCTAssertTrue([payload containsString:@"deviceName="], @"应包含设备名称");
    XCTAssertTrue([payload containsString:@"systemName="], @"应包含系统名称");
    XCTAssertTrue([payload containsString:@"systemVersion="], @"应包含系统版本");
    XCTAssertTrue([payload containsString:@"sdkVersion="], @"应包含SDK版本");
    XCTAssertTrue([payload containsString:@"sessionId="], @"应包含会话ID");
}

- (void)testFormatReportParamsWithDifferentEncryptTypes {
    // 测试不同加密类型的格式化
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeDES];
    [self flushParamQueue];
    
    NSString *payloadDES = [self.report formatReportParams:@{ @"eventName": @"TestDES" }];
    XCTAssertTrue([payloadDES containsString:@"encryptType=DesHttp"], @"DES加密应显示DesHttp");
    
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeAES];
    [self flushParamQueue];
    
    NSString *payloadAES = [self.report formatReportParams:@{ @"eventName": @"TestAES" }];
    XCTAssertTrue([payloadAES containsString:@"encryptType=AesHttp"], @"AES加密应显示AesHttp");
    
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushParamQueue];
    
    NSString *payloadHTTPS = [self.report formatReportParams:@{ @"eventName": @"TestHTTPS" }];
    XCTAssertTrue([payloadHTTPS containsString:@"encryptType=Https"], @"HTTPS加密应显示Https");
}

#pragma mark - shoulReportDnsSpend测试

- (void)testShouldReportDnsSpendRespectsInterval {
    [self.report setValue:@(5) forKey:@"interval"];
    [self.report setValue:[NSDate dateWithTimeIntervalSinceNow:-10] forKey:@"lastReportTime"];
    BOOL first = [self.report shoulReportDnsSpend];
    XCTAssertTrue(first);
    BOOL second = [self.report shoulReportDnsSpend];
    XCTAssertFalse(second);
    [self.report setValue:[NSDate dateWithTimeIntervalSinceNow:-10] forKey:@"lastReportTime"];
    XCTAssertTrue([self.report shoulReportDnsSpend]);
}

- (void)testShouldReportDnsSpendReturnsFalseWhenIntervalNotPassed {
    [self.report setValue:@(60) forKey:@"interval"];  // 60秒间隔
    [self.report setValue:[NSDate date] forKey:@"lastReportTime"];  // 刚刚上报过
    
    BOOL shouldReport = [self.report shoulReportDnsSpend];
    
    XCTAssertFalse(shouldReport, @"间隔未过时不应上报");
}

- (void)testShouldReportDnsSpendUpdatesLastReportTime {
    [self.report setValue:@(1) forKey:@"interval"];
    [self.report setValue:[NSDate dateWithTimeIntervalSinceNow:-10] forKey:@"lastReportTime"];
    
    NSDate *oldTime = [self.report valueForKey:@"lastReportTime"];
    [self.report shoulReportDnsSpend];
    NSDate *newTime = [self.report valueForKey:@"lastReportTime"];
    
    XCTAssertTrue([newTime timeIntervalSinceDate:oldTime] > 0, @"上报后应更新lastReportTime");
}

#pragma mark - getOperatorsType测试

- (void)testGetOperatorsTypeReturnsValidString {
    NSString *operatorType = [AttaReport getOperatorsType];
    
    XCTAssertNotNil(operatorType, @"运营商类型不应为nil");
    XCTAssertTrue(operatorType.length > 0, @"运营商类型应为非空字符串");
}

#pragma mark - reportEvent测试

- (void)testReportEventDoesNotCrash {
    NSDictionary *params = @{
        @"eventName": @"TestEvent",
        @"testKey": @"testValue"
    };
    
    // 主要测试方法不崩溃
    XCTAssertNoThrow([self.report reportEvent:params], @"reportEvent不应抛出异常");
}

- (void)testReportEventWithEmptyParams {
    // 空参数不应崩溃
    XCTAssertNoThrow([self.report reportEvent:@{}], @"空参数reportEvent不应抛出异常");
}

#pragma mark - 边界条件测试

- (void)testFormatReportParamsWithSpecialCharacters {
    NSDictionary *params = @{
        @"eventName": @"Test&Event=Special",
        @"message": @"包含中文和特殊字符!@#$%"
    };
    
    // 不应崩溃
    XCTAssertNoThrow([self.report formatReportParams:params], @"特殊字符不应导致崩溃");
}

- (void)testMultipleConsecutiveReportCalls {
    // 测试连续多次调用
    for (int i = 0; i < 5; i++) {
        NSDictionary *params = @{
            @"eventName": [NSString stringWithFormat:@"Event%d", i]
        };
        XCTAssertNoThrow([self.report reportEvent:params], @"连续上报不应崩溃");
    }
}

@end
