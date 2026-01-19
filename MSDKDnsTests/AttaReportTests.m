#import <XCTest/XCTest.h>
#import "AttaReport.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"

@interface AttaReport ()
- (NSString *)formatReportParams:(NSDictionary *)params;
- (NSString *)paramsToUrlString:(NSDictionary *)params;
@end

@interface AttaReportTests : XCTestCase
@end

@implementation AttaReportTests

- (void)setUp {
    [super setUp];
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [params msdkDnsSetMDnsId:4321 dnsKey:@"dummy" token:@"token"];
    [params msdkDnsSetMOpenId:@"open-id"];
    [self flushParamQueue];
}

- (void)flushParamQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

- (void)testParamsToUrlStringContainsRequiredKeys {
    AttaReport *report = [AttaReport sharedInstance];
    NSString *query = [report paramsToUrlString:@{ @"eventName": @"UnitTest" }];
    XCTAssertTrue([query containsString:@"attaid="]);
    XCTAssertTrue([query containsString:@"token="]);
    XCTAssertTrue([query containsString:@"eventName=UnitTest"]);
}

- (void)testFormatReportParamsInjectsMetadata {
    AttaReport *report = [AttaReport sharedInstance];
    NSString *payload = [report formatReportParams:@{ @"eventName": @"UnitTest" }];
    XCTAssertTrue([payload containsString:@"eventName=UnitTest"]);
    XCTAssertTrue([payload containsString:@"appId=test-app"]);
    XCTAssertTrue([payload containsString:@"dnsId=4321"]);
}

- (void)testShouldReportDnsSpendRespectsInterval {
    AttaReport *report = [AttaReport sharedInstance];
    [report setValue:@(5) forKey:@"interval"];
    [report setValue:[NSDate dateWithTimeIntervalSinceNow:-10] forKey:@"lastReportTime"];
    BOOL first = [report shoulReportDnsSpend];
    XCTAssertTrue(first);
    BOOL second = [report shoulReportDnsSpend];
    XCTAssertFalse(second);
    [report setValue:[NSDate dateWithTimeIntervalSinceNow:-10] forKey:@"lastReportTime"];
    XCTAssertTrue([report shoulReportDnsSpend]);
}

@end
