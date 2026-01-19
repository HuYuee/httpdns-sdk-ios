#import <XCTest/XCTest.h>
#import "MSDKDnsInfoTool.h"
#import "MSDKDnsParamsManager.h"

@interface MSDKDnsInfoToolTests : XCTestCase
@end

@implementation MSDKDnsInfoToolTests

- (void)setUp {
    [super setUp];
    [self configureRequiredParams];
    [self resetSceneAndFeatureFlags];
}

- (void)tearDown {
    [self resetSceneAndFeatureFlags];
    [super tearDown];
}

- (void)configureRequiredParams {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [params msdkDnsSetMDnsId:1234 dnsKey:@"dummy-key" token:@"token-value"];
    [self flushParamQueue];
}

- (void)resetSceneAndFeatureFlags {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsUpdateSceneUseLdns:NO];
    [params msdkDnsUpdateSceneIsRetry:NO];
    [params msdkDnsSetHttpOnly:NO];
    [params msdkDnsSetPreResolvedDomains:nil];
    [params msdkDnsSetPersistCacheIPEnabled:NO];
    [params msdkDnsSetExpiredIPEnabled:NO];
    [params msdkDnsSetKeepAliveDomains:nil];
    [self flushParamQueue];
}

- (void)flushParamQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

- (void)testHttpsUrlEncodesSceneAndFeatureAsLowercaseHex {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsUpdateSceneUseLdns:YES];
    [params msdkDnsUpdateSceneIsRetry:YES];
    [params msdkDnsSetPreResolvedDomains:@[@"pre.example.com"]];
    [params msdkDnsSetHttpOnly:YES];
    [params msdkDnsSetPersistCacheIPEnabled:YES];
    [params msdkDnsSetExpiredIPEnabled:YES];
    [params msdkDnsSetKeepAliveDomains:@[@"keep.example.com"]];
    [self flushParamQueue];

    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@"example.com"
                                               dnsId:1234
                                              dnsKey:@"dummy-key"
                                              ipType:HttpDnsTypeIPv4
                                         encryptType:HttpDnsEncryptTypeHTTPS];

    XCTAssertNotNil(url);
    NSString *query = url.query;
    XCTAssertNotNil(query);
    XCTAssertTrue([query containsString:@"scene=3"], @"scene flag should be encoded as hex");
    XCTAssertTrue([query containsString:@"feature=1f"], @"feature flags should be encoded as lowercase hex");
}

- (void)testSceneParameterOmittedWhenNoFlagsSet {
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@"example.com"
                                               dnsId:1234
                                              dnsKey:@"dummy-key"
                                              ipType:HttpDnsTypeIPv4
                                         encryptType:HttpDnsEncryptTypeHTTPS];

    XCTAssertNotNil(url);
    NSString *query = url.query;
    XCTAssertNotNil(query);
    XCTAssertFalse([query containsString:@"scene="], @"scene parameter should be omitted when no scene flags are set");
    XCTAssertTrue([query containsString:@"feature=0"], @"feature should default to 0 when no features are enabled");
}

- (void)testGenerateSessionIDProducesStableBase62Value {
    NSString *first = [MSDKDnsInfoTool generateSessionID];
    NSString *second = [MSDKDnsInfoTool generateSessionID];
    XCTAssertNotNil(first);
    XCTAssertEqual(first.length, 12);
    XCTAssertEqualObjects(first, second);
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"];
    for (NSUInteger idx = 0; idx < first.length; idx++) {
        unichar ch = [first characterAtIndex:idx];
        XCTAssertTrue([allowed characterIsMember:ch], @"Session ID should contain only base62 characters");
    }
}

- (void)testGetIPsStringFromArrayFormatsCommaSeparatedList {
    NSString *result = [MSDKDnsInfoTool getIPsStringFromIPsArray:@[@"1.1.1.1", @"2.2.2.2", @"3.3.3.3"]];
    XCTAssertEqualObjects(result, @"1.1.1.1,2.2.2.2,3.3.3.3");
}

- (void)testIsExistValidatesNonEmptyStrings {
    XCTAssertTrue([MSDKDnsInfoTool isExist:@"value"]);
    XCTAssertFalse([MSDKDnsInfoTool isExist:@""]);
    XCTAssertFalse([MSDKDnsInfoTool isExist:nil]);
}

@end
