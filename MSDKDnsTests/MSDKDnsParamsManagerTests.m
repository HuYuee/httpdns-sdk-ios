#import <XCTest/XCTest.h>
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"
#import "MSDKDnsPrivate.h"

@interface MSDKDnsParamsManagerTests : XCTestCase
@end

@implementation MSDKDnsParamsManagerTests

- (void)setUp {
    [super setUp];
    [self resetAllFlags];
}

- (void)tearDown {
    [self resetAllFlags];
    [super tearDown];
}

- (void)resetAllFlags {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetPreResolvedDomains:nil];
    [params msdkDnsSetHttpOnly:NO];
    [params msdkDnsSetPersistCacheIPEnabled:NO];
    [params msdkDnsSetExpiredIPEnabled:NO];
    [params msdkDnsSetKeepAliveDomains:nil];
    [params msdkDnsUpdateSceneUseLdns:NO];
    [params msdkDnsUpdateSceneIsRetry:NO];
    [self flushParamQueue];
}

- (void)flushParamQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

- (void)testFeatureFlagsToggleBasedOnConfiguration {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetPreResolvedDomains:@[@"pre.example.com"]];
    [params msdkDnsSetHttpOnly:YES];
    [params msdkDnsSetPersistCacheIPEnabled:YES];
    [params msdkDnsSetExpiredIPEnabled:YES];
    [params msdkDnsSetKeepAliveDomains:@[@"keep.example.com"]];
    [self flushParamQueue];

    uint32_t expected = MSDKDNS_FEATURE_PRE_RESOLVE_DOMAINS |
                        MSDKDNS_FEATURE_HTTP_ONLY |
                        MSDKDNS_FEATURE_PERSIST_CACHE_IP |
                        MSDKDNS_FEATURE_EXPIRED_IP_ENABLED |
                        MSDKDNS_FEATURE_KEEP_ALIVE_DOMAINS;
    XCTAssertEqual([params msdkDnsGetFeatureFlags], expected);

    [params msdkDnsSetPreResolvedDomains:nil];
    [params msdkDnsSetHttpOnly:NO];
    [params msdkDnsSetPersistCacheIPEnabled:NO];
    [params msdkDnsSetExpiredIPEnabled:NO];
    [params msdkDnsSetKeepAliveDomains:nil];
    [self flushParamQueue];
    XCTAssertEqual([params msdkDnsGetFeatureFlags], 0);
}

- (void)testSceneFlagsToggle {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsUpdateSceneUseLdns:YES];
    [params msdkDnsUpdateSceneIsRetry:YES];
    [self flushParamQueue];
    XCTAssertEqual([params msdkDnsGetSceneFlags], MSDKDNS_SCENE_USE_LDNS | MSDKDNS_SCENE_HTTPDNS_RETRY);

    [params msdkDnsUpdateSceneUseLdns:NO];
    [params msdkDnsUpdateSceneIsRetry:NO];
    [self flushParamQueue];
    XCTAssertEqual([params msdkDnsGetSceneFlags], 0);
}

- (void)testTimeoutConversionFallbacks {
    MSDKDnsParamsManager *params = [MSDKDnsParamsManager shareInstance];
    [params msdkDnsSetMAppId:@"app" timeOut:1500 encryptType:HttpDnsEncryptTypeDES];
    XCTAssertEqualWithAccuracy([params msdkDnsGetMTimeOut], 1.5, 0.0001);

    [params msdkDnsSetMAppId:@"app" timeOut:0 encryptType:HttpDnsEncryptTypeDES];
    XCTAssertEqualWithAccuracy([params msdkDnsGetMTimeOut], 2.0, 0.0001);
}

@end
