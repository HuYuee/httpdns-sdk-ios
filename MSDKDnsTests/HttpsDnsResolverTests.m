#import <XCTest/XCTest.h>
#import "HttpsDnsResolver.h"
#import "MSDKDnsPrivate.h"

@interface HttpsDnsResolver (Testing)
- (NSDictionary *)parseResultString:(NSString *)string;
- (NSDictionary *)parseAllIPString:(NSString *)ipString;
@end

@interface HttpsDnsResolverTests : XCTestCase
@end

@implementation HttpsDnsResolverTests

- (void)testParseResultStringParsesSingleDomainLine {
    HttpsDnsResolver *resolver = [[HttpsDnsResolver alloc] init];
    [resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSDictionary *results = [resolver parseResultString:@"api.example.com:1.1.1.1;2.2.2.2,60|10.0.0.1"];
    NSDictionary *domainInfo = results[@"api.example.com"];
    XCTAssertNotNil(domainInfo);
    NSArray *ips = domainInfo[kIP];
    XCTAssertEqualObjects(ips.firstObject, @"1.1.1.1");
    XCTAssertEqualObjects(domainInfo[kTTL], @"60");
}

- (void)testParseResultStringTrimsTrailingDotFromDomain {
    HttpsDnsResolver *resolver = [[HttpsDnsResolver alloc] init];
    [resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSDictionary *results = [resolver parseResultString:@"api.example.com.:3.3.3.3,30|10.0.0.2"];
    XCTAssertNotNil(results[@"api.example.com"]);
}

- (void)testParseAllIPStringDualStackProducesBothFamilies {
    HttpsDnsResolver *resolver = [[HttpsDnsResolver alloc] init];
    [resolver setValue:@(HttpDnsTypeDual) forKey:@"ipType"];
    NSString *payload = @"1.1.1.1;2.2.2.2,60-2001::1;2001::2,120|10.0.0.1";
    NSDictionary *both = [resolver parseAllIPString:payload];
    XCTAssertNotNil(both[@"ipv4"]);
    XCTAssertNotNil(both[@"ipv6"]);
}

@end
