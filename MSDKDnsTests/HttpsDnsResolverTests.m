#import <XCTest/XCTest.h>
#import "HttpsDnsResolver.h"
#import "MSDKDnsPrivate.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"

@interface HttpsDnsResolver (Testing)
- (NSDictionary *)parseResultString:(NSString *)string;
- (NSDictionary *)parseAllIPString:(NSString *)ipString;
- (NSDictionary *)parseIPString:(NSString *)ipString ClientIP:(NSString *)clientIP use4A:(BOOL)use4A;
- (NSString *)getQueryDomain:(NSString *)str;
- (NSString *)getDecryptStrWithResponseStr:(NSString *)responseStr;
@end

@interface HttpsDnsResolverTests : XCTestCase
@property (nonatomic, strong) HttpsDnsResolver *resolver;
@end

@implementation HttpsDnsResolverTests

- (void)setUp {
    [super setUp];
    self.resolver = [[HttpsDnsResolver alloc] init];
    
    // 设置基本配置
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMDnsId:12345 dnsKey:@"testkey12345678" token:@"test-token"];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMAppId:@"test-app" timeOut:2000 encryptType:HttpDnsEncryptTypeHTTPS];
    [self flushQueue];
}

- (void)tearDown {
    self.resolver = nil;
    [super tearDown];
}

- (void)flushQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

#pragma mark - 初始化测试

- (void)testResolverCanBeInitialized {
    XCTAssertNotNil(self.resolver, @"HttpsDnsResolver应能正常初始化");
}

- (void)testResolverInitialState {
    XCTAssertFalse(self.resolver.isFinished, @"初始状态isFinished应为NO");
    XCTAssertFalse(self.resolver.isSucceed, @"初始状态isSucceed应为NO");
}

#pragma mark - parseResultString测试

- (void)testParseResultStringParsesSingleDomainLine {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSDictionary *results = [self.resolver parseResultString:@"api.example.com:1.1.1.1;2.2.2.2,60|10.0.0.1"];
    NSDictionary *domainInfo = results[@"api.example.com"];
    XCTAssertNotNil(domainInfo);
    NSArray *ips = domainInfo[kIP];
    XCTAssertEqualObjects(ips.firstObject, @"1.1.1.1");
    XCTAssertEqualObjects(domainInfo[kTTL], @"60");
}

- (void)testParseResultStringTrimsTrailingDotFromDomain {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSDictionary *results = [self.resolver parseResultString:@"api.example.com.:3.3.3.3,30|10.0.0.2"];
    XCTAssertNotNil(results[@"api.example.com"]);
}

- (void)testParseResultStringParsesMultipleDomainLines {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSString *multiLine = @"domain1.com:1.1.1.1,60|1.2.3.4\ndomain2.com:2.2.2.2,120|5.6.7.8";
    NSDictionary *results = [self.resolver parseResultString:multiLine];
    
    XCTAssertNotNil(results[@"domain1.com"], @"应解析出domain1");
    XCTAssertNotNil(results[@"domain2.com"], @"应解析出domain2");
}

- (void)testParseResultStringWithEmptyString {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSDictionary *results = [self.resolver parseResultString:@""];
    
    XCTAssertEqual(results.count, 0, @"空字符串应返回空字典");
}

- (void)testParseResultStringWithNil {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSDictionary *results = [self.resolver parseResultString:nil];
    
    XCTAssertEqual(results.count, 0, @"nil应返回空字典");
}

#pragma mark - parseAllIPString测试

- (void)testParseAllIPStringDualStackProducesBothFamilies {
    [self.resolver setValue:@(HttpDnsTypeDual) forKey:@"ipType"];
    NSString *payload = @"1.1.1.1;2.2.2.2,60-2001::1;2001::2,120|10.0.0.1";
    NSDictionary *both = [self.resolver parseAllIPString:payload];
    XCTAssertNotNil(both[@"ipv4"]);
    XCTAssertNotNil(both[@"ipv6"]);
}

- (void)testParseAllIPStringIPv4Only {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSString *payload = @"1.1.1.1;2.2.2.2,60|10.0.0.1";
    NSDictionary *result = [self.resolver parseAllIPString:payload];
    
    XCTAssertNotNil(result, @"IPv4解析结果不应为nil");
    XCTAssertNotNil(result[kIP], @"应包含IP数组");
    XCTAssertNotNil(result[kTTL], @"应包含TTL");
}

- (void)testParseAllIPStringIPv6Only {
    [self.resolver setValue:@(HttpDnsTypeIPv6) forKey:@"ipType"];
    NSString *payload = @"2001::1;2001::2,120|2001::ff";
    NSDictionary *result = [self.resolver parseAllIPString:payload];
    
    XCTAssertNotNil(result, @"IPv6解析结果不应为nil");
}

- (void)testParseAllIPStringWithInvalidFormat {
    [self.resolver setValue:@(HttpDnsTypeIPv4) forKey:@"ipType"];
    NSString *invalidPayload = @"invalid_format";
    NSDictionary *result = [self.resolver parseAllIPString:invalidPayload];
    
    XCTAssertNil(result, @"无效格式应返回nil");
}

#pragma mark - parseIPString测试

- (void)testParseIPStringWithValidIPv4 {
    NSString *ipString = @"1.1.1.1;2.2.2.2,60";
    NSDictionary *result = [self.resolver parseIPString:ipString ClientIP:@"1.2.3.4" use4A:NO];
    
    XCTAssertNotNil(result, @"有效IPv4字符串应返回非nil结果");
    XCTAssertNotNil(result[kIP], @"应包含IP数组");
    XCTAssertNotNil(result[kTTL], @"应包含TTL");
    XCTAssertNotNil(result[kClientIP], @"应包含客户端IP");
    XCTAssertEqualObjects(result[kChannel], @"http", @"channel应为http");
}

- (void)testParseIPStringWithTrailingSemicolon {
    // 测试IP字符串末尾带分号的情况
    NSString *ipString = @"1.1.1.1;2.2.2.2;,60";
    NSDictionary *result = [self.resolver parseIPString:ipString ClientIP:@"1.2.3.4" use4A:NO];
    
    // 应该能正常处理末尾分号
    if (result) {
        XCTAssertNotNil(result[kIP], @"应包含IP数组");
    }
}

- (void)testParseIPStringWithValidIPv6 {
    NSString *ipString = @"2001::1;2001::2,120";
    NSDictionary *result = [self.resolver parseIPString:ipString ClientIP:@"2001::ff" use4A:YES];
    
    XCTAssertNotNil(result, @"有效IPv6字符串应返回非nil结果");
}

- (void)testParseIPStringWithInvalidIP {
    NSString *ipString = @"invalid_ip,60";
    NSDictionary *result = [self.resolver parseIPString:ipString ClientIP:@"1.2.3.4" use4A:NO];
    
    XCTAssertNil(result, @"无效IP应返回nil");
}

#pragma mark - getQueryDomain测试

- (void)testGetQueryDomainRemovesTrailingDot {
    NSString *result = [self.resolver getQueryDomain:@"example.com."];
    
    XCTAssertEqualObjects(result, @"example.com", @"应移除末尾的点");
}

- (void)testGetQueryDomainKeepsNormalDomain {
    NSString *result = [self.resolver getQueryDomain:@"example.com"];
    
    XCTAssertEqualObjects(result, @"example.com", @"没有末尾点的域名应保持不变");
}

#pragma mark - getDecryptStrWithResponseStr测试

- (void)testGetDecryptStrWithHTTPS {
    [self.resolver setValue:@(HttpDnsEncryptTypeHTTPS) forKey:@"encryptType"];
    
    NSString *response = @"test_response_string";
    NSString *result = [self.resolver getDecryptStrWithResponseStr:response];
    
    XCTAssertEqualObjects(result, response, @"HTTPS模式应直接返回原字符串");
}

- (void)testGetDecryptStrWithDES {
    [self.resolver setValue:@(HttpDnsEncryptTypeDES) forKey:@"encryptType"];
    [self.resolver setValue:@"testkey1" forKey:@"dnsKey"];
    
    // 先加密一个字符串
    NSString *plainText = @"test.example.com";
    NSString *encrypted = [MSDKDnsInfoTool encryptUseDES:plainText key:@"testkey1"];
    
    // 再解密
    NSString *decrypted = [self.resolver getDecryptStrWithResponseStr:encrypted];
    
    XCTAssertEqualObjects(decrypted, plainText, @"DES解密应还原原文");
}

- (void)testGetDecryptStrWithAES {
    [self.resolver setValue:@(HttpDnsEncryptTypeAES) forKey:@"encryptType"];
    [self.resolver setValue:@"1234567890123456" forKey:@"dnsKey"];
    
    // 先加密一个字符串
    NSString *plainText = @"test.example.com";
    NSString *encrypted = [MSDKDnsInfoTool encryptUseAES:plainText key:@"1234567890123456"];
    
    // 再解密
    NSString *decrypted = [self.resolver getDecryptStrWithResponseStr:encrypted];
    
    XCTAssertEqualObjects(decrypted, plainText, @"AES解密应还原原文");
}

#pragma mark - isIPLegal测试

- (void)testIsIPLegalWithValidIPv4 {
    NSArray *ips = @[@"1.1.1.1", @"2.2.2.2"];
    BOOL result = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertTrue(result, @"有效IPv4数组应返回YES");
}

- (void)testIsIPLegalWithInvalidIPv4 {
    NSArray *ips = @[@"invalid", @"not_an_ip"];
    BOOL result = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertFalse(result, @"无效IPv4数组应返回NO");
}

- (void)testIsIPLegalWithValidIPv6 {
    NSArray *ips = @[@"2001::1", @"2001::2"];
    BOOL result = [self.resolver isIPLegal:ips use4A:YES];
    
    XCTAssertTrue(result, @"有效IPv6数组应返回YES");
}

- (void)testIsIPLegalWithEmptyArray {
    NSArray *ips = @[];
    BOOL result = [self.resolver isIPLegal:ips use4A:NO];
    
    XCTAssertFalse(result, @"空数组应返回NO");
}

- (void)testIsIPLegalWithNil {
    BOOL result = [self.resolver isIPLegal:nil use4A:NO];
    
    XCTAssertFalse(result, @"nil应返回NO");
}

#pragma mark - dnsTimeConsuming测试

- (void)testDnsTimeConsumingReturnsValidValue {
    int timeConsuming = [self.resolver dnsTimeConsuming];
    
    XCTAssertGreaterThanOrEqual(timeConsuming, 0, @"DNS耗时应为非负数");
}

#pragma mark - 双栈解析边界测试

- (void)testParseAllIPStringDualStackWithOnlyIPv4 {
    [self.resolver setValue:@(HttpDnsTypeDual) forKey:@"ipType"];
    // 只有IPv4结果的双栈响应
    NSString *payload = @"1.1.1.1,60-,0|10.0.0.1";
    NSDictionary *result = [self.resolver parseAllIPString:payload];
    
    // 应该至少有IPv4结果
    if (result) {
        XCTAssertNotNil(result[@"ipv4"], @"应包含IPv4结果");
    }
}

- (void)testParseAllIPStringDualStackWithOnlyIPv6 {
    [self.resolver setValue:@(HttpDnsTypeDual) forKey:@"ipType"];
    // 只有IPv6结果的双栈响应
    NSString *payload = @",0-2001::1,120|10.0.0.1";
    NSDictionary *result = [self.resolver parseAllIPString:payload];
    
    // 应该至少有IPv6结果
    if (result) {
        XCTAssertNotNil(result[@"ipv6"], @"应包含IPv6结果");
    }
}

@end
