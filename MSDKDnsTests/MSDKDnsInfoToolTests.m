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

#pragma mark - 队列测试

- (void)testMsdkdnsQueueReturnsSameQueue {
    dispatch_queue_t queue1 = [MSDKDnsInfoTool msdkdns_queue];
    dispatch_queue_t queue2 = [MSDKDnsInfoTool msdkdns_queue];
    
    XCTAssertNotNil(queue1, @"msdkdns_queue不应返回nil");
    XCTAssertEqual(queue1, queue2, @"多次调用应返回同一队列");
}

- (void)testMsdkdnsResolverQueueReturnsSameQueue {
    dispatch_queue_t queue1 = [MSDKDnsInfoTool msdkdns_resolver_queue];
    dispatch_queue_t queue2 = [MSDKDnsInfoTool msdkdns_resolver_queue];
    
    XCTAssertNotNil(queue1, @"msdkdns_resolver_queue不应返回nil");
    XCTAssertEqual(queue1, queue2, @"多次调用应返回同一队列");
}

- (void)testMsdkdnsLocalQueueReturnsSameQueue {
    dispatch_queue_t queue1 = [MSDKDnsInfoTool msdkdns_local_queue];
    dispatch_queue_t queue2 = [MSDKDnsInfoTool msdkdns_local_queue];
    
    XCTAssertNotNil(queue1, @"msdkdns_local_queue不应返回nil");
    XCTAssertEqual(queue1, queue2, @"多次调用应返回同一队列");
}

#pragma mark - DES加密解密测试

- (void)testEncryptUseDESWithValidInput {
    NSString *plainText = @"test.example.com";
    NSString *key = @"testkey1";
    
    NSString *encrypted = [MSDKDnsInfoTool encryptUseDES:plainText key:key];
    
    XCTAssertNotNil(encrypted, @"加密结果不应为nil");
    XCTAssertTrue(encrypted.length > 0, @"加密结果长度应大于0");
    XCTAssertFalse([encrypted isEqualToString:plainText], @"加密结果应与原文不同");
}

- (void)testDecryptUseDESWithValidInput {
    NSString *plainText = @"test.example.com";
    NSString *key = @"testkey1";
    
    // 先加密
    NSString *encrypted = [MSDKDnsInfoTool encryptUseDES:plainText key:key];
    XCTAssertNotNil(encrypted, @"加密结果不应为nil");
    
    // 再解密
    NSString *decrypted = [MSDKDnsInfoTool decryptUseDES:encrypted key:key];
    
    XCTAssertNotNil(decrypted, @"解密结果不应为nil");
    XCTAssertEqualObjects(decrypted, plainText, @"解密结果应与原文相同");
}

- (void)testDecryptUseDESWithNilInput {
    NSString *decrypted = [MSDKDnsInfoTool decryptUseDES:nil key:@"testkey1"];
    XCTAssertNil(decrypted, @"nil输入应返回nil");
}

- (void)testDecryptUseDESWithNilKey {
    NSString *decrypted = [MSDKDnsInfoTool decryptUseDES:@"encrypted" key:nil];
    XCTAssertNil(decrypted, @"nil key应返回nil");
}

- (void)testDecryptUseDESWithEmptyString {
    NSString *decrypted = [MSDKDnsInfoTool decryptUseDES:@"" key:@"testkey1"];
    XCTAssertNil(decrypted, @"空字符串应返回nil");
}

#pragma mark - AES加密解密测试

- (void)testEncryptUseAESWithValidInput {
    NSString *plainText = @"test.example.com";
    NSString *key = @"1234567890123456";  // AES需要16字节的key
    
    NSString *encrypted = [MSDKDnsInfoTool encryptUseAES:plainText key:key];
    
    XCTAssertNotNil(encrypted, @"AES加密结果不应为nil");
    XCTAssertTrue(encrypted.length > 32, @"AES加密结果应包含IV和密文");
}

- (void)testDecryptUseAESWithValidInput {
    NSString *plainText = @"test.example.com";
    NSString *key = @"1234567890123456";
    
    // 先加密
    NSString *encrypted = [MSDKDnsInfoTool encryptUseAES:plainText key:key];
    XCTAssertNotNil(encrypted, @"加密结果不应为nil");
    
    // 再解密
    NSString *decrypted = [MSDKDnsInfoTool decryptUseAES:encrypted key:key];
    
    XCTAssertNotNil(decrypted, @"AES解密结果不应为nil");
    XCTAssertEqualObjects(decrypted, plainText, @"AES解密结果应与原文相同");
}

- (void)testDecryptUseAESWithNilInput {
    NSString *decrypted = [MSDKDnsInfoTool decryptUseAES:nil key:@"1234567890123456"];
    XCTAssertNil(decrypted, @"nil输入应返回nil");
}

- (void)testDecryptUseAESWithShortString {
    // 字符串长度小于等于32时应返回nil
    NSString *decrypted = [MSDKDnsInfoTool decryptUseAES:@"short" key:@"1234567890123456"];
    XCTAssertNil(decrypted, @"过短的字符串应返回nil");
}

#pragma mark - URL构建测试

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

- (void)testHttpsUrlWithEmptyDomainReturnsNil {
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@""
                                               dnsId:1234
                                              dnsKey:@"dummy-key"
                                              ipType:HttpDnsTypeIPv4
                                         encryptType:HttpDnsEncryptTypeDES];
    
    XCTAssertNil(url, @"空域名应返回nil");
}

- (void)testHttpsUrlWithNilDomainReturnsNil {
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:nil
                                               dnsId:1234
                                              dnsKey:@"dummy-key"
                                              ipType:HttpDnsTypeIPv4
                                         encryptType:HttpDnsEncryptTypeDES];
    
    XCTAssertNil(url, @"nil域名应返回nil");
}

- (void)testHttpsUrlWithDESEncryptType {
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMDnsId:1234 dnsKey:@"testkey1" token:@""];
    [self flushParamQueue];
    
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@"example.com"
                                               dnsId:1234
                                              dnsKey:@"testkey1"
                                              ipType:HttpDnsTypeIPv4
                                         encryptType:HttpDnsEncryptTypeDES];
    
    XCTAssertNotNil(url, @"DES加密URL不应为nil");
    XCTAssertTrue([url.query containsString:@"alg=des"], @"DES加密应包含alg=des参数");
}

- (void)testHttpsUrlWithAESEncryptType {
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetMDnsId:1234 dnsKey:@"1234567890123456" token:@""];
    [self flushParamQueue];
    
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@"example.com"
                                               dnsId:1234
                                              dnsKey:@"1234567890123456"
                                              ipType:HttpDnsTypeIPv4
                                         encryptType:HttpDnsEncryptTypeAES];
    
    XCTAssertNotNil(url, @"AES加密URL不应为nil");
    XCTAssertTrue([url.query containsString:@"alg=aes"], @"AES加密应包含alg=aes参数");
}

- (void)testHttpsUrlWithIPv6Type {
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@"example.com"
                                               dnsId:1234
                                              dnsKey:@"dummy-key"
                                              ipType:HttpDnsTypeIPv6
                                         encryptType:HttpDnsEncryptTypeHTTPS];
    
    XCTAssertNotNil(url);
    XCTAssertTrue([url.query containsString:@"type=aaaa"], @"IPv6请求应包含type=aaaa参数");
}

- (void)testHttpsUrlWithDualType {
    NSURL *url = [MSDKDnsInfoTool httpsUrlWithDomain:@"example.com"
                                               dnsId:1234
                                              dnsKey:@"dummy-key"
                                              ipType:HttpDnsTypeDual
                                         encryptType:HttpDnsEncryptTypeHTTPS];
    
    XCTAssertNotNil(url);
    XCTAssertTrue([url.query containsString:@"type=addrs"], @"双栈请求应包含type=addrs参数");
}

#pragma mark - sessionID测试

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

#pragma mark - IP字符串处理测试

- (void)testGetIPsStringFromArrayFormatsCommaSeparatedList {
    NSString *result = [MSDKDnsInfoTool getIPsStringFromIPsArray:@[@"1.1.1.1", @"2.2.2.2", @"3.3.3.3"]];
    XCTAssertEqualObjects(result, @"1.1.1.1,2.2.2.2,3.3.3.3");
}

- (void)testGetIPsStringFromEmptyArray {
    NSString *result = [MSDKDnsInfoTool getIPsStringFromIPsArray:@[]];
    XCTAssertEqualObjects(result, @"", @"空数组应返回空字符串");
}

- (void)testGetIPsStringFromNilArray {
    NSString *result = [MSDKDnsInfoTool getIPsStringFromIPsArray:nil];
    XCTAssertEqualObjects(result, @"", @"nil数组应返回空字符串");
}

- (void)testGetIPsStringFromSingleIPArray {
    NSString *result = [MSDKDnsInfoTool getIPsStringFromIPsArray:@[@"192.168.1.1"]];
    XCTAssertEqualObjects(result, @"192.168.1.1", @"单个IP不应有逗号");
}

#pragma mark - isExist测试

- (void)testIsExistValidatesNonEmptyStrings {
    XCTAssertTrue([MSDKDnsInfoTool isExist:@"value"]);
    XCTAssertFalse([MSDKDnsInfoTool isExist:@""]);
    XCTAssertFalse([MSDKDnsInfoTool isExist:nil]);
}

- (void)testIsExistWithWhitespace {
    XCTAssertTrue([MSDKDnsInfoTool isExist:@"  "], @"空白字符串应返回YES（非空）");
    XCTAssertTrue([MSDKDnsInfoTool isExist:@"\n"], @"换行符应返回YES（非空）");
}

#pragma mark - arrayTransLowercase测试

- (void)testArrayTransLowercaseConvertsToLowercase {
    NSArray *input = @[@"WWW.EXAMPLE.COM", @"Api.Test.Com"];
    NSArray *result = [MSDKDnsInfoTool arrayTransLowercase:input];
    
    XCTAssertEqual(result.count, 2, @"结果数组长度应相同");
    XCTAssertEqualObjects(result[0], @"www.example.com", @"应转换为小写");
    XCTAssertEqualObjects(result[1], @"api.test.com", @"应转换为小写");
}

- (void)testArrayTransLowercaseWithEmptyStrings {
    NSArray *input = @[@"WWW.EXAMPLE.COM", @"", @"Api.Test.Com"];
    NSArray *result = [MSDKDnsInfoTool arrayTransLowercase:input];
    
    // 空字符串应该被跳过
    XCTAssertEqual(result.count, 2, @"空字符串应被过滤");
}

- (void)testArrayTransLowercaseWithEmptyArray {
    NSArray *result = [MSDKDnsInfoTool arrayTransLowercase:@[]];
    XCTAssertEqual(result.count, 0, @"空数组应返回空数组");
}

#pragma mark - getCurrentTimeByBaseTime测试

- (void)testGetCurrentTimeByBaseTimeReturnsValidTime {
    NSTimeInterval time = [MSDKDnsInfoTool getCurrentTimeByBaseTime];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    
    // 时间差应在合理范围内（考虑偏移量）
    XCTAssertTrue(fabs(time - now) < 86400, @"返回的时间应在合理范围内");
}

#pragma mark - wifiSSID测试

- (void)testWifiSSIDReturnsStringOrMinusOne {
    NSString *ssid = [MSDKDnsInfoTool wifiSSID];
    
    XCTAssertNotNil(ssid, @"wifiSSID不应返回nil");
    // 在非WiFi环境下应返回-1
    XCTAssertTrue(ssid.length > 0, @"应返回非空字符串");
}

@end
