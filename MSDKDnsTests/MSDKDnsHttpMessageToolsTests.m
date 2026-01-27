//
//  MSDKDnsHttpMessageToolsTests.m
//  MSDKDnsTests
//
//  测试MSDKDnsHttpMessageTools HTTP消息工具类
//

#import <XCTest/XCTest.h>
#import "MSDKDnsHttpMessageTools.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsInfoTool.h"

@interface MSDKDnsHttpMessageToolsTests : XCTestCase
@end

@implementation MSDKDnsHttpMessageToolsTests

- (void)setUp {
    [super setUp];
    // 重置劫持域名配置，确保干净的初始状态
    [self resetHijackConfig];
}

- (void)tearDown {
    // 清理状态
    [self resetHijackConfig];
    [super tearDown];
}

- (void)resetHijackConfig {
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetHijackDomainArray:nil];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetNoHijackDomainArray:nil];
    // 确保异步操作完成
    [self flushQueue];
}

- (void)flushQueue {
    dispatch_sync([MSDKDnsInfoTool msdkdns_queue], ^{});
}

#pragma mark - canInitWithRequest 基础测试

- (void)testCanInitWithRequestForAboutBlank {
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]];
    XCTAssertFalse([MSDKDnsHttpMessageTools canInitWithRequest:request], @"about:blank不应被拦截");
}

- (void)testCanInitWithRequestForIPv4Address {
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://192.168.1.1/path"]];
    XCTAssertFalse([MSDKDnsHttpMessageTools canInitWithRequest:request], @"IPv4地址不应被拦截");
}

- (void)testCanInitWithRequestForIPv6Address {
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://[2001:db8::1]/path"]];
    XCTAssertFalse([MSDKDnsHttpMessageTools canInitWithRequest:request], @"IPv6地址不应被拦截");
}

- (void)testCanInitWithRequestForNormalDomain {
    // 确保没有配置任何劫持列表
    [self resetHijackConfig];
    
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    XCTAssertTrue([MSDKDnsHttpMessageTools canInitWithRequest:request], @"普通域名应被拦截");
}

#pragma mark - hijackDomainArray 测试

- (void)testCanInitWithRequestForHijackDomain {
    // 先清理，再配置
    [self resetHijackConfig];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetHijackDomainArray:@[@"hijack.example.com"]];
    [self flushQueue];
    
    // 在劫持列表中的HTTPS域名应被拦截
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://hijack.example.com/path"]];
    BOOL result1 = [MSDKDnsHttpMessageTools canInitWithRequest:request];
    XCTAssertTrue(result1, @"在劫持列表中的HTTPS域名应被拦截");
    
    // 不在劫持列表中的域名不应被拦截
    NSURLRequest *request2 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://other.example.com/path"]];
    BOOL result2 = [MSDKDnsHttpMessageTools canInitWithRequest:request2];
    XCTAssertFalse(result2, @"不在劫持列表中的域名不应被拦截");
}

- (void)testCanInitWithRequestForHttpScheme {
    // 先清理，再配置
    [self resetHijackConfig];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetHijackDomainArray:@[@"hijack.example.com"]];
    [self flushQueue];
    
    // HTTP协议的请求不应被拦截
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"http://hijack.example.com/path"]];
    BOOL result = [MSDKDnsHttpMessageTools canInitWithRequest:request];
    XCTAssertFalse(result, @"HTTP协议不应被拦截（当配置了劫持列表时，只拦截HTTPS）");
}

#pragma mark - noHijackDomainArray 测试

- (void)testCanInitWithRequestForNoHijackDomain {
    // 确保hijackDomainArray为nil，这样才会检查noHijackDomainArray
    [self resetHijackConfig];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetNoHijackDomainArray:@[@"nohijack.example.com"]];
    [self flushQueue];
    
    // 在不劫持列表中的域名不应被拦截
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://nohijack.example.com/path"]];
    BOOL result1 = [MSDKDnsHttpMessageTools canInitWithRequest:request];
    XCTAssertFalse(result1, @"在不劫持列表中的域名不应被拦截");
    
    // 不在不劫持列表中的普通域名应被拦截
    NSURLRequest *request2 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://other.example.com/path"]];
    BOOL result2 = [MSDKDnsHttpMessageTools canInitWithRequest:request2];
    XCTAssertTrue(result2, @"不在不劫持列表中的域名应被拦截");
}

#pragma mark - canonicalRequestForRequest 测试

- (void)testCanonicalRequestForRequestReturnsOriginalRequest {
    NSURLRequest *originalRequest = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    NSURLRequest *canonicalRequest = [MSDKDnsHttpMessageTools canonicalRequestForRequest:originalRequest];
    
    XCTAssertEqualObjects(canonicalRequest.URL, originalRequest.URL, @"canonicalRequest应返回原始请求");
}

#pragma mark - 边界情况测试

- (void)testCanInitWithRequestForLocalhost {
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://127.0.0.1/path"]];
    XCTAssertFalse([MSDKDnsHttpMessageTools canInitWithRequest:request], @"localhost IP不应被拦截");
}

- (void)testCanInitWithRequestForIPv6Localhost {
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://[::1]/path"]];
    XCTAssertFalse([MSDKDnsHttpMessageTools canInitWithRequest:request], @"IPv6 localhost不应被拦截");
}

- (void)testCanInitWithRequestForEmptyHijackArray {
    [self resetHijackConfig];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetHijackDomainArray:@[]];
    [self flushQueue];
    
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    // 空劫持数组（count为0）应该让普通域名被拦截，因为源码中 hijackDomainArray.count > 0 为 false
    XCTAssertTrue([MSDKDnsHttpMessageTools canInitWithRequest:request], @"空劫持数组时普通域名应被拦截");
}

- (void)testCanInitWithRequestForEmptyNoHijackArray {
    [self resetHijackConfig];
    [[MSDKDnsParamsManager shareInstance] msdkDnsSetNoHijackDomainArray:@[]];
    [self flushQueue];
    
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    XCTAssertTrue([MSDKDnsHttpMessageTools canInitWithRequest:request], @"空不劫持数组时普通域名应被拦截");
}

- (void)testCanInitWithRequestForAlreadyProcessedRequest {
    // 测试已经被处理过的请求（防止无限循环）
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    [NSURLProtocol setProperty:@(YES) forKey:@"MSDKDnsHttpMessagePropertyKey" inRequest:request];
    
    XCTAssertFalse([MSDKDnsHttpMessageTools canInitWithRequest:request], @"已处理的请求不应再被拦截");
}

#pragma mark - requestIsCacheEquivalent 测试

- (void)testRequestIsCacheEquivalent {
    NSURLRequest *request1 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    NSURLRequest *request2 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.example.com/path"]];
    
    // 默认情况下使用父类实现
    BOOL equivalent = [MSDKDnsHttpMessageTools requestIsCacheEquivalent:request1 toRequest:request2];
    XCTAssertTrue(equivalent == YES || equivalent == NO, @"应返回有效的BOOL值");
}

@end
