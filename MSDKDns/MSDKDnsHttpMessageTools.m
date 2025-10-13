/**
 * Copyright (c) Tencent. All rights reserved.
 */

#import <Foundation/Foundation.h>
#import "MSDKDnsHttpMessageTools.h"
#import "MSDKDnsLog.h"
#import "MSDKDnsParamsManager.h"
#import "MSDKDnsManager.h"
#import <arpa/inet.h>
#import <objc/runtime.h>
#import "MSDKDns.h"

static NSString *const protocolKey = @"MSDKDnsHttpMessagePropertyKey";
static NSString *const kAnchorAlreadyAdded = @"AnchorAlreadyAdded";

@interface MSDKDnsHttpMessageTools () <NSStreamDelegate>

@property (strong, readwrite, nonatomic) NSMutableURLRequest *curRequest;
@property (strong, readwrite, nonatomic) NSRunLoop *curRunLoop;
@property (strong, readwrite, nonatomic) NSInputStream *inputStream;

@end

@implementation MSDKDnsHttpMessageTools

/**
 *  是否拦截处理指定的请求
 *
 *  @param request 指定的请求
 *
 *  @return 返回YES表示要拦截处理，返回NO表示不拦截处理
 */
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    
    if([[request.URL absoluteString] isEqual:@"about:blank"]) {
        return NO;
    }
    
    /* 防止无限循环，因为一个请求在被拦截处理过程中，也会发起一个请求，这样又会走到这里，如果不进行处理，就会造成无限循环 */
    if ([NSURLProtocol propertyForKey:protocolKey inRequest:request]) {
        return NO;
    }
    NSString * url = request.URL.absoluteString;
    NSURL *URL = request.URL;
    NSString * originHost = [request.allHTTPHeaderFields objectForKey:@"host"];
    NSString * domain = request.URL.host;
        
    NSArray * hijackDomainArray = [[[MSDKDnsParamsManager shareInstance] msdkDnsGetHijackDomainArray] copy];
    NSArray * noHijackDomainArray = [[[MSDKDnsParamsManager shareInstance] msdkDnsGetNoHijackDomainArray] copy];
    
    if (hijackDomainArray && (hijackDomainArray.count > 0)) {
        if ([url hasPrefix:@"https"] && [hijackDomainArray containsObject:domain]) {
            return YES;
        } else {
            return NO;
        }
    }
    if (noHijackDomainArray && (noHijackDomainArray.count > 0)) {
        if ([noHijackDomainArray containsObject:domain]) {
            return NO;
        }
    }
    // 如果为ip，则不拦截处理
    if ([self isIPV4:domain]){
        return NO;
    }
    if ([self isIPV6:domain]){
        return NO;
    }
    return YES;
}

+ (BOOL)isIPV4:(NSString *)ipSting {
    BOOL isIPV4 = YES;
    
    if (ipSting) {
        const char *utf8 = [ipSting UTF8String];
        int success = 0;
        struct in_addr dst;
        success = inet_pton(AF_INET, utf8, &dst);
        if (success != 1) {
            isIPV4 = NO;
        }
    } else {
        isIPV4 = NO;
    }
    return isIPV4;
}

+ (BOOL)isIPV6:(NSString *)ipSting {
    BOOL isIPV6 = YES;
    
    if (ipSting) {
        const char *utf8 = [ipSting UTF8String];
        int success = 0;
        struct in6_addr dst6;
        success = inet_pton(AF_INET6, utf8, &dst6);
        if (success != 1) {
            isIPV6 = NO;
        }
    } else {
        isIPV6 = NO;
    }
    return isIPV6;
}

/**
 * 如果需要对请求进行重定向，添加指定头部等操作，可以在该方法中进行
 */
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

/**
 * 开始加载，在该方法中，加载一个请求
 */
- (void)startLoading {
    NSMutableURLRequest *request = [self.request mutableCopy];
    // 表示该请求已经被处理，防止无限循环
    [NSURLProtocol setProperty:@(YES) forKey:protocolKey inRequest:request];
    self.curRequest = [self applyHttpDnsIpDirectConnect:request];
    [self startRequest];
}

- (NSString *)cookieForURL:(NSURL *)URL {
    NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    NSMutableArray *cookieList = [NSMutableArray array];
    for (NSHTTPCookie *cookie in [cookieStorage cookies]) {
        if (![self p_checkCookie:cookie URL:URL]) {
            continue;
        }
        [cookieList addObject:cookie];
    }
    
    if (cookieList.count > 0) {
        NSDictionary *cookieDic = [NSHTTPCookie requestHeaderFieldsWithCookies:cookieList];
        if ([cookieDic objectForKey:@"Cookie"]) {
            return cookieDic[@"Cookie"];
        }
    }
    return nil;
}


- (BOOL)p_checkCookie:(NSHTTPCookie *)cookie URL:(NSURL *)URL {
    if (cookie.domain.length <= 0 || URL.host.length <= 0) {
        return NO;
    }
    if ([URL.host containsString:cookie.domain]) {
        return YES;
    }
    return NO;
}

- (NSURLRequest*)applyHttpDnsIpDirectConnect:(NSURLRequest*)request {
    NSURL* originUrl = request.URL;
    NSString* originHost = originUrl.host;
    NSString *cookie = [self cookieForURL:originUrl];
    NSURL* newUrl = [self getIpAndReplace:[originUrl absoluteString]];
    
    NSMutableURLRequest* mutableRequest = [request copy];
    mutableRequest.URL = newUrl;
    [mutableRequest setValue:originHost forHTTPHeaderField:@"Host"];
    [mutableRequest setValue:cookie forHTTPHeaderField:@"Cookie"];
    
    return [mutableRequest copy];
}

- (NSURL*)getIpAndReplace:(NSString*)urlString {
    NSURL* url = [NSURL URLWithString:urlString];
    NSString* originHost = url.host;
    
    NSTimeInterval start = [[NSDate date] timeIntervalSince1970];
    NSArray* result = [[MSDKDns sharedInstance] WGGetHostByName:url.host];
    NSString* ip = nil;
    if (result && result.count > 1) {
        if (![result[0] isEqualToString:@"0"]) {
            ip = result[0];
        } else {
            ip = result[1];
        }
    }
    // 通过HTTPDNS获取IP成功，进行URL替换和HOST头设置
    if (originHost.length > 0 && ip.length > 0) {
        NSString* originUrlStringafterdispatch = [url absoluteString];
        NSRange hostRange = [originUrlStringafterdispatch rangeOfString:url.host];
        NSString* urlString = [originUrlStringafterdispatch stringByReplacingCharactersInRange:hostRange withString:ip];
        url = [NSURL URLWithString:urlString];
    }
    return url;
}

/**
 * 取消请求
 */
- (void)stopLoading {
    if (_inputStream.streamStatus == NSStreamStatusOpen) {
        [self closeStream:_inputStream];
    }
    [self.client URLProtocol:self didFailWithError:[[NSError alloc] initWithDomain:@"stop loading" code:-1 userInfo:nil]];
}

/**
 * 使用CFHTTPMessage转发请求
 */
- (void)startRequest {
    NSDictionary *headFields = _curRequest.allHTTPHeaderFields;
    CFURLRef requestURL = CFURLCreateWithString(kCFAllocatorDefault,
                                                (__bridge CFStringRef)_curRequest.URL.absoluteString,
                                                NULL);
    
    // 方法：nil 时默认 GET；不转移所有权，无需释放
    NSString *method = _curRequest.HTTPMethod ?: @"GET";
    CFStringRef requestMethod = (__bridge CFStringRef)method;
    
    // 根据请求的url、方法、版本创建CFHTTPMessageRef对象
    CFHTTPMessageRef cfrequest = CFHTTPMessageCreateRequest(kCFAllocatorDefault, requestMethod, requestURL, kCFHTTPVersion1_1);
    
    // 添加http post请求所附带的数据
    CFDataRef bodyData = NULL;
    if (_curRequest.HTTPBody) {
        bodyData = (__bridge_retained CFDataRef)_curRequest.HTTPBody; // +1
    } else if (_curRequest.HTTPBodyStream) {
        NSData *data = [self dataWithInputStream:_curRequest.HTTPBodyStream] ?: [NSData data];
        bodyData = (__bridge_retained CFDataRef)data; // +1
    }
    if (bodyData) {
        CFHTTPMessageSetBody(cfrequest, bodyData);
        CFRelease(bodyData); // 配对释放
    }
    
    // 复制 header（用 objectForKey，并跳过 nil）
    for (NSString *key in headFields) {
        NSString *val = [headFields objectForKey:key];
        if (val) {
            CFHTTPMessageSetHeaderFieldValue(cfrequest,
                                             (__bridge CFStringRef)key,
                                             (__bridge CFStringRef)val);
        }
    }
    
    // 创建CFHTTPMessage对象的输入流并交给 ARC 管理
    CFReadStreamRef readStream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, cfrequest);
    self.inputStream = (__bridge_transfer NSInputStream *)readStream;
    
    // 设置SNI host信息，关键步骤
    NSString *host = headFields[@"host"] ?: _curRequest.URL.host;
    if (host.length > 0) {
        [_inputStream setProperty:NSStreamSocketSecurityLevelNegotiatedSSL
                           forKey:NSStreamSocketSecurityLevelKey];
        
        NSDictionary *sslProperties = @{ (__bridge NSString *)kCFStreamSSLPeerName : host };
        [_inputStream setProperty:sslProperties
                           forKey:(__bridge NSString *)kCFStreamPropertySSLSettings];
    }
    
    _inputStream.delegate = self;
    
    if (!_curRunLoop) {
        // 保存当前线程的runloop，这对于重定向的请求很关键
        self.curRunLoop = [NSRunLoop currentRunLoop];
    }
    [_inputStream scheduleInRunLoop:_curRunLoop forMode:NSRunLoopCommonModes];
    [_inputStream open];
    
    // 仅释放你创建（Create/Copy）的 CF 对象
    CFRelease(cfrequest);
    CFRelease(requestURL);
}

-(NSData*)dataWithInputStream:(NSInputStream*)stream {
  NSMutableData *data = [NSMutableData data];
  [stream open];
  NSInteger result;
  uint8_t buffer[1024];

  while ((result = [stream read:buffer maxLength:1024]) != 0) {
    if (result > 0) {
      // buffer contains result bytes of data to be handled
      [data appendBytes:buffer length:result];
    } else if (result < 0) {
      // The stream had an error. You can get an NSError object using [iStream streamError]
      data = nil;
      break;
    }
  }
  [stream close];
  return data;
}

#pragma mark - NSStreamDelegate
/**
 * input stream 收到header complete后的回调函数
 */
- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode {
    if (eventCode == NSStreamEventHasBytesAvailable) {
        CFReadStreamRef readStream = (__bridge_retained CFReadStreamRef) aStream;
        CFHTTPMessageRef message = (CFHTTPMessageRef) CFReadStreamCopyProperty(readStream, kCFStreamPropertyHTTPResponseHeader);
        if (CFHTTPMessageIsHeaderComplete(message)) {
            // 以防response的header信息不完整
            UInt8 buffer[16 * 1024];
            UInt8 *buf = NULL;
            NSUInteger length = 0;
            NSInputStream *inputstream = (NSInputStream *) aStream;
            NSNumber *alreadyAdded = objc_getAssociatedObject(aStream, (__bridge const void *)(kAnchorAlreadyAdded));
            if (!alreadyAdded || ![alreadyAdded boolValue]) {
                objc_setAssociatedObject(aStream, (__bridge const void *)(kAnchorAlreadyAdded), [NSNumber numberWithBool:YES], OBJC_ASSOCIATION_COPY);
                // 通知client已收到response，只通知一次
                
                NSDictionary *headDict = (__bridge NSDictionary *) (CFHTTPMessageCopyAllHeaderFields(message));
                CFStringRef httpVersion = CFHTTPMessageCopyVersion(message);
                // 获取响应头部的状态码
                CFIndex statusCode = CFHTTPMessageGetResponseStatusCode(message);
                NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:_curRequest.URL statusCode:statusCode
                                                                         HTTPVersion:(__bridge NSString *) httpVersion headerFields:headDict];
                
                
                [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                
                // 验证证书
                SecTrustRef trust = (__bridge SecTrustRef) [aStream propertyForKey:(__bridge NSString *) kCFStreamPropertySSLPeerTrust];
                SecTrustResultType res = kSecTrustResultInvalid;
                NSMutableArray *policies = [NSMutableArray array];
                NSString *domain = [[_curRequest allHTTPHeaderFields] valueForKey:@"host"];
                if (domain) {
                    [policies addObject:(__bridge_transfer id) SecPolicyCreateSSL(true, (__bridge CFStringRef) domain)];
                } else {
                    [policies addObject:(__bridge_transfer id) SecPolicyCreateBasicX509()];
                }
                /*
                 * 绑定校验策略到服务端的证书上
                 */
                SecTrustSetPolicies(trust, (__bridge CFArrayRef) policies);
                if (SecTrustEvaluate(trust, &res) != errSecSuccess) {
                    [self closeStream:aStream];
                    [self.client URLProtocol:self didFailWithError:[[NSError alloc] initWithDomain:@"can not evaluate the server trust" code:-1 userInfo:nil]];
                    return;
                }
                if (res != kSecTrustResultProceed && res != kSecTrustResultUnspecified) {
                    /* 证书验证不通过，关闭input stream */
                    [self closeStream:aStream];
                    [self.client URLProtocol:self didFailWithError:[[NSError alloc] initWithDomain:@"fail to evaluate the server trust" code:-1 userInfo:nil]];
                } else {
                    // 证书校验通过
                    if (statusCode >= 300 && statusCode < 400) {
                        // 处理重定向错误码
                        [self closeStream:aStream];
                        [self handleRedirect:message];
                    } else {
                        // 返回成功收到的数据
                        if (![inputstream getBuffer:&buf length:&length]) {
                            NSInteger amount = [inputstream read:buffer maxLength:sizeof(buffer)];
                            buf = buffer;
                            length = amount;
                        }
                        if ((NSInteger)length >= 0) {
                            NSData *data = [[NSData alloc] initWithBytes:buf length:length];
                            [self.client URLProtocol:self didLoadData:data];
                        } else {
                            NSError *error = inputstream.streamError;
                            if (!error) {
                                error = [[NSError alloc] initWithDomain:@"inputstream length is invalid"
                                                                   code:-2
                                                               userInfo:nil];
                            }
                            [aStream removeFromRunLoop:_curRunLoop forMode:NSRunLoopCommonModes];
                            [aStream setDelegate:nil];
                            [aStream close];
                            [self.client URLProtocol:self didFailWithError:error];
                        }
                    }
                }
            } else {
                // 证书已验证过，返回数据
                if (![inputstream getBuffer:&buf length:&length]) {
                    NSInteger amount = [inputstream read:buffer maxLength:sizeof(buffer)];
                    buf = buffer;
                    length = amount;
                }
                if ((NSInteger)length >= 0) {
                    NSData *data = [[NSData alloc] initWithBytes:buf length:length];
                    [self.client URLProtocol:self didLoadData:data];
                } else {
                    NSError *error = inputstream.streamError;
                    if (!error) {
                        error = [[NSError alloc] initWithDomain:@"inputstream length is invalid"
                                                                    code:-2
                                                                userInfo:nil];
                    }
                    [aStream removeFromRunLoop:_curRunLoop forMode:NSRunLoopCommonModes];
                    [aStream setDelegate:nil];
                    [aStream close];
                    [self.client URLProtocol:self didFailWithError:error];
                }
            }
            CFRelease((CFReadStreamRef)inputstream);
            CFRelease(message);
        }
    } else if (eventCode == NSStreamEventErrorOccurred) {
        [self closeStream:aStream];
        // 通知client发生错误了
        [self.client URLProtocol:self didFailWithError:
        [[NSError alloc] initWithDomain:@"NSStreamEventErrorOccurred" code:-1 userInfo:nil]];
    } else if (eventCode == NSStreamEventEndEncountered) {
        [self closeStream:_inputStream];
        [self.client URLProtocolDidFinishLoading:self];
    }
}

- (void)closeStream:(NSStream*)stream {
    [stream removeFromRunLoop:_curRunLoop forMode:NSRunLoopCommonModes];
    [stream setDelegate:nil];
    [stream close];
}

- (void)handleRedirect:(CFHTTPMessageRef)messageRef {
    // 响应头
    CFDictionaryRef headerFieldsRef = CFHTTPMessageCopyAllHeaderFields(messageRef);
    NSDictionary *headDict = (__bridge_transfer NSDictionary *)headerFieldsRef;
    [self redirect:headDict];
}

- (void)redirect:(NSDictionary *)headDict {
    // 重定向时如果有cookie需求的话，注意处理
    NSString *location = headDict[@"Location"];
    if (!location)
        location = headDict[@"location"];
    NSURL *url = [[NSURL alloc] initWithString:location];
    _curRequest.URL = url;
    if ([[_curRequest.HTTPMethod lowercaseString] isEqualToString:@"post"]) {
        // 根据RFC文档，当重定向请求为POST请求时，要将其转换为GET请求
        _curRequest.HTTPMethod = @"GET";
        _curRequest.HTTPBody = nil;
    }
    
    _curRequest.URL = [self getIpAndReplace:[url absoluteString]];
    [_curRequest setValue:url.host forHTTPHeaderField:@"host"];
    [self startRequest];
}

@end
