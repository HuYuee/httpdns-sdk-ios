//
// MSDKDnsURLSchemeHandler.m
// MSDKDns
//
// Created by eric hu on 2024/2/20.
// Copyright © 2024 Tencent. All rights reserved.
//
#import "MSDKDnsURLSchemeHandler.h"
#import "MSDKDns.h"
#import "MSDKDnsLog.h"
#import <objc/runtime.h>
#import <WebKit/WebKit.h>


@interface MSDKDnsURLSchemeHandler () <WKURLSchemeHandler, NSURLSessionDataDelegate>

@property (strong, nonatomic) NSURLSession *session;
@property (strong, readwrite, nonatomic) NSMutableURLRequest *curRequest;
@property (strong, nonatomic) NSMutableDictionary<id<WKURLSchemeTask>, NSURLSessionDataTask *> *activeTasks;

@property (strong, nonatomic) NSURLSessionDataTask *dataTask;
@property (weak, nonatomic) id<WKURLSchemeTask> urlSchemeTask;

@end

@implementation MSDKDnsURLSchemeHandler

- (instancetype)init {
    self = [super init];
    if (self) {
        NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
        self.session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
        self.activeTasks = [NSMutableDictionary dictionary];
    }
    return self;
}

- (void)webView:(WKWebView *)webView startURLSchemeTask:(id<WKURLSchemeTask>)urlSchemeTask {
    // 创建一个NSURLSessionDataTask来处理请求
    // 配置 NSURLSession
     NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
     NSURLSession *session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
    self.urlSchemeTask = urlSchemeTask;
    
    NSURLRequest *request = [[urlSchemeTask request] mutableCopy];
        NSMutableURLRequest *mutaRequest = [urlSchemeTask.request mutableCopy];
    
    NSLog(@"request.URL:%@",request.URL);
    NSString *originalUrl = [request.URL absoluteString];
        NSArray* result = [[MSDKDns sharedInstance] WGGetHostByName:request.URL.host];
        NSString* ip = nil;
        if (result && result.count > 1) {
            if (![result[1] isEqualToString:@"0"]) {
                ip = result[1];
            } else {
                ip = result[0];
            }
        }
        NSURL *url = [request.URL copy];
    
        NSLog(@"the url is :%@",url.host);
        // 通过HTTPDNS获取IP成功，进行URL替换和HOST头设置
        if (ip) {
            NSRange hostFirstRange = [originalUrl rangeOfString:request.URL.host];
            if (NSNotFound != hostFirstRange.location) {
                NSString *newUrl = [originalUrl stringByReplacingCharactersInRange:hostFirstRange withString:ip];
                NSLog(@"the new url is :%@ == host：%@",newUrl, request.URL.host);
                mutaRequest.URL = [NSURL URLWithString:newUrl];
                [mutaRequest setValue:request.URL.host forHTTPHeaderField:@"host"];
            }
        }
    self.curRequest = [mutaRequest copy];
    NSURLSessionDataTask *task = [session dataTaskWithURL:mutaRequest.URL completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            // 处理错误
            [urlSchemeTask didFailWithError:error];
        } else {
            // 将响应传递给WKWebView
            [urlSchemeTask didReceiveResponse:response];
            [urlSchemeTask didReceiveData:data];
            [urlSchemeTask didFinish];
        }
    }];
    // 开始任务
    [task resume];
}

- (void)webView:(WKWebView *)webView stopURLSchemeTask:(id<WKURLSchemeTask>)urlSchemeTask {
    [self.dataTask cancel];
    self.dataTask = nil;
    self.urlSchemeTask = nil;
}

- (NSURLRequest *)requestForURLSchemeTask:(id<WKURLSchemeTask>)urlSchemeTask {
    // Create a new NSURLRequest from the original request, but modify it for your needs
    NSMutableURLRequest *newRequest = [urlSchemeTask.request mutableCopy];
    // Perform any changes to the request here, such as setting a new URL, adding headers, etc.
    // Example:
    // newRequest.URL = [NSURL URLWithString:@"http://example.com"];
    
    return newRequest;
}

#pragma mark - NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler;
{
    if (dataTask.state == NSURLSessionTaskStateCanceling) {
        return;
    }
    [self.urlSchemeTask didReceiveResponse:response];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
      
        if (dataTask.state == NSURLSessionTaskStateCanceling) {
            return;
        }
[self.urlSchemeTask didReceiveData:data];
    
}
#pragma mark - NSURLSessionDelegate
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain {


   //创建证书校验策略
   NSMutableArray *policies = [NSMutableArray array];
   if (domain) {
       [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];
   } else {
       [policies addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
   }


   //绑定校验策略到服务端的证书上
   SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);


   //评估当前 serverTrust 是否可信任，
   //官方建议在 result = kSecTrustResultUnspecified 或 kSecTrustResultProceed 的情况下 serverTrust 可以被验证通过，
   //https://developer.apple.com/library/ios/technotes/tn2232/_index.html
   //关于SecTrustResultType的详细信息请参考SecTrust.h
   SecTrustResultType result;
   SecTrustEvaluate(serverTrust, &result);


   return YES;
}


- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * __nullable credential))completionHandler {
   if (!challenge) {
       return;
   }


   NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
   NSURLCredential *credential = nil;

   //获取原始域名信息
   NSString *host = [[self.curRequest allHTTPHeaderFields] objectForKey:@"host"];
    
    NSLog(@"%@ 获取原始域名：%@",[self.curRequest.URL absoluteString] ,host);
   if (!host) {
       host = self.curRequest.URL.host;
   }
   if ([challenge.protectionSpace.authenticationMethod  isEqualToString:NSURLAuthenticationMethodServerTrust]) {
       if ([self evaluateServerTrust:challenge.protectionSpace.serverTrust forDomain:host]) {
           disposition = NSURLSessionAuthChallengeUseCredential;
           credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
       } else {
           disposition = NSURLSessionAuthChallengePerformDefaultHandling;
       }
   } else {
       disposition = NSURLSessionAuthChallengePerformDefaultHandling;
   }


   // 对于其他的 challenges 直接使用默认的验证方案
   completionHandler(disposition,credential);
}


- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.urlSchemeTask didFailWithError:error];
    } else {
        [self.urlSchemeTask didFinish];
    }
    self.dataTask = nil;
    self.urlSchemeTask = nil;
}

@end

@implementation WKWebView (handlesURLScheme)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Method originalMethod = class_getClassMethod(self, @selector(handlesURLScheme:));
        Method swizzledMethod = class_getClassMethod(self, @selector(sdk_handlesURLScheme:));
        method_exchangeImplementations(originalMethod, swizzledMethod);
        
    });
    
}

+ (BOOL)sdk_handlesURLScheme:(NSString *)urlScheme {
    if ([urlScheme isEqualToString:@"http"] || [urlScheme isEqualToString:@"https"]) {
        return NO;
    }
    return [self sdk_handlesURLScheme:urlScheme];
}
@end
