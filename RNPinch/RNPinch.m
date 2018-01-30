//
//  RNNativeFetch.m
//  medipass
//
//  Created by Paul Wong on 13/10/16.
//  Copyright © 2016 Localz. All rights reserved.
//

#if __has_include(<React/RCTBridge.h>)
#import <React/RCTBridge.h>
#else
#import "RCTBridge.h"
#endif

#import "RNPinch.h"

@interface RNPinchException : NSException
@end
@implementation RNPinchException
@end

// private delegate for verifying certs
@interface NSURLSessionSSLPinningDelegate:NSObject <NSURLSessionDelegate>

- (id)initWithCertNames:(NSArray<NSString *> *)certNames;

@property (nonatomic, strong) NSArray<NSString *> *certNames;

@end

@implementation NSURLSessionSSLPinningDelegate

- (id)initWithCertNames:(NSArray<NSString *> *)certNames {
    if (self = [super init]) {
        _certNames = certNames;
    }
    return self;
}

- (NSArray *)pinnedCertificateData {
    NSMutableArray *localCertData = [NSMutableArray array];
    for (NSString* certName in self.certNames) {
        NSString *cerPath = [[NSBundle mainBundle] pathForResource:certName ofType:@"cer"];
        if (cerPath == nil) {
            @throw [[RNPinchException alloc]
                initWithName:@"CertificateError"
                reason:@"Can not load certicate given, check it's in the app resources."
                userInfo:nil];
        }
        [localCertData addObject:[NSData dataWithContentsOfFile:cerPath]];
    }

    NSMutableArray *pinnedCertificates = [NSMutableArray array];
    for (NSData *certificateData in localCertData) {
        [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData)];
    }
    return pinnedCertificates;
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {

    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSString *domain = challenge.protectionSpace.host;
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];

        NSArray *policies = @[(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];

        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);
        // setup
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)self.pinnedCertificateData);
        SecTrustResultType result;

        // evaluate
        OSStatus errorCode = SecTrustEvaluate(serverTrust, &result);

        BOOL evaluatesAsTrusted = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
        if (errorCode == errSecSuccess && evaluatesAsTrusted) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else {
            completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, NULL);
        }
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
}

@end

@interface RNPinch()

@property (nonatomic, strong) NSURLSessionConfiguration *sessionConfig;

@end

@implementation RNPinch
RCT_EXPORT_MODULE();

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        self.sessionConfig.HTTPCookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    }
    return self;
}

RCT_EXPORT_METHOD(fetch:(NSString *)url obj:(NSDictionary *)obj callback:(RCTResponseSenderBlock)callback) {
    NSURL *u = [NSURL URLWithString:url];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:u];

    NSURLSession *session;
    if (obj) {
        if (obj[@"method"]) {
            [request setHTTPMethod:obj[@"method"]];
        }
        if (obj[@"timeoutInterval"]) {
          [request setTimeoutInterval:[obj[@"timeoutInterval"] doubleValue] / 1000];
        }
        if (obj[@"headers"] && [obj[@"headers"] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *m = [obj[@"headers"] mutableCopy];
            for (NSString *key in [m allKeys]) {
                if (![m[key] isKindOfClass:[NSString class]]) {
                    m[key] = [m[key] stringValue];
                }
            }
            [request setAllHTTPHeaderFields:m];
        }
        if (obj[@"body"]) {
            NSArray *keys = [NSArray arrayWithObjects:@"ping", nil];
            NSArray *objects = [NSArray arrayWithObjects:@"check", nil];
            
            NSDictionary *jsonDictionary = [NSDictionary dictionaryWithObjects:objects forKeys:keys];
            NSData *jsonData ;
            NSString *jsonString;
            if([NSJSONSerialization isValidJSONObject:jsonDictionary])
            {
                jsonData = [NSJSONSerialization dataWithJSONObject:jsonDictionary options:0 error:nil];
                jsonString = [[NSString alloc]initWithData:jsonData encoding:NSUTF8StringEncoding];
            }
            [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            [request setValue:[NSString stringWithFormat:@"%lu", (unsigned long)[jsonData length]] forHTTPHeaderField:@"Content-Length"];

            [request setHTTPBody:jsonData];
        }
    }
    if (obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"cert"]) {
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:@[obj[@"sslPinning"][@"cert"]]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else if (obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"certs"]) {
        // load all certs
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:obj[@"sslPinning"][@"certs"]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else {
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig];
    }

    __block NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (!error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
                NSInteger statusCode = httpResp.statusCode;
                NSString *bodyString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSString *statusText = [NSHTTPURLResponse localizedStringForStatusCode:httpResp.statusCode];

                NSDictionary *res = @{
                                      @"status": @(statusCode),
                                      @"headers": httpResp.allHeaderFields,
                                      @"bodyString": bodyString,
                                      @"statusText": statusText
                                      };
                callback(@[[NSNull null], res]);
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[@{@"message":error.localizedDescription}, [NSNull null]]);
            });
        }
    }];

    [dataTask resume];
}

@end

