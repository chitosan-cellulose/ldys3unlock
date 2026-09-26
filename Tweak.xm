// ldys3_unlock v3 - 纯 Objective-C，无 substrate 依赖（保证可加载）
// 双重绕过：
//   1) 强制账户本地状态：login=YES / expireTime=2099 / isExpired=NO
//   2) 跳过服务器验证：拦截发往验证服务器的请求，直接本地返回“成功+永不过期”

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#define kFuture 4070908800LL
#define kFutureStr @"2099-12-31 23:59:59"

#pragma mark - 加载标记（确认 %ctor 执行）
static void MarkLoaded(const char *tag) {
    @autoreleasepool {
        NSString *proc = [[NSProcessInfo processInfo] processName];
        NSString *line = [NSString stringWithFormat:@"%@ | %s | %@\n", [NSDate date], tag, proc];
        NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding];
        for (NSString *p in @[@"/tmp/ldys3_unlock_loaded.txt", @"/var/mobile/Library/ldys3_unlock_loaded.txt"]) {
            @try {
                if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
                    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
                    if (fh) { [fh seekToEndOfFile]; [fh writeData:d]; [fh closeFile]; }
                } else { [d writeToFile:p atomically:YES]; }
            } @catch (NSException *e) {}
        }
    }
}

#pragma mark - 工具：找实现某 selector 的所有类
static NSArray *ClassesWithSel(SEL s) {
    unsigned int n = 0; Class *cs = objc_copyClassList(&n);
    NSMutableArray *out = [NSMutableArray array];
    for (unsigned int i = 0; i < n; i++) {
        Class c = cs[i];
        if (class_getInstanceMethod(c, s) || class_getClassMethod(c, s)) [out addObject:c];
    }
    if (cs) free(cs);
    return out;
}

#pragma mark - 1) 强制账户本地状态（贪婪枚举方法）
static void HookAccountClass(Class cls) {
    unsigned int mc = 0; Method *ms = class_copyMethodList(cls, &mc);
    for (unsigned int i = 0; i < mc; i++) {
        NSString *name = NSStringFromSelector(method_getName(ms[i]));
        if (!name) continue;
        if ([name isEqualToString:@"login"] || [name isEqualToString:@"loggedIn"] ||
            [name containsString:@"isValid"] || [name containsString:@"isActivated"]) {
            method_setImplementation(ms[i], imp_implementationWithBlock(^BOOL(id s){ return YES; }));
        } else if ([name containsString:@"isExpired"] || [name isEqualToString:@"expired"] ||
                   [name containsString:@"isOverdue"]) {
            method_setImplementation(ms[i], imp_implementationWithBlock(^BOOL(id s){ return NO; }));
        } else if ([name isEqualToString:@"expireTime"]) {
            method_setImplementation(ms[i], imp_implementationWithBlock(^long long(id s){ return kFuture; }));
        } else if ([name isEqualToString:@"expireTimeString"]) {
            method_setImplementation(ms[i], imp_implementationWithBlock(^id(id s){ return kFutureStr; }));
        } else if ([name isEqualToString:@"activationCode"] || [name isEqualToString:@"getActivationCode"]) {
            method_setImplementation(ms[i], imp_implementationWithBlock(^id(id s){ return @"ACTIVATED"; }));
        } else if ([name isEqualToString:@"setLogin:"] || [name isEqualToString:@"setExpireTime:"] ||
                   [name isEqualToString:@"setExpireTimeString:"] || [name isEqualToString:@"setActivationCode:"]) {
            method_setImplementation(ms[i], imp_implementationWithBlock(^(id s, id v){}));
        }
    }
    if (ms) free(ms);
}

static BOOL TryHookAll(void) {
    NSMutableSet *seen = [NSMutableSet set];
    NSArray *sels = @[@"getExpireStatusWithCompletionHandler:", @"expireTime", @"login", @"replyActivationCode"];
    BOOL any = NO;
    for (NSString *sn in sels) {
        for (Class c in ClassesWithSel(NSSelectorFromString(sn))) {
            if (c && ![seen containsObject:c]) {
                [seen addObject:c]; any = YES;
                NSLog(@"[ldys3_unlock] hooking %@", NSStringFromClass(c));
                HookAccountClass(c);
            }
        }
    }
    return any;
}

#pragma mark - 2) 跳过服务器验证：拦截 NSURLSession
@interface LDFakeTask : NSObject @end
@implementation LDFakeTask
- (void)resume {} - (void)cancel {} - (void)suspend {}
@end

static NSURLSessionDataTask *(*orig_dtwrc)(id, SEL, NSURLRequest *, id);
static NSURLSessionDataTask *new_dtwrc(id self, SEL _cmd, NSURLRequest *req, id handler) {
    @autoreleasepool {
        NSURL *u = [req URL];
        NSString *host = [[u host] lowercaseString];
        NSString *path = [[u path] lowercaseString];
        BOOL verify = ([host containsString:@"jyyxt"] || [host isEqualToString:@"116.62.39.79"] || [host isEqualToString:@"api.jyyxt.vip"]) &&
                      ([path containsString:@"login"] || [path containsString:@"deposit"] || [path containsString:@"activ"] ||
                       [path containsString:@"expire"] || [path containsString:@"verify"] || [path containsString:@"/f"] || [path length] == 0);
        if (verify && handler) {
            NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc] initWithURL:u statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Content-Type":@"application/json"}];
            NSData *data = [@"{\"code\":0,\"success\":true,\"expire_time\":4070908800,\"newExpireTime\":4070908800,\"login_token\":\"ldys3_unlock\",\"userType\":\"vip\"}" dataUsingEncoding:NSUTF8StringEncoding];
            NSLog(@"[ldys3_unlock] intercepted verify request -> fake success");
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                void (^h)(NSData *, NSURLResponse *, NSError *) = (void (^)(NSData *, NSURLResponse *, NSError *))handler;
                h(data, resp, nil);
            });
            return (NSURLSessionDataTask *)[LDFakeTask new];
        }
    }
    return orig_dtwrc ? orig_dtwrc(self, _cmd, req, handler) : nil;
}

static void HookNetwork(void) {
    Class c = objc_getClass("NSURLSession");
    if (!c) return;
    Method m = class_getInstanceMethod(c, @selector(dataTaskWithRequest:completionHandler:));
    if (m) {
        orig_dtwrc = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))method_getImplementation(m);
        method_setImplementation(m, (IMP)new_dtwrc);
        NSLog(@"[ldys3_unlock] network hook installed");
    }
}

#pragma mark - 入口
__attribute__((constructor)) static void ldys3_entry(void) {
    @autoreleasepool {
        MarkLoaded("ctor");
        HookNetwork();                 // 任意进程都装网络拦截
        if (TryHookAll()) { MarkLoaded("hooked-imm"); return; }
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            for (int i = 0; i < 25; i++) {
                [NSThread sleepForTimeInterval:1.0];
                if (TryHookAll()) { MarkLoaded("hooked-retry"); break; }
            }
        });
    }
}
