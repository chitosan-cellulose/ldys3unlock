// ldys3_unlock v2 - 绕过佳影游戏厅3(com.zjx.ldys3)服务器验证
// 策略：运行时按 selector 定位账户相关类（类名混淆，故动态发现），
//       贪婪枚举其方法，把登录/过期/激活相关的“读”恒返回已激活、“写”强制写远未来。
// 健壮性：带重试（解决 dylib 加载顺序早于目标类注册的问题）；
//         任意进程注入都尝试，找不到类就静默跳过。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <substrate.h>

#define kFutureTime 4070908800LL   // ~2099
#define kFutureStr  @"2099-12-31 23:59:59"

// ---------------------------------------------------------------------------
// 标记文件：确认 dylib 被加载并跑起来了（用户可 ls 查看）
// ---------------------------------------------------------------------------
static void LDMarkLoaded(const char *tag) {
    @autoreleasepool {
        NSString *path = @"/var/mobile/Library/ldys3_unlock_loaded.txt";
        NSString *proc = [[NSProcessInfo processInfo] processName];
        NSString *line = [NSString stringWithFormat:@"%@ | %s | %@\n",
                          [NSDate date], tag, proc];
        NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
            if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        } else {
            [data writeToFile:path atomically:YES];
        }
    }
}

// ---------------------------------------------------------------------------
// 找到所有“实现了指定 selector”的类
// ---------------------------------------------------------------------------
static NSArray *LDClassesWithSelector(SEL sel) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    NSMutableArray *out = [NSMutableArray array];
    for (unsigned int i = 0; i < count; i++) {
        Class c = classes[i];
        if (class_getInstanceMethod(c, sel) || class_getClassMethod(c, sel)) {
            [out addObject:c];
        }
    }
    if (classes) free(classes);
    return out;
}

// ---------------------------------------------------------------------------
// 对单个类贪婪 hook：枚举方法，按名称语义强制返回值
// ---------------------------------------------------------------------------
static void LDHookOneClass(Class cls) {
    unsigned int mc = 0;
    Method *methods = class_copyMethodList(cls, &mc);
    for (unsigned int i = 0; i < mc; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *name = NSStringFromSelector(sel);
        if (!name) continue;

        // —— 读：恒“已激活/永不过期” ——
        if ([name isEqualToString:@"login"] || [name isEqualToString:@"loggedIn"] ||
            [name isEqualToString:@"isLogin"] || [name containsString:@"isValid"] ||
            [name containsString:@"isActivated"]) {
            IMP y = imp_implementationWithBlock(^BOOL(id slf){ return YES; });
            method_setImplementation(methods[i], y);
            NSLog(@"[ldys3_unlock] %@ -> YES", name);
        }
        else if ([name containsString:@"isExpired"] || [name isEqualToString:@"expired"] ||
                 [name containsString:@"isOverdue"]) {
            IMP n = imp_implementationWithBlock(^BOOL(id slf){ return NO; });
            method_setImplementation(methods[i], n);
            NSLog(@"[ldys3_unlock] %@ -> NO", name);
        }
        else if ([name isEqualToString:@"expireTime"]) {
            IMP f = imp_implementationWithBlock(^long long(id slf){ return kFutureTime; });
            method_setImplementation(methods[i], f);
            NSLog(@"[ldys3_unlock] expireTime -> 2099");
        }
        else if ([name isEqualToString:@"expireTimeString"]) {
            IMP s = imp_implementationWithBlock(^id(id slf){ return kFutureStr; });
            method_setImplementation(methods[i], s);
        }
        else if ([name isEqualToString:@"getActivationCode"] || [name isEqualToString:@"activationCode"]) {
            IMP s = imp_implementationWithBlock(^id(id slf){ return @"ACTIVATED"; });
            method_setImplementation(methods[i], s);
        }
        // —— 写：强制写远未来 / YES ——
        else if ([name isEqualToString:@"setLogin:"]) {
            IMP s = imp_implementationWithBlock(^(id slf, BOOL v){ /* force YES */ });
            method_setImplementation(methods[i], s);
        }
        else if ([name isEqualToString:@"setExpireTime:"]) {
            IMP s = imp_implementationWithBlock(^(id slf, long long v){ /* force future */ });
            method_setImplementation(methods[i], s);
        }
        else if ([name isEqualToString:@"setExpireTimeString:"]) {
            IMP s = imp_implementationWithBlock(^(id slf, id v){ });
            method_setImplementation(methods[i], s);
        }
        else if ([name isEqualToString:@"setActivationCode:"]) {
            IMP s = imp_implementationWithBlock(^(id slf, id v){ });
            method_setImplementation(methods[i], s);
        }
    }
    if (methods) free(methods);
}

// 触发一次：找出所有账户相关类并 hook；返回是否至少命中一个类
static BOOL LDTryHookAll(void) {
    NSMutableSet *seen = [NSMutableSet set];
    NSMutableArray *targets = [NSMutableArray array];
    NSArray *sels = @[
        NSStringFromSelector(@selector(getExpireStatusWithCompletionHandler:)),
        NSStringFromSelector(@selector(expireTime)),
        NSStringFromSelector(@selector(login)),
        NSStringFromSelector(@selector(replyActivationCode)),
    ];
    for (NSString *sn in sels) {
        for (Class c in LDClassesWithSelector(NSSelectorFromString(sn))) {
            if (c && ![seen containsObject:c]) { [seen addObject:c]; [targets addObject:c]; }
        }
    }
    if (targets.count == 0) return NO;
    for (Class c in targets) {
        NSLog(@"[ldys3_unlock] hooking class: %@", NSStringFromClass(c));
        LDHookOneClass(c);
    }
    return YES;
}

// ---------------------------------------------------------------------------
// 入口：任意进程都尝试；带重试，避免加载顺序导致类未注册
// ---------------------------------------------------------------------------
%ctor {
    @autoreleasepool {
        LDMarkLoaded("ctor");
        // 立刻试一次
        if (LDTryHookAll()) {
            LDMarkLoaded("hooked-imm");
            return;
        }
        // 没找到：后台重试最多 ~25 秒
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            for (int i = 0; i < 25; i++) {
                [NSThread sleepForTimeInterval:1.0];
                if (LDTryHookAll()) {
                    LDMarkLoaded("hooked-retry");
                    break;
                }
            }
        });
    }
}
