// ldys3_unlock - 绕过佳影游戏厅3(com.zjx.ldys3)服务器验证
// 思路：运行时 hook 账户状态的读写方法，让本地始终判定为“已登录/永不过期”，
//       从而使输入充值卡号后的服务器校验结果不再影响功能。
// 注意：本文件同时编译进 SpringBoard 注入端 与 ldysdaemon 注入端，
//       通过 HBProcessCheck / 环境区分各自要 hook 的目标。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <substrate.h>

// ---------------------------------------------------------------------------
// 工具：在所有已加载类中，找到“第一个实现了指定 selector”的类
// ---------------------------------------------------------------------------
static Class LDFindClassWithSelector(SEL sel) {
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    Class found = Nil;
    for (unsigned int i = 0; i < count; i++) {
        Class c = classes[i];
        if (class_getInstanceMethod(c, sel) || class_getClassMethod(c, sel)) {
            // 仅匹配我们关注的、且不是来自系统框架的“实现”更稳妥：
            // 这里简单地取第一个即可，关键方法(getExpireStatusWithCompletionHandler:)
            // 基本只在本 tweak 的账户类里实现。
            found = c;
            break;
        }
    }
    if (classes) free(classes);
    return found;
}

static IMP LDHook(Class cls, SEL sel, IMP newImp, const char *types) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) return NULL;
    IMP orig = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return orig;
}

// ===========================================================================
// SpringBoard 端：账户状态强制“已激活”
// ===========================================================================
static id (*orig_login)(id, SEL);
static id new_login(id self, SEL _cmd) {
    return @YES; // -[Account login] -> BOOL
}

static long long (*orig_expireTime)(id, SEL);
static long long new_expireTime(id self, SEL _cmd) {
    // 返回一个极远的未来时间戳（约 2099 年）
    return 4070908800LL;
}

static NSString *(*orig_expireTimeString)(id, SEL);
static NSString *new_expireTimeString(id self, SEL _cmd) {
    return @"2099-12-31 23:59:59";
}

static void (*orig_setLogin)(id, SEL, BOOL);
static void new_setLogin(id self, SEL _cmd, BOOL v) {
    if (orig_setLogin) orig_setLogin(self, _cmd, YES); // 强制写回 YES
}

static void (*orig_setExpireTime)(id, SEL, long long);
static void new_setExpireTime(id self, SEL _cmd, long long v) {
    if (orig_setExpireTime) orig_setExpireTime(self, _cmd, 4070908800LL);
}

static void (*orig_setExpireTimeString)(id, SEL, id);
static void new_setExpireTimeString(id self, SEL _cmd, id v) {
    if (orig_setExpireTimeString) orig_setExpireTimeString(self, _cmd, @"2099-12-31 23:59:59");
}

static void (*orig_setActivationCode)(id, SEL, id);
static void new_setActivationCode(id self, SEL _cmd, id v) {
    // 任意激活码都接受：原样写入（或可写入固定值）
    if (orig_setActivationCode) orig_setActivationCode(self, _cmd, v ?: @"activated");
}

// getExpireStatusWithCompletionHandler: —— 无论服务器返回什么，都回调“有效”
static void (*orig_getExpireStatus)(id, SEL, id);
static void new_getExpireStatus(id self, SEL _cmd, id handler) {
    // 先保证本地状态是“已激活”
    new_setLogin(self, @selector(setLogin:), YES);
    new_setExpireTime(self, @selector(setExpireTime:), 4070908800LL);
    // 照常调用原始实现（让它走网络），但其写回会被上面的 setter 强制覆盖为已激活
    if (orig_getExpireStatus) orig_getExpireStatus(self, _cmd, handler);
    else if (handler) {
        // 兜底：若拿不到原实现，直接调用 handler（参数个数未知，这里谨慎不调用）
    }
}

static void LDHookSpringBoardAccount(void) {
    Class cls = LDFindClassWithSelector(@selector(getExpireStatusWithCompletionHandler:));
    if (!cls) {
        // 退而求其次：找实现了 login 的类
        cls = LDFindClassWithSelector(@selector(login));
    }
    if (!cls) return;

    NSLog(@"[ldys3_unlock] hooking account class: %@", NSStringFromClass(cls));

    orig_login = (id(*)(id,SEL))LDHook(cls, @selector(login), (IMP)new_login, "c@:");
    orig_expireTime = (long long(*)(id,SEL))LDHook(cls, @selector(expireTime), (IMP)new_expireTime, "q@:");
    orig_expireTimeString = (id(*)(id,SEL))LDHook(cls, @selector(expireTimeString), (IMP)new_expireTimeString, "@@:");
    orig_setLogin = (void(*)(id,SEL,BOOL))LDHook(cls, @selector(setLogin:), (IMP)new_setLogin, "v@:c");
    orig_setExpireTime = (void(*)(id,SEL,long long))LDHook(cls, @selector(setExpireTime:), (IMP)new_setExpireTime, "v@:q");
    orig_setExpireTimeString = (void(*)(id,SEL,id))LDHook(cls, @selector(setExpireTimeString:), (IMP)new_setExpireTimeString, "v@:@");
    orig_setActivationCode = (void(*)(id,SEL,id))LDHook(cls, @selector(setActivationCode:), (IMP)new_setActivationCode, "v@:@");
    orig_getExpireStatus = (void(*)(id,SEL,id))LDHook(cls, @selector(getExpireStatusWithCompletionHandler:), (IMP)new_getExpireStatus, "v@:@?");
}

// ===========================================================================
// ldysdaemon 端：激活码校验绕过
// ===========================================================================
// 守护进程里有 getActivationCode / setActivationCode / replyActivationCode。
// 让“是否已激活”的判定恒为真：若存在返回 BOOL 的判定方法则强制 YES；
// 同时把 replyActivationCode 的结果置为成功。
static void LDHookDaemonActivation(void) {
    Class cls = LDFindClassWithSelector(@selector(getActivationCode));
    if (!cls) cls = LDFindClassWithSelector(@selector(replyActivationCode));
    if (!cls) return;
    NSLog(@"[ldys3_unlock] hooking daemon class: %@", NSStringFromClass(cls));

    // 常见的判定方法名猜测，命中才 hook
    NSArray *cands = @[@"isActivated", @"isValid", @"checkActivation", @"verifyActivationCode"];
    for (NSString *name in cands) {
        SEL s = NSSelectorFromString(name);
        Method m = class_getInstanceMethod(cls, s);
        if (!m) m = class_getClassMethod(cls, s);
        if (m) {
            IMP cur = method_getImplementation(m);
            IMP yes = imp_implementationWithBlock(^BOOL(id slf){ return YES; });
            method_setImplementation(m, yes);
            NSLog(@"[ldys3_unlock] forced %@ -> YES", name);
        }
    }
}

// ===========================================================================
// 入口
// ===========================================================================
%ctor {
    @autoreleasepool {
        NSString *proc = [[NSProcessInfo processInfo] processName];
        if ([proc isEqualToString:@"SpringBoard"] || [proc hasSuffix:@"Board"]) {
            LDHookSpringBoardAccount();
        } else if ([proc isEqualToString:@"ldysdaemon"]) {
            LDHookDaemonActivation();
        }
    }
}
