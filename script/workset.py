#!/usr/bin/env python3
"""多仓工作集：三个仓并排时，「另一个仓在哪」的答案。

为什么有这个模块：拆成三个仓（底座 kit + 管理面 + 执行面）之后，有几件事
天生跨仓：

  - 底座的审计留痕（pkg/audit）要由**服务仓**的守卫盯着（答复守卫与留痕
    守卫在服务仓里）⇒ 变异脚本要能同时改**底座**的源码、跑**服务仓**的测试。
  - 委派凭据的门禁一边在管理面（biz/handler/delegation.go）、
    一边在执行面（internal/repository/koko/token.go），而门禁的守卫在服务仓。

⇒ 这些脚本与守卫都需要同一份「工作集」的定义。

⚠️ **一份拷贝会漂**：两个变异脚本各写一份约定，改了一处忘了另一处 ⇒
工作集在两个脚本里指向不同的目录 ⇒ 报告的数字对着的是另一份代码 ⇒ 而那
看起来跟「守卫是假的」一模一样。

约定的形状（与守卫用的是同一套，别另造）：

    1. 环境变量 `JMS_SIBLING_ROOTS`（`:` 分隔的目录列表）；
    2. 没有就用同级目录约定：../jumpserver-mcp、../jumpserver-mcp-exec。

⚠️ 同级目录约定是**相对脚本自己那个仓的父目录**解析的，不是相对当前工作
目录 —— 否则「在哪个仓里跑脚本」就会改变工作集。
"""
import os
import re

# 同级目录约定里认得的仓名。
# ⚠️ 这三个名字是一份约定（守卫也用同一套）—— 一份拷贝会漂。
REPO_NAMES = ("jumpserver-mcp-kit", "jumpserver-mcp", "jumpserver-mcp-exec")

# 扫源码树时要跳过的目录。
SKIP_DIRS = (".git", "__pycache__", "bin", "node_modules", "legacy", ".idea")


def own_root(script_file):
    """脚本自己所在的那个仓的根（脚本在 <repo>/script/ 下 ⇒ 上两级）。"""
    return os.path.realpath(
        os.path.dirname(os.path.dirname(os.path.abspath(script_file))))


def sibling_roots(own):
    """同级目录里的那**另外几个**仓。"""
    env = os.environ.get("JMS_SIBLING_ROOTS", "")
    if env.strip():
        out = []
        for part in env.split(":"):
            part = part.strip()
            if not part:
                continue
            p = os.path.realpath(part)
            if p != own and os.path.isdir(p):
                out.append(p)
        return out
    parent = os.path.dirname(own)
    out = []
    for name in REPO_NAMES:
        p = os.path.join(parent, name)
        if os.path.isdir(p) and os.path.realpath(p) != own:
            out.append(os.path.realpath(p))
    return out


def roots(script_file):
    """工作集：脚本自己那个仓 + 同级的那些仓。"""
    own = own_root(script_file)
    return [own] + sibling_roots(own)


def sibling_env(roots_):
    """给子进程（go test）用的 JMS_SIBLING_ROOTS 值。

    ⚠️ 传的是**工作集里的每一个仓**，不只是「另外几个」：守卫可能要回头
    指着自己那个仓（相对路径 ../../ 就是在指它自己）。
    """
    return ":".join(roots_)


def locate(relpath, roots_):
    """在工作集里找「仓内相对路径」对应的绝对路径。

    ⚠️ 命中多于一个 ⇒ **拒绝猜**：同一个相对路径在两个仓里都有时，猜一个
    就是「在错的代码上跑」—— 而那看起来跟「守卫是假的」一模一样。
    """
    hits = [os.path.join(r, relpath) for r in roots_]
    hits = [h for h in hits if os.path.exists(h)]
    if not hits:
        raise SystemExit(
            "⚠️  工作集里找不到 %s（工作集：%s）" % (relpath, ", ".join(roots_)))
    if len(hits) > 1:
        raise SystemExit(
            "⚠️  %s 在多个仓里都有：%s ⇒ 不猜，报出来"
            % (relpath, ", ".join(hits)))
    return hits[0]


def repo_root_named(name, roots_):
    """工作集里**按名字**认出某个仓的根。

    ⚠️ 为什么需要它：重构之后两个服务仓的仓内相对路径**会撞名**
    （两个仓都有 `biz/handler/`）⇒ locate 会拒绝猜（那是它的正确行为）
    ⇒ 需要一个能指名道姓地说「在执行面那个仓里」的入口。
    """
    for r in roots_:
        if os.path.basename(r) == name:
            return r
    raise SystemExit(
        "⚠️  工作集里没有仓 %s（工作集：%s）" % (name, ", ".join(roots_)))


def locate_in(repo_name, relpath, roots_):
    """在**指定的**仓里找「仓内相对路径」。

    ⚠️ 它与 locate 的区别只有一个：locate 在工作集里找（撞名就拒绝猜），
    locate_in 在**点名**的那个仓里找 ⇒ 撞名不再是问题。
    """
    root = repo_root_named(repo_name, roots_)
    p = os.path.join(root, relpath)
    if not os.path.exists(p):
        raise SystemExit(
            "⚠️  仓 %s 里找不到 %s" % (repo_name, relpath))
    return p


def repo_of(path, roots_):
    """一个绝对路径属于哪个仓。"""
    best = None
    for r in roots_:
        if path == r or path.startswith(r + os.sep):
            if best is None or len(r) > len(best):
                best = r
    return best


def rel_to_repo(path, roots_):
    """相对它自己那个仓的路径（给人看的）。"""
    r = repo_of(path, roots_)
    if r is None:
        return path
    return os.path.relpath(path, r)


def index_tests(roots_):
    """{测试函数名: [(仓根, 包目录的相对路径), ...]}。

    ⚠️ 为什么按**函数名**建索引，而不是按包路径：拆仓之后同一个相对包
    路径（internal/arch/）在几个仓里都可能存在，而**同名的测试函数只声明
    一次** ⇒ 「谁声明了它」是唯一不靠猜的判据。
    """
    index = {}
    pat = re.compile(r"^func\s+(Test[A-Za-z0-9_]*)\s*\(", re.M)
    for r in roots_:
        for dirpath, dirnames, filenames in os.walk(r):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith("_test.go"):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        src = f.read()
                except OSError:
                    continue
                rel = os.path.relpath(dirpath, r)
                for m in pat.finditer(src):
                    index.setdefault(m.group(1), []).append((r, rel))
    return index
