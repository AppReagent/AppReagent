.class public Lcom/obfuscated/a;
.super Ljava/lang/Object;
.source ""

.field private a:[B
.field private b:Ljava/lang/reflect/Method;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public a(Ljava/lang/String;)Ljava/lang/String;
    .registers 6

    # XOR-based string decoding — classic obfuscation pattern
    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    array-length v1, v0
    const/4 v2, 0x0

    :loop_start
    if-ge v2, v1, :loop_end

    aget-byte v3, v0, v2
    xor-int/lit8 v3, v3, 0x42
    int-to-byte v3, v3
    aput-byte v3, v0, v2
    add-int/lit8 v2, v2, 0x1
    goto :loop_start

    :loop_end
    new-instance v4, Ljava/lang/String;
    invoke-direct {v4, v0}, Ljava/lang/String;-><init>([B)V
    return-object v4
.end method

.method public b()V
    .registers 5

    # Reflection-based method invocation — hides the real target
    const-string v0, "java.lang.Runtime"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0

    const-string v1, "getRuntime"
    const/4 v2, 0x0
    new-array v2, v2, [Ljava/lang/Class;
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v1

    const/4 v3, 0x0
    const/4 v4, 0x0
    new-array v4, v4, [Ljava/lang/Object;
    invoke-virtual {v1, v3, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method private c([B)[B
    .registers 5

    # Custom byte cipher — another obfuscation layer
    array-length v0, p1
    new-array v1, v0, [B
    const/4 v2, 0x0

    :cipher_loop
    if-ge v2, v0, :cipher_done
    aget-byte v3, p1, v2
    add-int/lit8 v3, v3, 0xd
    xor-int/lit8 v3, v3, 0x37
    int-to-byte v3, v3
    aput-byte v3, v1, v2
    add-int/lit8 v2, v2, 0x1
    goto :cipher_loop

    :cipher_done
    return-object v1
.end method
