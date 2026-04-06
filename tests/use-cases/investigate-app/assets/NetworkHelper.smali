.class public Lcom/example/network/NetworkHelper;
.super Ljava/lang/Object;
.source "NetworkHelper.java"

.field private baseUrl:Ljava/lang/String;
.field private timeout:I

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/example/network/NetworkHelper;->baseUrl:Ljava/lang/String;
    return-void
.end method

.method public sendData(Ljava/lang/String;)Z
    .locals 2
    .param p1, "payload"
    new-instance v0, Ljava/net/URL;
    iget-object v1, p0, Lcom/example/network/NetworkHelper;->baseUrl:Ljava/lang/String;
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    const/4 v0, 0x1
    return v0
.end method

.method public downloadPayload(Ljava/lang/String;)[B
    .locals 1
    .param p1, "url"
    const/4 v0, 0x0
    return-object v0
.end method
