.class public Lcom/example/NetworkHelper;
.super Ljava/lang/Object;
.source "NetworkHelper.java"

.field private serverUrl:Ljava/lang/String;

.method public constructor <init>()V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    const-string v0, "https://api.example.com"
    iput-object v0, p0, Lcom/example/NetworkHelper;->serverUrl:Ljava/lang/String;
    return-void
.end method

.method public fetchData()Ljava/lang/String;
    .locals 4
    new-instance v0, Ljava/net/URL;
    iget-object v1, p0, Lcom/example/NetworkHelper;->serverUrl:Ljava/lang/String;
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v1
    check-cast v1, Ljava/net/HttpURLConnection;
    const-string v2, "GET"
    invoke-virtual {v1, v2}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;
    move-result-object v3
    return-object v3
.end method

.method public getVersion()Ljava/lang/String;
    .locals 1
    const-string v0, "1.0.0"
    return-object v0
.end method
